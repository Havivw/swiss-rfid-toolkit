/*
 * NFC UID Stepper — Flipper Zero app
 *
 * Read (or start from a default) an ISO14443-3A UID, step it up/down, and
 * emulate a card with that UID so a UID-based 13.56 MHz reader sees it.
 * Includes an AUTO sweep that walks the UID and re-emulates each on a timer.
 *
 * NOTE: this emulates the UID (+ ATQA/SAK) only. Readers that check Mifare
 * crypto / sector data are NOT fooled — this is for UID-based systems.
 *
 * Controls (Edit screen):
 *   Left/Right  select field: UID / Len / step / delay / Dir
 *   Up/Down     change the selected field (UID = +/- step)
 *   OK  (tap)   start AUTO sweep; while running, OK = STOP
 *   OK  (hold)  toggle MANUAL emulate of the current UID
 *   Back        stop / back to menu ;  Back(hold) exit
 */
#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <nfc/nfc.h>
#include <nfc/nfc_listener.h>
#include <nfc/nfc_poller.h>
#include <nfc/protocols/nfc_protocol.h>
#include <nfc/nfc_device.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller_sync.h>
#include <nfc/protocols/mf_desfire/mf_desfire.h>
#include <nfc/protocols/mf_desfire/mf_desfire_poller.h>
#include <dialogs/dialogs.h>

#define NFC_DIR "/ext/nfc"

static const uint32_t STEPS[] = {1, 10, 100, 1000, 10000};
#define STEP_COUNT ((int)(sizeof(STEPS) / sizeof(STEPS[0])))

#define DELAY_MIN 100u
#define DELAY_MAX 10000u
#define DELAY_INC 100u

typedef enum {
    SceneMenu,
    SceneRead,
    SceneEdit,
} Scene;

typedef enum {
    FieldUid,
    FieldPos, /* which byte to step: -1 = whole value, else byte index */
    FieldLen,
    FieldStep,
    FieldDelay,
    FieldDir,
    FieldCount,
} Field;

typedef enum {
    EvInput,
    EvAutoTick,
} AppEventType;

typedef struct {
    AppEventType type;
    InputEvent input;
} AppEvent;

/* Security verdict for a scanned card. */
typedef enum {
    VerdUnknown = 0, /* can't tell passively (EMV/JCOP/Type-4, or ambiguous) */
    VerdSecure, /* AES-class, no public crypto break */
    VerdClone, /* no read-auth / UID-only -> cloneable */
    VerdBroken, /* crypto broken (Crypto1, orig DESFire 3DES) */
} Verdict;

static const char* verdict_str(int v) {
    switch(v) {
    case VerdSecure: return "SECURE";
    case VerdClone: return "CLONE";
    case VerdBroken: return "BROKEN";
    default: return "UNK";
    }
}

static bool verdict_skull(int v) {
    return v == VerdBroken || v == VerdClone;
}

typedef struct {
    Gui* gui;
    ViewPort* view_port;
    DialogsApp* dialogs;
    FuriMessageQueue* event_queue;
    FuriMutex* mutex;
    FuriTimer* auto_timer;

    Nfc* nfc;
    Iso14443_3aData* emu_data; /* reused to configure the listener */
    NfcListener* listener; /* non-NULL while emulating */

    Scene scene;
    int menu_index;

    uint8_t uid[10];
    uint8_t uid_len; /* 4 or 7 */
    char card_label[16]; /* card type inferred at read time */
    int card_verdict; /* Verdict (see enum) */
    int step_pos; /* -1 = step whole value; else step only this byte index */
    int step_index;
    uint32_t delay_ms;
    int dir;
    int cursor;
    bool auto_on; /* sweep active (emulating; may be paused) */
    bool paused; /* sweep paused: timer stopped, still emulating current UID */

    char message[32];
} App;

/* -------------------------- UID math -------------------------- */

static uint64_t uid_to_u64(const uint8_t* uid, int len) {
    uint64_t v = 0;
    int start = (len > 8) ? len - 8 : 0;
    for(int i = start; i < len; i++) v = (v << 8) | uid[i];
    return v;
}

static void u64_to_dec(uint64_t v, char* out, size_t n) {
    char tmp[24];
    int i = 0;
    if(v == 0) {
        if(n) out[0] = '0';
        if(n > 1) out[1] = '\0';
        return;
    }
    while(v > 0 && i < (int)sizeof(tmp)) {
        tmp[i++] = (char)('0' + (v % 10));
        v /= 10;
    }
    int j = 0;
    while(i > 0 && j < (int)n - 1) out[j++] = tmp[--i];
    out[j] = '\0';
}

static void step_uid(App* app, int dir) {
    uint32_t step = STEPS[app->step_index];
    int n = app->uid_len;

    /* single-byte mode: change only the selected byte, wrap within it, no carry
     * — this is the truncation test (vary one byte, watch if access changes) */
    if(app->step_pos >= 0 && app->step_pos < n) {
        int i = app->step_pos;
        int v = (int)app->uid[i] + (dir > 0 ? (int)step : -(int)step);
        v %= 256;
        if(v < 0) v += 256;
        app->uid[i] = (uint8_t)v;
        return;
    }

    if(dir > 0) {
        uint32_t carry = step;
        for(int i = n - 1; i >= 0 && carry; i--) {
            uint32_t v = app->uid[i] + (carry & 0xFF);
            app->uid[i] = (uint8_t)(v & 0xFF);
            carry = (carry >> 8) + (v >> 8);
        }
    } else {
        uint32_t s = step;
        for(int i = n - 1; i >= 0 && s; i--) {
            int32_t sub = (int32_t)(s & 0xFF);
            s >>= 8;
            int32_t v = (int32_t)app->uid[i] - sub;
            if(v < 0) {
                v += 256;
                s += 1;
            }
            app->uid[i] = (uint8_t)v;
        }
    }
}

/* -------------------------- NFC emulate / read (call WITHOUT the mutex) ----- */

static void emu_data_set_defaults(App* app);

static NfcCommand nfc_listener_cb(NfcGenericEvent event, void* ctx) {
    UNUSED(event);
    UNUSED(ctx);
    return NfcCommandContinue;
}

static void emu_stop(App* app) {
    if(app->listener) {
        nfc_listener_stop(app->listener);
        nfc_listener_free(app->listener);
        app->listener = NULL;
    }
}

static void emu_start(App* app) {
    emu_stop(app);

    iso14443_3a_set_uid(app->emu_data, app->uid, app->uid_len);
    emu_data_set_defaults(app); /* plausible ATQA/SAK so readers accept it */

    app->listener =
        nfc_listener_alloc(app->nfc, NfcProtocolIso14443_3a, (const NfcDeviceData*)app->emu_data);
    nfc_listener_start(app->listener, nfc_listener_cb, app);
}

/* True if a 4-byte UID is an ISO14443-3 random ID (RID): first byte 0x08.
 * DESFire / EV1+ in random-UID mode presents exactly this — a signal that the
 * deployment relies on the AES layer, so UID cloning is pointless. */
static bool uid_is_random(const uint8_t* uid, uint8_t len) {
    return (len == 4 && uid[0] == 0x08);
}

/* Classify a card from its ISO14443-3A ATQA/SAK fingerprint into a type label
 * and a security verdict. DESFire refinement (via GetVersion) is applied by the
 * caller. See the bundled VULN_CATALOG.md for sources and the collision caveats
 * (SAK 0x08 = whole Crypto1 family; SAK 0x00/ATQA 0044 = whole UL/NTAG family,
 * which can hide a secure UL-AES / NTAG-424). */
static Verdict classify_hf(char* out, size_t n, const uint8_t* atqa, uint8_t sak) {
    if(sak & 0x20) { /* ISO14443-4 -> resolved by GetVersion in caller */
        snprintf(out, n, "ISO14443-4");
        return VerdUnknown;
    } else if(sak == 0x08 || sak == 0x18 || sak == 0x09) { /* Crypto1 family */
        snprintf(out, n, "%s", sak == 0x18 ? "MFClassic4K" : (sak == 0x09 ? "MF Mini" : "MFClassic1K"));
        return VerdBroken;
    } else if(sak == 0x00 && atqa[0] == 0x44) { /* UL / NTAG family */
        snprintf(out, n, "UL/NTAG");
        return VerdClone;
    }
    snprintf(out, n, "ISO14443-3A");
    return VerdClone;
}

/* --- exact DESFire generation via GetVersion (ISO14443-4) ------------------ */

typedef struct {
    FuriSemaphore* sem;
    bool got;
    bool ok;
    MfDesfireVersion version;
} DesfireProbe;

static NfcCommand desfire_probe_cb(NfcGenericEvent event, void* ctx) {
    DesfireProbe* p = ctx;
    if(!p->got) {
        /* the card is activated in this callback — issue GetVersion (no auth) */
        MfDesfirePoller* poller = (MfDesfirePoller*)event.instance;
        MfDesfireError err = mf_desfire_poller_read_version(poller, &p->version);
        p->ok = (err == MfDesfireErrorNone);
        p->got = true;
        furi_semaphore_release(p->sem);
    }
    return NfcCommandStop;
}

/* Blocking: run a short MfDesfire poller session to fetch the version. Returns
 * true and fills *ver on success; false if no DESFire answered in time. */
static bool desfire_get_version(App* app, MfDesfireVersion* ver) {
    DesfireProbe p = {0};
    p.sem = furi_semaphore_alloc(1, 0);
    NfcPoller* poller = nfc_poller_alloc(app->nfc, NfcProtocolMfDesfire);
    nfc_poller_start(poller, desfire_probe_cb, &p);
    bool signaled = (furi_semaphore_acquire(p.sem, furi_ms_to_ticks(2500)) == FuriStatusOk);
    nfc_poller_stop(poller);
    nfc_poller_free(poller);
    furi_semaphore_free(p.sem);
    if(signaled && p.ok) {
        *ver = p.version;
        return true;
    }
    return false;
}

static void do_read(App* app) {
    emu_stop(app);

    /* show the reading screen before the blocking call */
    view_port_update(app->view_port);

    Iso14443_3aData* d = iso14443_3a_alloc();
    Iso14443_3aError err = iso14443_3a_poller_sync_read(app->nfc, d);

    if(err == Iso14443_3aErrorNone) {
        size_t len = 0;
        const uint8_t* uid = iso14443_3a_get_uid(d, &len);
        if(uid && (len == 4 || len == 7)) {
            uint8_t uidbuf[10];
            memcpy(uidbuf, uid, len);
            uint8_t atqa[2] = {d->atqa[0], d->atqa[1]};
            uint8_t sak = d->sak;

            char label[16];
            Verdict verd = classify_hf(label, sizeof(label), atqa, sak);

            /* refine ISO14443-4 cards via DESFire GetVersion */
            if(sak & 0x20) {
                MfDesfireVersion ver;
                if(desfire_get_version(app, &ver)) {
                    switch(ver.hw_major) {
                    case 0x00: /* MF3ICD40 — original DESFire, 3DES side-channel */
                        snprintf(label, sizeof(label), "DESFire orig");
                        verd = VerdBroken;
                        break;
                    case 0x01: snprintf(label, sizeof(label), "DESFire EV1"); verd = VerdSecure; break;
                    case 0x08: snprintf(label, sizeof(label), "DESFireLight"); verd = VerdSecure; break;
                    case 0x12: snprintf(label, sizeof(label), "DESFire EV2"); verd = VerdSecure; break;
                    case 0x30:
                    case 0x33: snprintf(label, sizeof(label), "DESFire EV3"); verd = VerdSecure; break;
                    default: snprintf(label, sizeof(label), "DESFire EVx"); verd = VerdSecure; break;
                    }
                } else {
                    /* RATS-capable but not DESFire: EMV / JCOP / Plus SL3 / ... */
                    snprintf(label, sizeof(label), "Type-4");
                    verd = VerdUnknown;
                }
            }

            furi_mutex_acquire(app->mutex, FuriWaitForever);
            memcpy(app->uid, uidbuf, len);
            app->uid_len = (uint8_t)len;
            snprintf(app->card_label, sizeof(app->card_label), "%s", label);
            app->card_verdict = verd;
            app->message[0] = '\0';
            app->scene = SceneEdit;
            furi_mutex_release(app->mutex);
        } else {
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            snprintf(app->message, sizeof(app->message), "Unsupported UID len");
            app->scene = SceneMenu;
            furi_mutex_release(app->mutex);
        }
    } else {
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        snprintf(app->message, sizeof(app->message), "No card / read error");
        app->scene = SceneMenu;
        furi_mutex_release(app->mutex);
    }

    iso14443_3a_free(d);
}

/* set atqa/sak on emu_data to plausible values for the current uid length */
static void emu_data_set_defaults(App* app) {
    if(app->uid_len == 7) {
        app->emu_data->atqa[0] = 0x44;
        app->emu_data->atqa[1] = 0x00;
        app->emu_data->sak = 0x00;
    } else {
        app->emu_data->atqa[0] = 0x04;
        app->emu_data->atqa[1] = 0x00;
        app->emu_data->sak = 0x08;
    }
}

/* -------------------------- .nfc load / save (call WITHOUT the mutex) ------ */

static void do_load_nfc(App* app) {
    emu_stop(app);

    FuriString* path = furi_string_alloc();
    furi_string_set(path, NFC_DIR);
    DialogsFileBrowserOptions opts;
    dialog_file_browser_set_basic_options(&opts, ".nfc", NULL);
    opts.base_path = NFC_DIR;
    bool picked = dialog_file_browser_show(app->dialogs, path, path, &opts);

    if(picked) {
        NfcDevice* dev = nfc_device_alloc();
        bool ok = nfc_device_load(dev, furi_string_get_cstr(path));
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        if(ok) {
            size_t len = 0;
            const uint8_t* uid = nfc_device_get_uid(dev, &len);
            if(uid && (len == 4 || len == 7)) {
                memcpy(app->uid, uid, len);
                app->uid_len = (uint8_t)len;
                snprintf(app->card_label, sizeof(app->card_label), "loaded");
                app->card_verdict = VerdUnknown;
                app->message[0] = '\0';
                app->scene = SceneEdit;
            } else {
                snprintf(app->message, sizeof(app->message), "Unsupported UID len");
                app->scene = SceneMenu;
            }
        } else {
            snprintf(app->message, sizeof(app->message), "Load failed");
            app->scene = SceneMenu;
        }
        furi_mutex_release(app->mutex);
        nfc_device_free(dev);
    }
    furi_string_free(path);
}

static void do_save_nfc(App* app) {
    emu_stop(app);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    uint8_t uid[10];
    uint8_t len = app->uid_len;
    memcpy(uid, app->uid, len);
    furi_mutex_release(app->mutex);

    iso14443_3a_set_uid(app->emu_data, uid, len);
    emu_data_set_defaults(app);

    char hex[10 * 2 + 1];
    for(int i = 0; i < len; i++) snprintf(hex + i * 2, 3, "%02X", uid[i]);

    char fn[96];
    snprintf(fn, sizeof(fn), NFC_DIR "/STEP_%s.nfc", hex);

    NfcDevice* dev = nfc_device_alloc();
    nfc_device_set_data(dev, NfcProtocolIso14443_3a, (const NfcDeviceData*)app->emu_data);
    bool ok = nfc_device_save(dev, fn);
    nfc_device_free(dev);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    snprintf(app->message, sizeof(app->message), ok ? "Saved to nfc" : "Save failed");
    furi_mutex_release(app->mutex);
}

/* -------------------------- GUI -------------------------- */

static const char* const kMenu[] = {
    "Read card",
    "Load saved (.nfc)",
    "Manual / continue",
    "Save current UID",
};
#define MENU_COUNT ((int)(sizeof(kMenu) / sizeof(kMenu[0])))

static void draw_menu(Canvas* c, App* app) {
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 11, "NFC UID Stepper");
    canvas_set_font(c, FontSecondary);
    for(int i = 0; i < MENU_COUNT; i++) {
        int y = 23 + i * 10;
        if(app->menu_index == i) {
            canvas_draw_box(c, 0, y - 8, 128, 10);
            canvas_set_color(c, ColorWhite);
            canvas_draw_str(c, 4, y, kMenu[i]);
            canvas_set_color(c, ColorBlack);
        } else {
            canvas_draw_str(c, 4, y, kMenu[i]);
        }
    }
    if(app->message[0])
        canvas_draw_str(c, 2, 63, app->message);
    else
        canvas_draw_str(c, 2, 63, "OK select   Back exit");
}

static void draw_read(Canvas* c, App* app) {
    UNUSED(app);
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 12, "Reading NFC...");
    canvas_set_font(c, FontSecondary);
    canvas_draw_str(c, 2, 30, "Hold card to back");
    canvas_draw_str(c, 2, 62, "(blocks until a card)");
}

static void draw_token(Canvas* c, int x, int y, const char* s, bool hi) {
    int w = canvas_string_width(c, s);
    if(hi) {
        canvas_draw_box(c, x - 1, y - 9, w + 3, 11);
        canvas_set_color(c, ColorWhite);
        canvas_draw_str(c, x + 1, y, s);
        canvas_set_color(c, ColorBlack);
    } else {
        canvas_draw_str(c, x, y, s);
    }
}

/* crude ~9x9 skull mark drawn at top-left (x, y) */
static void draw_skull(Canvas* c, int x, int y) {
    canvas_draw_rframe(c, x, y, 9, 7, 3); /* cranium */
    canvas_draw_dot(c, x + 2, y + 3); /* left eye */
    canvas_draw_dot(c, x + 6, y + 3); /* right eye */
    canvas_draw_dot(c, x + 4, y + 4); /* nose */
    canvas_draw_line(c, x + 2, y + 7, x + 2, y + 8); /* teeth */
    canvas_draw_line(c, x + 4, y + 7, x + 4, y + 8);
    canvas_draw_line(c, x + 6, y + 7, x + 6, y + 8);
}

static void draw_edit(Canvas* c, App* app) {
    char buf[40];

    /* UID hex (field 0) */
    canvas_set_font(c, FontSecondary);
    char hexbuf[10 * 3 + 1];
    int hp = 0;
    for(int i = 0; i < app->uid_len; i++)
        hp += snprintf(hexbuf + hp, sizeof(hexbuf) - hp, "%02X ", app->uid[i]);
    if(hp > 0) hexbuf[hp - 1] = '\0';
    canvas_draw_str(c, 2, 10, "UID");
    draw_token(c, 22, 10, hexbuf, app->cursor == FieldUid);

    /* decimal + byte-position (truncation-test) selector */
    char dec[24];
    u64_to_dec(uid_to_u64(app->uid, app->uid_len), dec, sizeof(dec));
    snprintf(buf, sizeof(buf), "DEC:%s", dec);
    canvas_draw_str(c, 2, 22, buf);
    if(app->step_pos < 0)
        snprintf(buf, sizeof(buf), "all");
    else
        snprintf(buf, sizeof(buf), "B%d", app->step_pos);
    draw_token(c, 104, 22, buf, app->cursor == FieldPos);

    /* fields row: Len, step, delay, dir */
    snprintf(buf, sizeof(buf), "L%u", (unsigned)app->uid_len);
    draw_token(c, 2, 34, buf, app->cursor == FieldLen);
    snprintf(buf, sizeof(buf), "x%lu", (unsigned long)STEPS[app->step_index]);
    draw_token(c, 26, 34, buf, app->cursor == FieldStep);
    snprintf(
        buf,
        sizeof(buf),
        "%lu.%lus",
        (unsigned long)(app->delay_ms / 1000),
        (unsigned long)((app->delay_ms % 1000) / 100));
    draw_token(c, 66, 34, buf, app->cursor == FieldDelay);
    snprintf(buf, sizeof(buf), "D%c", app->dir > 0 ? '+' : '-');
    draw_token(c, 104, 34, buf, app->cursor == FieldDir);

    /* status line: emulation state when active, else the card-audit label
     * (type + live random-UID flag) */
    char statusbuf[32];
    const char* status;
    if(app->auto_on) {
        status = app->paused ? "AUTO paused" : "AUTO sweeping";
    } else {
        snprintf(
            statusbuf,
            sizeof(statusbuf),
            "%s %s%s",
            app->card_label,
            verdict_str(app->card_verdict),
            uid_is_random(app->uid, app->uid_len) ? " RND" : "");
        status = statusbuf;
    }
    if(app->message[0]) {
        /* transient confirmation (e.g. "Saved to nfc") until the next keypress */
        canvas_draw_box(c, 0, 40, 128, 11);
        canvas_set_color(c, ColorWhite);
        canvas_draw_str(c, 2, 49, app->message);
        canvas_set_color(c, ColorBlack);
    } else if(app->auto_on) {
        canvas_draw_box(c, 0, 40, 128, 11);
        canvas_set_color(c, ColorWhite);
        canvas_draw_str(c, 2, 49, status);
        canvas_set_color(c, ColorBlack);
    } else if(verdict_skull(app->card_verdict)) {
        /* skull-marked vulnerable card (BROKEN crypto or UID-cloneable) */
        draw_skull(c, 2, 41);
        canvas_draw_str(c, 14, 49, status);
    } else {
        canvas_draw_str(c, 2, 49, status);
    }

    canvas_draw_str(c, 2, 62, "OK pause  hold=save");
}

static void draw_cb(Canvas* c, void* ctx) {
    App* app = ctx;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    canvas_clear(c);
    canvas_set_color(c, ColorBlack);
    switch(app->scene) {
    case SceneMenu:
        draw_menu(c, app);
        break;
    case SceneRead:
        draw_read(c, app);
        break;
    case SceneEdit:
        draw_edit(c, app);
        break;
    }
    furi_mutex_release(app->mutex);
}

static void input_cb(InputEvent* event, void* ctx) {
    App* app = ctx;
    AppEvent ev = {.type = EvInput, .input = *event};
    furi_message_queue_put(app->event_queue, &ev, FuriWaitForever);
}

static void auto_timer_cb(void* ctx) {
    App* app = ctx;
    AppEvent ev = {.type = EvAutoTick};
    furi_message_queue_put(app->event_queue, &ev, 0);
}

/* -------------------------- lifecycle -------------------------- */

static App* app_alloc(void) {
    App* app = malloc(sizeof(App));
    memset(app, 0, sizeof(App));

    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->event_queue = furi_message_queue_alloc(16, sizeof(AppEvent));
    app->auto_timer = furi_timer_alloc(auto_timer_cb, FuriTimerTypePeriodic, app);

    app->nfc = nfc_alloc();
    app->emu_data = iso14443_3a_alloc();

    app->scene = SceneMenu;
    app->uid_len = 4;
    snprintf(app->card_label, sizeof(app->card_label), "manual");
    app->uid[0] = 0xDE;
    app->uid[1] = 0xAD;
    app->uid[2] = 0xBE;
    app->uid[3] = 0xEF;
    app->step_index = 0;
    app->step_pos = -1; /* whole-value stepping by default */
    app->delay_ms = 500;
    app->dir = +1;
    app->cursor = FieldUid;

    app->dialogs = furi_record_open(RECORD_DIALOGS);
    app->gui = furi_record_open(RECORD_GUI);
    app->view_port = view_port_alloc();
    view_port_draw_callback_set(app->view_port, draw_cb, app);
    view_port_input_callback_set(app->view_port, input_cb, app);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);
    return app;
}

static void app_free(App* app) {
    furi_timer_stop(app->auto_timer);
    furi_timer_free(app->auto_timer);
    emu_stop(app);
    iso14443_3a_free(app->emu_data);
    nfc_free(app->nfc);

    gui_remove_view_port(app->gui, app->view_port);
    view_port_free(app->view_port);
    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_DIALOGS);

    furi_message_queue_free(app->event_queue);
    furi_mutex_free(app->mutex);
    free(app);
}

int32_t nfc_uid_stepper_app(void* p) {
    UNUSED(p);
    App* app = app_alloc();

    bool running = true;
    AppEvent event;
    while(running) {
        if(furi_message_queue_get(app->event_queue, &event, FuriWaitForever) != FuriStatusOk)
            continue;

        bool a_emu = false, a_stop = false, a_read = false;
        bool a_timer_start = false, a_timer_stop = false;
        bool a_load = false, a_save = false;

        furi_mutex_acquire(app->mutex, FuriWaitForever);

        if(event.type == EvAutoTick) {
            if(app->auto_on && !app->paused) {
                step_uid(app, app->dir);
                a_emu = true;
            }
        } else { /* EvInput */
            InputEvent* in = &event.input;
            bool press = (in->type == InputTypeShort);
            bool repeat = (in->type == InputTypeRepeat);

            if(app->scene == SceneMenu) {
                if(press && in->key == InputKeyUp) {
                    app->menu_index = (app->menu_index + MENU_COUNT - 1) % MENU_COUNT;
                } else if(press && in->key == InputKeyDown) {
                    app->menu_index = (app->menu_index + 1) % MENU_COUNT;
                } else if(press && in->key == InputKeyOk) {
                    app->message[0] = '\0';
                    switch(app->menu_index) {
                    case 0: /* Read card */
                        app->scene = SceneRead;
                        a_read = true;
                        break;
                    case 1: /* Load saved */
                        a_load = true;
                        break;
                    case 2: /* Manual / continue */
                        snprintf(app->card_label, sizeof(app->card_label), "manual");
                        app->card_verdict = VerdUnknown;
                        app->scene = SceneEdit;
                        break;
                    case 3: /* Save current UID */
                        a_save = true;
                        break;
                    }
                } else if(press && in->key == InputKeyBack) {
                    running = false;
                }
            } else if(app->scene == SceneEdit) {
                bool ud = (press || repeat);
                if(press || in->type == InputTypeLong)
                    app->message[0] = '\0'; /* dismiss prior confirmation */
                if(ud && in->key == InputKeyUp) {
                    switch(app->cursor) {
                    case FieldUid:
                        step_uid(app, +1);
                        if(app->auto_on) a_emu = true;
                        break;
                    case FieldPos:
                        if(app->step_pos < (int)app->uid_len - 1)
                            app->step_pos++;
                        else
                            app->step_pos = -1;
                        break;
                    case FieldLen:
                        if(app->uid_len == 4) {
                            app->uid[4] = app->uid[5] = app->uid[6] = 0;
                            app->uid_len = 7;
                        }
                        if(app->auto_on) a_emu = true;
                        break;
                    case FieldStep:
                        if(app->step_index < STEP_COUNT - 1) app->step_index++;
                        break;
                    case FieldDelay:
                        if(app->delay_ms + DELAY_INC <= DELAY_MAX) app->delay_ms += DELAY_INC;
                        if(app->auto_on) a_timer_start = true;
                        break;
                    case FieldDir:
                        app->dir = +1;
                        break;
                    default:
                        break;
                    }
                } else if(ud && in->key == InputKeyDown) {
                    switch(app->cursor) {
                    case FieldUid:
                        step_uid(app, -1);
                        if(app->auto_on) a_emu = true;
                        break;
                    case FieldPos:
                        if(app->step_pos < 0)
                            app->step_pos = (int)app->uid_len - 1;
                        else
                            app->step_pos--;
                        break;
                    case FieldLen:
                        if(app->uid_len == 7) {
                            app->uid_len = 4;
                            if(app->step_pos >= 4) app->step_pos = -1;
                        }
                        if(app->auto_on) a_emu = true;
                        break;
                    case FieldStep:
                        if(app->step_index > 0) app->step_index--;
                        break;
                    case FieldDelay:
                        if(app->delay_ms >= DELAY_MIN + DELAY_INC) app->delay_ms -= DELAY_INC;
                        if(app->auto_on) a_timer_start = true;
                        break;
                    case FieldDir:
                        app->dir = -1;
                        break;
                    default:
                        break;
                    }
                } else if(press && in->key == InputKeyLeft) {
                    app->cursor = (app->cursor + FieldCount - 1) % FieldCount;
                } else if(press && in->key == InputKeyRight) {
                    app->cursor = (app->cursor + 1) % FieldCount;
                } else if(press && in->key == InputKeyOk) {
                    /* OK: idle -> start sweep; sweeping -> pause; paused -> resume */
                    if(!app->auto_on) {
                        app->auto_on = true;
                        app->paused = false;
                        a_emu = true;
                        a_timer_start = true;
                    } else if(!app->paused) {
                        app->paused = true; /* hold current UID, keep emulating */
                        a_timer_stop = true;
                    } else {
                        app->paused = false;
                        a_timer_start = true;
                    }
                } else if(in->key == InputKeyOk && in->type == InputTypeLong) {
                    /* OK hold: quick-save current UID (stops emulation) */
                    app->auto_on = false;
                    app->paused = false;
                    a_timer_stop = true;
                    a_save = true;
                } else if(in->key == InputKeyBack) {
                    if(in->type == InputTypeLong) {
                        running = false;
                    } else if(press) {
                        if(app->auto_on) { /* stop the sweep */
                            app->auto_on = false;
                            app->paused = false;
                            a_timer_stop = true;
                            a_stop = true;
                        } else {
                            app->scene = SceneMenu;
                        }
                    }
                }
            }
        }

        furi_mutex_release(app->mutex);

        /* worker/timer ops outside the mutex */
        if(a_emu) {
            emu_start(app);
        } else if(a_stop) {
            emu_stop(app);
        }
        if(a_timer_stop) {
            furi_timer_stop(app->auto_timer);
        }
        if(a_timer_start) {
            furi_timer_stop(app->auto_timer);
            furi_timer_start(app->auto_timer, furi_ms_to_ticks(app->delay_ms));
        }
        if(a_read) {
            do_read(app); /* blocking */
        }
        if(a_load) {
            do_load_nfc(app);
        }
        if(a_save) {
            do_save_nfc(app);
        }

        view_port_update(app->view_port);
    }

    app_free(app);
    return 0;
}
