/*
 * Reader Audit — Flipper Zero app
 *
 * Emulates an ISO14443-A card to a target reader and classifies what the reader
 * DOES after selecting the card:
 *   - selects, reads the UID, then HALTs with no further command  -> UID-ONLY
 *   - sends RATS (0xE0) / DESFire native                          -> ISO14443-4 crypto
 *   - sends Mifare auth (0x60/0x61) or UL-C auth (0x1A)           -> Crypto1 / 3DES
 *   - sends READ (0x30/0x3A)                                      -> reads card data
 *
 * This answers "does this reader trust the clonable UID, or does it use the card
 * crypto?" — the single most useful access-control audit. Read a valid card first
 * (so the reader recognises the credential), or audit with a default UID for
 * readers that talk to any card.
 *
 * NOTE: the truncation decision (backend dropping ID bytes) is NOT visible on the
 * RF wire — use the Stepper apps' per-byte sweep + watch the door for that.
 */
#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <storage/storage.h>
#include <nfc/nfc.h>
#include <nfc/nfc_listener.h>
#include <nfc/protocols/nfc_protocol.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_listener.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller_sync.h>
#include <toolbox/bit_buffer.h>

typedef enum {
    SceneMenu,
    SceneRead,
    SceneAudit,
} Scene;

typedef enum {
    EvInput,
    EvReaderActivity, /* listener saw a reader command */
} AppEventType;

typedef struct {
    AppEventType type;
    InputEvent input;
} AppEvent;

typedef struct {
    Gui* gui;
    ViewPort* view_port;
    FuriMessageQueue* event_queue;
    FuriMutex* mutex;

    Nfc* nfc;
    Iso14443_3aData* emu_data;
    NfcListener* listener;

    uint8_t uid[10];
    uint8_t uid_len;

    Scene scene;
    int menu_index;

    /* audit results (written by the listener thread under mutex) */
    bool saw_rats;
    bool saw_auth;
    bool saw_read;
    bool saw_write; /* reader wrote back (anti-passback / counter) */
    bool saw_other;
    bool saw_halt;
    uint8_t last_cmd[8];
    uint8_t last_cmd_len;

    char message[32];
} App;

/* -------------------------- emulate + audit -------------------------- */

static void audit_reset(App* app) {
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->saw_rats = app->saw_auth = app->saw_read = app->saw_write = app->saw_other =
        app->saw_halt = false;
    app->last_cmd_len = 0;
    furi_mutex_release(app->mutex);
}

/* Listener callback — runs on the listener thread. Classifies each command the
 * reader sends to our emulated card. */
static NfcCommand listener_cb(NfcGenericEvent event, void* ctx) {
    App* app = ctx;
    Iso14443_3aListenerEvent* ev = event.event_data;
    if(!ev) return NfcCommandContinue;

    if(ev->type == Iso14443_3aListenerEventTypeReceivedStandardFrame ||
       ev->type == Iso14443_3aListenerEventTypeReceivedData) {
        const BitBuffer* b = ev->data->buffer;
        size_t n = bit_buffer_get_size_bytes(b);
        if(n > 0) {
            uint8_t cmd = bit_buffer_get_byte(b, 0);
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            uint8_t k = (n < sizeof(app->last_cmd)) ? (uint8_t)n : (uint8_t)sizeof(app->last_cmd);
            app->last_cmd_len = k;
            for(uint8_t i = 0; i < k; i++) app->last_cmd[i] = bit_buffer_get_byte(b, i);
            if(cmd == 0xE0) /* RATS */
                app->saw_rats = true;
            else if(cmd == 0x60 || cmd == 0x61 || cmd == 0x1A) /* MF / UL-C auth */
                app->saw_auth = true;
            else if(cmd == 0xA0 || cmd == 0xA2) /* MFC write / UL write -> writes back */
                app->saw_write = true;
            else if(cmd == 0x30 || cmd == 0x3A || cmd == 0x39) /* READ family */
                app->saw_read = true;
            else
                app->saw_other = true;
            furi_mutex_release(app->mutex);
        }
    } else if(ev->type == Iso14443_3aListenerEventTypeHalted) {
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        app->saw_halt = true;
        furi_mutex_release(app->mutex);
    } else {
        return NfcCommandContinue;
    }

    AppEvent e = {.type = EvReaderActivity};
    furi_message_queue_put(app->event_queue, &e, 0);
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
    if(app->uid_len == 7) {
        app->emu_data->atqa[0] = 0x44;
        app->emu_data->atqa[1] = 0x00;
        app->emu_data->sak = 0x00;
    } else {
        app->emu_data->atqa[0] = 0x04;
        app->emu_data->atqa[1] = 0x00;
        app->emu_data->sak = 0x08;
    }
    app->listener =
        nfc_listener_alloc(app->nfc, NfcProtocolIso14443_3a, (const NfcDeviceData*)app->emu_data);
    nfc_listener_start(app->listener, listener_cb, app);
}

static void do_read(App* app) {
    emu_stop(app);
    view_port_update(app->view_port);

    Iso14443_3aData* d = iso14443_3a_alloc();
    Iso14443_3aError err = iso14443_3a_poller_sync_read(app->nfc, d);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    if(err == Iso14443_3aErrorNone) {
        size_t len = 0;
        const uint8_t* uid = iso14443_3a_get_uid(d, &len);
        if(uid && (len == 4 || len == 7)) {
            memcpy(app->uid, uid, len);
            app->uid_len = (uint8_t)len;
            app->message[0] = '\0';
            app->scene = SceneAudit;
        } else {
            snprintf(app->message, sizeof(app->message), "Unsupported UID len");
            app->scene = SceneMenu;
        }
    } else {
        snprintf(app->message, sizeof(app->message), "No card / read error");
        app->scene = SceneMenu;
    }
    furi_mutex_release(app->mutex);
    iso14443_3a_free(d);
}

/* Append the current audit result to /ext/reader_audit.txt for the report. */
static void save_report(App* app) {
    const char* verdict;
    if(app->saw_rats || app->saw_auth)
        verdict = "CRYPTO";
    else if(app->saw_read)
        verdict = "READS-DATA";
    else if(app->saw_other)
        verdict = "SENDS-CMDS";
    else if(app->saw_halt)
        verdict = "UID-ONLY";
    else
        verdict = "no-activity";

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(storage);
    if(storage_file_open(f, "/ext/reader_audit.txt", FSAM_WRITE, FSOM_OPEN_APPEND)) {
        char line[96];
        int hp = snprintf(line, sizeof(line), "UID ");
        for(int i = 0; i < app->uid_len; i++)
            hp += snprintf(line + hp, sizeof(line) - hp, "%02X", app->uid[i]);
        hp += snprintf(
            line + hp,
            sizeof(line) - hp,
            "  verdict=%s writes_back=%d rats=%d auth=%d read=%d\n",
            verdict,
            app->saw_write,
            app->saw_rats,
            app->saw_auth,
            app->saw_read);
        storage_file_write(f, line, hp);
    }
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
}

/* -------------------------- GUI -------------------------- */

static const char* const kMenu[] = {"Read card + audit", "Audit (default UID)"};
#define MENU_COUNT ((int)(sizeof(kMenu) / sizeof(kMenu[0])))

static void draw_menu(Canvas* c, App* app) {
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 12, "Reader Audit");
    canvas_set_font(c, FontSecondary);
    for(int i = 0; i < MENU_COUNT; i++) {
        int y = 30 + i * 12;
        if(app->menu_index == i) {
            canvas_draw_box(c, 0, y - 9, 128, 11);
            canvas_set_color(c, ColorWhite);
            canvas_draw_str(c, 4, y, kMenu[i]);
            canvas_set_color(c, ColorBlack);
        } else {
            canvas_draw_str(c, 4, y, kMenu[i]);
        }
    }
    if(app->message[0])
        canvas_draw_str(c, 2, 62, app->message);
    else
        canvas_draw_str(c, 2, 62, "OK select   Back exit");
}


static void draw_read(Canvas* c) {
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 12, "Reading NFC...");
    canvas_set_font(c, FontSecondary);
    canvas_draw_str(c, 2, 30, "Hold card to back");
    canvas_draw_str(c, 2, 62, "(blocks until a card)");
}

static void draw_audit(Canvas* c, App* app) {
    char buf[40];
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 11, "Reader Audit");

    canvas_set_font(c, FontSecondary);
    int hp = 0;
    char hex[10 * 3 + 1];
    for(int i = 0; i < app->uid_len; i++)
        hp += snprintf(hex + hp, sizeof(hex) - hp, "%02X ", app->uid[i]);
    if(hp > 0) hex[hp - 1] = '\0';
    snprintf(buf, sizeof(buf), "Emu UID %s", hex);
    canvas_draw_str(c, 2, 22, buf);
    canvas_draw_str(c, 2, 32, "Present to reader...");

    /* verdict */
    const char* verdict;
    if(app->saw_rats || app->saw_auth)
        verdict = "CRYPTO (reader ok)";
    else if(app->saw_read)
        verdict = "READS DATA";
    else if(app->saw_other)
        verdict = "SENDS CMDS";
    else if(app->saw_halt)
        verdict = "UID-ONLY!";
    else
        verdict = "waiting...";

    bool insecure = (!app->saw_rats && !app->saw_auth && !app->saw_read && app->saw_halt);
    canvas_draw_box(c, 0, 36, 128, 12);
    canvas_set_color(c, ColorWhite);
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, insecure ? 14 : 2, 46, verdict);
    if(insecure) {
        /* skull for a UID-only reader */
        canvas_draw_rframe(c, 2, 38, 9, 7, 3);
        canvas_draw_dot(c, 4, 41);
        canvas_draw_dot(c, 8, 41);
    }
    canvas_set_color(c, ColorBlack);

    /* last command bytes + write-back flag */
    canvas_set_font(c, FontSecondary);
    if(app->last_cmd_len > 0) {
        int p = snprintf(buf, sizeof(buf), "cmd:");
        for(int i = 0; i < app->last_cmd_len && p < (int)sizeof(buf) - 3; i++)
            p += snprintf(buf + p, sizeof(buf) - p, "%02X", app->last_cmd[i]);
        if(app->saw_write && p < (int)sizeof(buf) - 6)
            snprintf(buf + p, sizeof(buf) - p, " +WR");
        canvas_draw_str(c, 2, 58, buf);
    } else if(app->saw_write) {
        canvas_draw_str(c, 2, 58, "writes back (counter?)");
    }
    canvas_draw_str(c, 2, 64, "OK reset  Back saves");
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
        draw_read(c);
        break;
    case SceneAudit:
        draw_audit(c, app);
        break;
    }
    furi_mutex_release(app->mutex);
}

static void input_cb(InputEvent* event, void* ctx) {
    App* app = ctx;
    AppEvent ev = {.type = EvInput, .input = *event};
    furi_message_queue_put(app->event_queue, &ev, FuriWaitForever);
}

/* -------------------------- lifecycle -------------------------- */

static App* app_alloc(void) {
    App* app = malloc(sizeof(App));
    memset(app, 0, sizeof(App));

    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->event_queue = furi_message_queue_alloc(32, sizeof(AppEvent));
    app->nfc = nfc_alloc();
    app->emu_data = iso14443_3a_alloc();

    app->scene = SceneMenu;
    app->uid_len = 4;
    app->uid[0] = 0x04;
    app->uid[1] = 0xA1;
    app->uid[2] = 0xB2;
    app->uid[3] = 0xC3;

    app->gui = furi_record_open(RECORD_GUI);
    app->view_port = view_port_alloc();
    view_port_draw_callback_set(app->view_port, draw_cb, app);
    view_port_input_callback_set(app->view_port, input_cb, app);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);
    return app;
}

static void app_free(App* app) {
    emu_stop(app);
    iso14443_3a_free(app->emu_data);
    nfc_free(app->nfc);

    gui_remove_view_port(app->gui, app->view_port);
    view_port_free(app->view_port);
    furi_record_close(RECORD_GUI);

    furi_message_queue_free(app->event_queue);
    furi_mutex_free(app->mutex);
    free(app);
}

int32_t reader_audit_app(void* p) {
    UNUSED(p);
    App* app = app_alloc();

    bool running = true;
    AppEvent event;
    while(running) {
        if(furi_message_queue_get(app->event_queue, &event, FuriWaitForever) != FuriStatusOk)
            continue;

        bool a_read = false, a_emu = false, a_stop = false;

        furi_mutex_acquire(app->mutex, FuriWaitForever);
        if(event.type == EvReaderActivity) {
            /* just trigger a redraw below */
        } else { /* EvInput */
            InputEvent* in = &event.input;
            bool press = (in->type == InputTypeShort);
            if(app->scene == SceneMenu) {
                if(press && in->key == InputKeyUp) {
                    app->menu_index = (app->menu_index + MENU_COUNT - 1) % MENU_COUNT;
                } else if(press && in->key == InputKeyDown) {
                    app->menu_index = (app->menu_index + 1) % MENU_COUNT;
                } else if(press && in->key == InputKeyOk) {
                    app->message[0] = '\0';
                    if(app->menu_index == 0) { /* read + audit */
                        app->scene = SceneRead;
                        a_read = true;
                    } else { /* audit default UID */
                        app->scene = SceneAudit;
                        a_emu = true;
                    }
                } else if(press && in->key == InputKeyBack) {
                    running = false;
                }
            } else if(app->scene == SceneAudit) {
                if(press && in->key == InputKeyOk) {
                    a_emu = true; /* reset + restart audit */
                } else if(in->key == InputKeyBack) {
                    app->scene = SceneMenu;
                    a_stop = true;
                }
            }
        }
        furi_mutex_release(app->mutex);

        if(a_stop) {
            save_report(app); /* persist the audit result before leaving */
            emu_stop(app);
        }
        if(a_read) do_read(app); /* blocking; may set scene to Audit */
        /* if the read succeeded we are now in Audit — start emulating */
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        bool go_emu = a_emu || (a_read && app->scene == SceneAudit);
        furi_mutex_release(app->mutex);
        if(go_emu) {
            audit_reset(app);
            emu_start(app);
        }

        view_port_update(app->view_port);
    }

    app_free(app);
    return 0;
}
