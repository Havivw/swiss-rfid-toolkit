/*
 * Cloner Sniffer — Flipper Zero app  (SwissNFC/RFID toolkit)
 *
 * Reverse-engineer a magic-card writer/cloner by turning the Flipper into the
 * "card". It emulates a target card (UID/ATQA/SAK read from your real card) and
 * LOGS every raw frame the cloner sends when it tries to write. The cloner's
 * proprietary magic-unlock/UID-write commands land in /ext/cloner_sniff.txt.
 *
 * Modes:
 *   Passive        - just log every frame.
 *   ACK knocks     - additionally reply 0x0A (4-bit) to short/backdoor frames,
 *                    like a gen1a card would, to coax the cloner into sending
 *                    the rest of its sequence.
 *
 * This is NOT a passive over-the-air sniffer between two devices (the Flipper
 * can't reliably do that at 13.56). It is a card-emulation trap: present THIS
 * to the cloner in write mode.
 *
 * AUTHORIZED RESEARCH ONLY. Use with hardware you own.
 */
#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <storage/storage.h>
#include <dialogs/dialogs.h>
#include <nfc/nfc.h>
#include <nfc/nfc_device.h>
#include <nfc/nfc_listener.h>
#include <nfc/protocols/nfc_protocol.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller_sync.h>
#include <nfc/protocols/mf_classic/mf_classic.h>
#include <nfc/protocols/mf_classic/mf_classic_listener.h>
#include <toolbox/bit_buffer.h>

#define NFC_DIR "/ext/nfc"

#define LOG_PATH "/ext/cloner_sniff.txt"
#define MAX_FRAMES 400
#define FRAME_MAX_BYTES 32

typedef struct {
    uint16_t bits;
    uint8_t n; /* stored bytes (<= FRAME_MAX_BYTES) */
    uint8_t kind; /* 0 = standard frame, 1 = raw data */
    uint8_t d[FRAME_MAX_BYTES];
} Frame;

/* an auth nonce set collected from the cloner (for mfkey32 key recovery) */
#define MAX_AUTHS 40
typedef struct {
    uint8_t block;
    uint8_t ktype; /* 0=A 1=B */
    uint8_t nt[4];
    uint8_t nr[4];
    uint8_t ar[4];
} AuthRec;

typedef enum {
    SceneMenu,
    SceneBusy,
    SceneEmulate,
    SceneSaved,
} Scene;

typedef enum {
    EvInput,
    EvActivity,
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
    DialogsApp* dialogs;
    bool listening;

    /* full Mifare Classic emulation (mode 3) */
    NfcListener* mfc_listener;
    MfClassicData* mfc_src; /* baseline we emulate */
    MfClassicData* mfc_result; /* memory after the cloner ran */
    bool mfc_mode;
    int auth_events;
    int changed_blocks;
    bool block0_changed;
    AuthRec auths[MAX_AUTHS];
    int auth_rec_count;

    uint8_t uid[10];
    uint8_t uid_len;
    uint8_t atqa[2];
    uint8_t sak;
    bool have_card;

    bool ack_mode;
    bool raw_mode; /* skip auto-anticollision so pre-select frames surface */
    Scene scene;
    int menu_index;

    /* capture (written by NFC thread under mutex) */
    Frame* frames;
    int frame_count;
    int field_on;
    int activated;
    int saved_count;
    char message[40];
} App;

static const char* const kMenu[] = {
    "Sniff: passive",
    "Sniff: ACK knocks",
    "Raw (no anticol)",
    "Emul MFC (.nfc)"};
#define MENU_COUNT ((int)(sizeof(kMenu) / sizeof(kMenu[0])))

/* -------------------------- emulate + capture -------------------------- */

/* Is this a short "backdoor knock" worth ACKing? gen1a uses a 7-bit 0x40; many
 * magic cards lead with a tiny frame or a 0x4x/0x9x command. */
static bool is_knock(const BitBuffer* b, size_t bits, size_t bytes) {
    if(bits <= 8) return true; /* 7-bit short frame (e.g. gen1a 0x40) */
    if(bytes >= 1) {
        uint8_t c = bit_buffer_get_byte(b, 0);
        if(c == 0x40 || c == 0x43 || c == 0x90 || c == 0xCF || c == 0x1B) return true;
    }
    return false;
}

/* Raw HAL listen callback — surfaces EVERY frame (incl. short/pre-select ones)
 * via RxEnd, plus field/activation markers. */
static NfcCommand nfc_raw_cb(NfcEvent event, void* ctx) {
    App* app = ctx;

    if(event.type == NfcEventTypeFieldOn) {
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        app->field_on++;
        furi_mutex_release(app->mutex);
    } else if(event.type == NfcEventTypeListenerActivated) {
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        app->activated++;
        furi_mutex_release(app->mutex);
    } else if(event.type == NfcEventTypeRxEnd) {
        const BitBuffer* b = event.data.buffer;
        size_t bits = bit_buffer_get_size(b);
        size_t bytes = bit_buffer_get_size_bytes(b);

        furi_mutex_acquire(app->mutex, FuriWaitForever);
        if(app->frame_count < MAX_FRAMES) {
            Frame* f = &app->frames[app->frame_count];
            f->bits = (uint16_t)bits;
            f->kind = 0;
            uint8_t k = (bytes < FRAME_MAX_BYTES) ? (uint8_t)bytes : FRAME_MAX_BYTES;
            f->n = k;
            for(uint8_t i = 0; i < k; i++) f->d[i] = bit_buffer_get_byte(b, i);
            app->frame_count++;
        }
        bool ack = app->ack_mode && is_knock(b, bits, bytes);
        furi_mutex_release(app->mutex);

        if(ack) {
            /* reply 0x0A (4-bit ACK), mimicking a magic card, to coax more */
            BitBuffer* tx = bit_buffer_alloc(1);
            bit_buffer_append_byte(tx, 0x0A);
            bit_buffer_set_size(tx, 4);
            nfc_iso14443a_listener_tx_custom_parity(app->nfc, tx);
            bit_buffer_free(tx);
        }

        AppEvent e = {.type = EvActivity};
        furi_message_queue_put(app->event_queue, &e, 0);
    }
    return NfcCommandContinue;
}

static void emu_stop(App* app) {
    if(app->listening) {
        nfc_stop(app->nfc);
        app->listening = false;
    }
}

static void emu_start(App* app) {
    emu_stop(app);
    nfc_config(app->nfc, NfcModeListener, NfcTechIso14443a);
    /* In raw mode, skip auto-anticollision: the HW then hands us EVERY frame
     * (incl. the cloner's pre-select magic probe) via RxEnd, though it can't
     * complete a normal select. In passive/ACK modes, let the HW handle
     * anticollision so the cloner activates the card. */
    if(!app->raw_mode)
        nfc_iso14443a_listener_set_col_res_data(
            app->nfc, app->uid, app->uid_len, app->atqa, app->sak);
    nfc_start(app->nfc, nfc_raw_cb, app);
    app->listening = true;
}

/* ---- full Mifare Classic emulation: let the cloner auth+write into us ---- */

static NfcCommand mfc_listener_cb(NfcGenericEvent event, void* ctx) {
    App* app = ctx;
    MfClassicListenerEvent* ev = event.event_data;
    if(ev && (ev->type == MfClassicListenerEventTypeAuthContextFullCollected ||
              ev->type == MfClassicListenerEventTypeAuthContextPartCollected)) {
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        app->auth_events++;
        /* stash the nonce set for mfkey32 recovery of the cloner's key */
        MfClassicAuthContext* ac = &ev->data->auth_context;
        if(app->auth_rec_count < MAX_AUTHS) {
            AuthRec* r = &app->auths[app->auth_rec_count];
            r->block = ac->block_num;
            r->ktype = (ac->key_type == MfClassicKeyTypeB) ? 1 : 0;
            memcpy(r->nt, ac->nt.data, 4);
            memcpy(r->nr, ac->nr.data, 4);
            memcpy(r->ar, ac->ar.data, 4);
            app->auth_rec_count++;
        }
        furi_mutex_release(app->mutex);
        AppEvent e = {.type = EvActivity};
        furi_message_queue_put(app->event_queue, &e, 0);
    }
    return NfcCommandContinue;
}

static bool load_mfc(App* app) {
    FuriString* path = furi_string_alloc();
    furi_string_set(path, NFC_DIR);
    DialogsFileBrowserOptions opts;
    dialog_file_browser_set_basic_options(&opts, ".nfc", NULL);
    opts.base_path = NFC_DIR;
    bool ok = false;
    if(dialog_file_browser_show(app->dialogs, path, path, &opts)) {
        NfcDevice* dev = nfc_device_alloc();
        if(nfc_device_load(dev, furi_string_get_cstr(path)) &&
           nfc_device_get_protocol(dev) == NfcProtocolMfClassic) {
            const MfClassicData* d =
                (const MfClassicData*)nfc_device_get_data(dev, NfcProtocolMfClassic);
            mf_classic_copy(app->mfc_src, d);
            ok = true;
        } else {
            snprintf(app->message, sizeof(app->message), "not Mifare Classic");
        }
        nfc_device_free(dev);
    }
    furi_string_free(path);
    return ok;
}

static void mfc_emu_start(App* app) {
    if(app->mfc_listener) return;
    app->mfc_listener =
        nfc_listener_alloc(app->nfc, NfcProtocolMfClassic, (const NfcDeviceData*)app->mfc_src);
    nfc_listener_start(app->mfc_listener, mfc_listener_cb, app);
    app->listening = true;
}

/* stop, retrieve post-write memory, diff vs the baseline we emulated */
static void mfc_emu_stop_and_diff(App* app) {
    if(!app->mfc_listener) return;
    nfc_listener_stop(app->mfc_listener);
    const MfClassicData* res =
        (const MfClassicData*)nfc_listener_get_data(app->mfc_listener, NfcProtocolMfClassic);
    if(res) mf_classic_copy(app->mfc_result, res);
    nfc_listener_free(app->mfc_listener);
    app->mfc_listener = NULL;
    app->listening = false;

    int changed = 0;
    bool b0 = false;
    uint8_t sectors = mf_classic_get_total_sectors_num(app->mfc_src->type);
    uint8_t last = mf_classic_get_first_block_num_of_sector(sectors - 1) +
                   mf_classic_get_blocks_num_in_sector(sectors - 1);
    for(uint8_t b = 0; b < last; b++) {
        if(memcmp(app->mfc_result->block[b].data, app->mfc_src->block[b].data, 16) != 0) {
            changed++;
            if(b == 0) b0 = true;
        }
    }
    app->changed_blocks = changed;
    app->block0_changed = b0;
}

/* read the real card so the emulated one matches (UID/ATQA/SAK) */
static bool do_read(App* app) {
    Iso14443_3aData* d = iso14443_3a_alloc();
    Iso14443_3aError err = iso14443_3a_poller_sync_read(app->nfc, d);
    bool ok = false;
    if(err == Iso14443_3aErrorNone) {
        size_t len = 0;
        const uint8_t* uid = iso14443_3a_get_uid(d, &len);
        if(uid && (len == 4 || len == 7)) {
            memcpy(app->uid, uid, len);
            app->uid_len = (uint8_t)len;
            app->atqa[0] = d->atqa[0];
            app->atqa[1] = d->atqa[1];
            app->sak = d->sak;
            app->have_card = true;
            ok = true;
        }
    }
    iso14443_3a_free(d);
    return ok;
}

/* write the captured frames to the SD */
static void save_log(App* app) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(storage);
    int written = 0;
    if(storage_file_open(f, LOG_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        char line[128];
        int hp = 0;
        hp = snprintf(line, sizeof(line), "Cloner Sniffer log\nEmu UID ");
        for(int i = 0; i < app->uid_len; i++)
            hp += snprintf(line + hp, sizeof(line) - hp, "%02X", app->uid[i]);
        hp += snprintf(
            line + hp,
            sizeof(line) - hp,
            " ATQA %02X%02X SAK %02X  mode=%s\nfield_on=%d activated=%d frames=%d\n",
            app->atqa[0],
            app->atqa[1],
            app->sak,
            app->raw_mode ? "raw" : (app->ack_mode ? "ACK" : "passive"),
            app->field_on,
            app->activated,
            app->frame_count);
        storage_file_write(f, line, hp);

        for(int i = 0; i < app->frame_count; i++) {
            Frame* fr = &app->frames[i];
            hp = snprintf(
                line, sizeof(line), "%c %3ub:", fr->kind ? 'D' : 'S', (unsigned)fr->bits);
            for(uint8_t j = 0; j < fr->n; j++)
                hp += snprintf(line + hp, sizeof(line) - hp, " %02X", fr->d[j]);
            hp += snprintf(line + hp, sizeof(line) - hp, "\n");
            storage_file_write(f, line, hp);
            written++;
        }

        if(app->mfc_mode) {
            hp = snprintf(
                line,
                sizeof(line),
                "MFC EMU  auth_events=%d  changed_blocks=%d  block0_changed=%d\n",
                app->auth_events,
                app->changed_blocks,
                app->block0_changed);
            storage_file_write(f, line, hp);
            /* block 0 before/after */
            hp = snprintf(line, sizeof(line), "blk0 before:");
            for(int j = 0; j < 16; j++)
                hp += snprintf(line + hp, sizeof(line) - hp, " %02X", app->mfc_src->block[0].data[j]);
            hp += snprintf(line + hp, sizeof(line) - hp, "\nblk0 after :");
            for(int j = 0; j < 16; j++)
                hp += snprintf(
                    line + hp, sizeof(line) - hp, " %02X", app->mfc_result->block[0].data[j]);
            hp += snprintf(line + hp, sizeof(line) - hp, "\n");
            storage_file_write(f, line, hp);
            /* every changed block, before/after */
            uint8_t sectors = mf_classic_get_total_sectors_num(app->mfc_src->type);
            uint8_t last = mf_classic_get_first_block_num_of_sector(sectors - 1) +
                           mf_classic_get_blocks_num_in_sector(sectors - 1);
            for(uint8_t b = 0; b < last; b++) {
                if(memcmp(app->mfc_result->block[b].data, app->mfc_src->block[b].data, 16) == 0)
                    continue;
                hp = snprintf(line, sizeof(line), "b%02u old:", b);
                for(int j = 0; j < 16; j++)
                    hp += snprintf(
                        line + hp, sizeof(line) - hp, "%02X", app->mfc_src->block[b].data[j]);
                hp += snprintf(line + hp, sizeof(line) - hp, " new:");
                for(int j = 0; j < 16; j++)
                    hp += snprintf(
                        line + hp, sizeof(line) - hp, "%02X", app->mfc_result->block[b].data[j]);
                hp += snprintf(line + hp, sizeof(line) - hp, "\n");
                storage_file_write(f, line, hp);
            }
            /* the cloner's auth nonces (for mfkey32 key recovery) */
            size_t ulen = 0;
            const uint8_t* uid = app->mfc_src->iso14443_3a_data ?
                                     iso14443_3a_get_uid(app->mfc_src->iso14443_3a_data, &ulen) :
                                     NULL;
            hp = snprintf(line, sizeof(line), "auth_nonces=%d cuid=", app->auth_rec_count);
            for(int j = 0; uid && j < 4 && j < (int)ulen; j++)
                hp += snprintf(line + hp, sizeof(line) - hp, "%02X", uid[j]);
            hp += snprintf(line + hp, sizeof(line) - hp, "\n");
            storage_file_write(f, line, hp);
            for(int i = 0; i < app->auth_rec_count; i++) {
                AuthRec* r = &app->auths[i];
                uint8_t sec = mf_classic_get_sector_by_block(r->block);
                hp = snprintf(
                    line,
                    sizeof(line),
                    "Sec %u key %c blk %u nt %02X%02X%02X%02X nr %02X%02X%02X%02X ar %02X%02X%02X%02X\n",
                    sec,
                    r->ktype ? 'B' : 'A',
                    r->block,
                    r->nt[0],
                    r->nt[1],
                    r->nt[2],
                    r->nt[3],
                    r->nr[0],
                    r->nr[1],
                    r->nr[2],
                    r->nr[3],
                    r->ar[0],
                    r->ar[1],
                    r->ar[2],
                    r->ar[3]);
                storage_file_write(f, line, hp);
            }
            written = app->changed_blocks;
        }
    }
    storage_file_close(f);
    storage_file_free(f);

    /* Also emit /ext/nfc/.mfkey32.log so the MFKey app can crack any standard
     * Crypto1 key a reader/cloner used: pair two nonces per (sector,keytype). */
    if(app->mfc_mode && app->auth_rec_count >= 2) {
        size_t ulen = 0;
        const uint8_t* uid = app->mfc_src->iso14443_3a_data ?
                                 iso14443_3a_get_uid(app->mfc_src->iso14443_3a_data, &ulen) :
                                 NULL;
        uint32_t cuid = 0;
        for(int j = 0; uid && j < 4 && j < (int)ulen; j++) cuid = (cuid << 8) | uid[j];
        File* mf = storage_file_alloc(storage);
        if(storage_file_open(mf, "/ext/nfc/.mfkey32.log", FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
            char line[160];
            /* naive pairing: consecutive records sharing sector+keytype */
            for(int i = 0; i + 1 < app->auth_rec_count; i++) {
                AuthRec* a = &app->auths[i];
                AuthRec* b = &app->auths[i + 1];
                uint8_t sa = mf_classic_get_sector_by_block(a->block);
                uint8_t sb = mf_classic_get_sector_by_block(b->block);
                if(sa != sb || a->ktype != b->ktype) continue;
                uint32_t nt0 = (a->nt[0] << 24) | (a->nt[1] << 16) | (a->nt[2] << 8) | a->nt[3];
                uint32_t nr0 = (a->nr[0] << 24) | (a->nr[1] << 16) | (a->nr[2] << 8) | a->nr[3];
                uint32_t ar0 = (a->ar[0] << 24) | (a->ar[1] << 16) | (a->ar[2] << 8) | a->ar[3];
                uint32_t nt1 = (b->nt[0] << 24) | (b->nt[1] << 16) | (b->nt[2] << 8) | b->nt[3];
                uint32_t nr1 = (b->nr[0] << 24) | (b->nr[1] << 16) | (b->nr[2] << 8) | b->nr[3];
                uint32_t ar1 = (b->ar[0] << 24) | (b->ar[1] << 16) | (b->ar[2] << 8) | b->ar[3];
                int hp = snprintf(
                    line,
                    sizeof(line),
                    "Sec %u key %c cuid %08lX nt0 %08lX nr0 %08lX ar0 %08lX nt1 %08lX nr1 %08lX ar1 %08lX\n",
                    sa,
                    a->ktype ? 'B' : 'A',
                    (unsigned long)cuid,
                    (unsigned long)nt0,
                    (unsigned long)nr0,
                    (unsigned long)ar0,
                    (unsigned long)nt1,
                    (unsigned long)nr1,
                    (unsigned long)ar1);
                storage_file_write(mf, line, hp);
            }
        }
        storage_file_close(mf);
        storage_file_free(mf);
    }

    furi_record_close(RECORD_STORAGE);
    app->saved_count = written;
}

/* -------------------------- GUI -------------------------- */

static void draw_cb(Canvas* c, void* ctx) {
    App* app = ctx;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    canvas_clear(c);
    canvas_set_color(c, ColorBlack);
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 11, "Cloner Sniffer");
    canvas_set_font(c, FontSecondary);

    if(app->scene == SceneMenu) {
        for(int i = 0; i < MENU_COUNT; i++) {
            int y = 22 + i * 10; /* 22,32,42,52 — leaves the footer clear */
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
            canvas_draw_str(c, 2, 62, "OK: read card & emulate");
    } else if(app->scene == SceneBusy) {
        canvas_draw_str(c, 2, 34, "Reading card...");
    } else if(app->scene == SceneEmulate) {
        char buf[40];
        if(app->mfc_mode) {
            snprintf(buf, sizeof(buf), "EMU MFC auth:%d non:%d", app->auth_events, app->auth_rec_count);
            canvas_draw_str(c, 2, 22, buf);
            canvas_draw_str(c, 2, 34, "Cloner: READ then WRITE");
            canvas_draw_str(c, 2, 46, "repeat write x3-5");
        } else {
            snprintf(
                buf,
                sizeof(buf),
                "%s fld:%d act:%d f:%d",
                app->raw_mode ? "raw" : (app->ack_mode ? "ACK" : "psv"),
                app->field_on,
                app->activated,
                app->frame_count);
            canvas_draw_str(c, 2, 22, buf);
            canvas_draw_str(c, 2, 32, "Present to CLONER now");
            if(app->frame_count > 0) {
                Frame* fr = &app->frames[app->frame_count - 1];
                int hp =
                    snprintf(buf, sizeof(buf), "%c%ub:", fr->kind ? 'D' : 'S', (unsigned)fr->bits);
                for(uint8_t j = 0; j < fr->n && hp < 30; j++)
                    hp += snprintf(buf + hp, sizeof(buf) - hp, "%02X", fr->d[j]);
                canvas_draw_str(c, 2, 46, buf);
            }
        }
        canvas_draw_str(c, 2, 62, "Back: stop & save");
    } else { /* SceneSaved */
        char buf[40];
        if(app->mfc_mode) {
            snprintf(
                buf,
                sizeof(buf),
                "auths:%d changed:%d",
                app->auth_events,
                app->changed_blocks);
            canvas_draw_str(c, 2, 24, buf);
            canvas_draw_str(
                c, 2, 36, app->block0_changed ? "BLOCK0 WRITTEN!" : "block0 unchanged");
            canvas_draw_str(c, 2, 48, LOG_PATH);
        } else {
            snprintf(buf, sizeof(buf), "Saved %d frames", app->saved_count);
            canvas_draw_str(c, 2, 28, buf);
            canvas_draw_str(c, 2, 40, LOG_PATH);
        }
        canvas_draw_str(c, 2, 62, "OK menu   Back exit");
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
    app->dialogs = furi_record_open(RECORD_DIALOGS);
    app->mfc_src = mf_classic_alloc();
    app->mfc_result = mf_classic_alloc();
    app->frames = malloc(sizeof(Frame) * MAX_FRAMES);
    app->scene = SceneMenu;
    /* sane default card in case read is skipped */
    app->uid_len = 4;
    app->uid[0] = 0x04;
    app->uid[1] = 0xA1;
    app->uid[2] = 0xB2;
    app->uid[3] = 0xC3;
    app->atqa[0] = 0x04;
    app->atqa[1] = 0x00;
    app->sak = 0x08;

    app->gui = furi_record_open(RECORD_GUI);
    app->view_port = view_port_alloc();
    view_port_draw_callback_set(app->view_port, draw_cb, app);
    view_port_input_callback_set(app->view_port, input_cb, app);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);
    return app;
}

static void app_free(App* app) {
    emu_stop(app);
    if(app->mfc_listener) {
        nfc_listener_stop(app->mfc_listener);
        nfc_listener_free(app->mfc_listener);
    }
    mf_classic_free(app->mfc_src);
    mf_classic_free(app->mfc_result);
    furi_record_close(RECORD_DIALOGS);
    nfc_free(app->nfc);
    free(app->frames);
    gui_remove_view_port(app->gui, app->view_port);
    view_port_free(app->view_port);
    furi_record_close(RECORD_GUI);
    furi_message_queue_free(app->event_queue);
    furi_mutex_free(app->mutex);
    free(app);
}

int32_t cloner_sniff_app(void* p) {
    UNUSED(p);
    App* app = app_alloc();

    bool running = true;
    AppEvent event;
    while(running) {
        FuriStatus st = furi_message_queue_get(app->event_queue, &event, 250);

        int action = 0; /* 1 = start emulate */
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        if(st == FuriStatusOk && event.type == EvInput) {
            InputEvent* in = &event.input;
            bool press = (in->type == InputTypeShort);
            switch(app->scene) {
            case SceneMenu:
                if(press && in->key == InputKeyUp)
                    app->menu_index = (app->menu_index + MENU_COUNT - 1) % MENU_COUNT;
                else if(press && in->key == InputKeyDown)
                    app->menu_index = (app->menu_index + 1) % MENU_COUNT;
                else if(press && in->key == InputKeyOk) {
                    app->ack_mode = (app->menu_index == 1);
                    app->raw_mode = (app->menu_index == 2);
                    app->mfc_mode = (app->menu_index == 3);
                    app->scene = SceneBusy;
                    action = app->mfc_mode ? 2 : 1;
                } else if(press && in->key == InputKeyBack)
                    running = false;
                break;
            case SceneEmulate:
                if(press && in->key == InputKeyBack) {
                    if(app->mfc_mode)
                        mfc_emu_stop_and_diff(app);
                    else
                        emu_stop(app);
                    save_log(app);
                    app->scene = SceneSaved;
                }
                break;
            case SceneSaved:
                if(press && in->key == InputKeyOk) {
                    app->frame_count = 0;
                    app->message[0] = '\0';
                    app->scene = SceneMenu;
                } else if(press && in->key == InputKeyBack)
                    running = false;
                break;
            default:
                break;
            }
        }
        furi_mutex_release(app->mutex);

        if(action == 1) {
            view_port_update(app->view_port);
            bool ok = do_read(app);
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            app->frame_count = 0;
            app->field_on = 0;
            app->activated = 0;
            if(!ok) snprintf(app->message, sizeof(app->message), "No card - emul default UID");
            app->scene = SceneEmulate;
            furi_mutex_release(app->mutex);
            emu_start(app);
        } else if(action == 2) {
            /* full Mifare Classic emulation from a saved .nfc */
            bool ok = load_mfc(app);
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            app->auth_events = 0;
            app->auth_rec_count = 0;
            app->changed_blocks = 0;
            app->block0_changed = false;
            app->scene = ok ? SceneEmulate : SceneMenu;
            furi_mutex_release(app->mutex);
            if(ok) mfc_emu_start(app);
        }
        view_port_update(app->view_port);
    }

    app_free(app);
    return 0;
}
