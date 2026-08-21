/*
 * Clone Writer — Flipper Zero app  (SwissNFC/RFID toolkit)
 *
 * Clones a Mifare Classic onto a MAGIC blank. The source dump comes from either:
 *   - a saved .nfc file (e.g. a CLONE_*.nfc made by Card Audit), or
 *   - reading a live card here (default-key dictionary dump).
 * Each sector is then written onto the target with the target's DEFAULT key
 * (FFFFFFFFFFFF, the state of a fresh magic blank); block 0 (UID) writes only on
 * gen2/CUID targets. Write auth is retried across key A / key B / the dump's own
 * keys so sector trailers (which often need key B) still take.
 *
 * AUTHORIZED USE ONLY. This OVERWRITES the target card. Only clone cards you own
 * or are permitted to duplicate. gen1a UID write is NOT done here (use stock NFC).
 */
#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <storage/storage.h>
#include <dialogs/dialogs.h>
#include <nfc/nfc.h>
#include <nfc/nfc_device.h>
#include <nfc/protocols/nfc_protocol.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller_sync.h>
#include <nfc/protocols/mf_classic/mf_classic.h>
#include <nfc/protocols/mf_classic/mf_classic_poller_sync.h>

#define NFC_DIR "/ext/nfc"

typedef enum {
    SceneMenu, /* choose source: saved / read */
    SceneReadPrompt, /* "present SOURCE card" */
    SceneBusy,
    SceneReady, /* source held; "present TARGET, OK to WRITE" */
    SceneResult,
} Scene;

typedef enum {
    EvInput,
} AppEventType;

typedef struct {
    AppEventType type;
    InputEvent input;
} AppEvent;

typedef struct {
    Gui* gui;
    ViewPort* view_port;
    DialogsApp* dialogs;
    FuriMessageQueue* event_queue;
    FuriMutex* mutex;
    Nfc* nfc;

    Scene scene;
    int menu_index;

    MfClassicData* src; /* the dump to write */
    bool have_src;
    char src_desc[28];

    /* write results */
    int wrote;
    int failed;
    int skipped;
    bool uid_ok;
    char note[28];
} App;

static const uint8_t DEFAULT_KEYS[][6] = {
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, /* factory default */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, /* all-zero / blank */
    {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}, /* MAD / infrastructure */
    {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7}, /* NDEF public */
    {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5},
    {0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD}, /* MAD key A */
    {0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A}, /* MAD key B */
    {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    {0x71, 0x4C, 0x5C, 0x88, 0x6E, 0x97},
    {0x58, 0x7E, 0xE5, 0xF9, 0x35, 0x0F},
    {0xA0, 0x47, 0x8C, 0xC3, 0x90, 0x91},
    {0x53, 0x3C, 0xB6, 0xC7, 0x23, 0xF6},
    {0x8F, 0xD0, 0xA4, 0xF2, 0x56, 0xE9},
    {0xFC, 0x00, 0x01, 0x87, 0x78, 0xF7},
    {0x64, 0x71, 0xA5, 0xEF, 0x2D, 0x1A},
    {0x5C, 0x8F, 0xF9, 0x99, 0x0D, 0xA2},
    {0xD0, 0x1A, 0xFE, 0xEB, 0x89, 0x0A},
    {0x75, 0xCC, 0xB5, 0x9C, 0x9B, 0xED},
    {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5},
    {0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5},
    {0xA1, 0xB1, 0xC1, 0xD1, 0xE1, 0xF1},
    {0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
    {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
    {0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
    {0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
    {0x33, 0x33, 0x33, 0x33, 0x33, 0x33},
    {0x44, 0x44, 0x44, 0x44, 0x44, 0x44},
    {0x55, 0x55, 0x55, 0x55, 0x55, 0x55},
    {0x66, 0x66, 0x66, 0x66, 0x66, 0x66},
    {0x77, 0x77, 0x77, 0x77, 0x77, 0x77},
    {0x88, 0x88, 0x88, 0x88, 0x88, 0x88},
    {0x99, 0x99, 0x99, 0x99, 0x99, 0x99},
    {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
    {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB},
    {0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC},
    {0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD},
    {0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
};
#define N_DEFAULT_KEYS ((int)(sizeof(DEFAULT_KEYS) / sizeof(DEFAULT_KEYS[0])))

static const char* const kMenu[] = {"Read source card", "From saved .nfc"};
#define MENU_COUNT ((int)(sizeof(kMenu) / sizeof(kMenu[0])))

/* ---------------- source acquisition ---------------- */

/* Load a saved .nfc into app->src. Returns true if it held a Mifare Classic. */
static bool load_saved(App* app) {
    FuriString* path = furi_string_alloc();
    furi_string_set(path, NFC_DIR);
    DialogsFileBrowserOptions opts;
    dialog_file_browser_set_basic_options(&opts, ".nfc", NULL);
    opts.base_path = NFC_DIR;
    bool picked = dialog_file_browser_show(app->dialogs, path, path, &opts);
    bool ok = false;
    if(picked) {
        NfcDevice* dev = nfc_device_alloc();
        if(!nfc_device_load(dev, furi_string_get_cstr(path))) {
            snprintf(app->note, sizeof(app->note), "load failed");
        } else if(nfc_device_get_protocol(dev) != NfcProtocolMfClassic) {
            snprintf(app->note, sizeof(app->note), "not Mifare Classic");
        } else {
            const MfClassicData* d =
                (const MfClassicData*)nfc_device_get_data(dev, NfcProtocolMfClassic);
            mf_classic_copy(app->src, d);
            uint8_t sr = 0, kf = 0;
            mf_classic_get_read_sectors_and_keys(app->src, &sr, &kf);
            uint8_t total = mf_classic_get_total_sectors_num(app->src->type);
            snprintf(app->src_desc, sizeof(app->src_desc), "saved %u/%u sec", sr, total);
            ok = true;
        }
        nfc_device_free(dev);
    }
    furi_string_free(path);
    return ok;
}

/* Read a live Classic with the default-key dictionary into app->src. */
static bool read_source(App* app) {
    Iso14443_3aData* d3 = iso14443_3a_alloc();
    Iso14443_3aError err = iso14443_3a_poller_sync_read(app->nfc, d3);
    uint8_t sak = (err == Iso14443_3aErrorNone) ? d3->sak : 0xFF;
    iso14443_3a_free(d3);
    if(err != Iso14443_3aErrorNone) {
        snprintf(app->note, sizeof(app->note), "no card");
        return false;
    }
    if(!(sak == 0x08 || sak == 0x18 || sak == 0x09)) {
        snprintf(app->note, sizeof(app->note), "not MF Classic");
        return false;
    }
    MfClassicType mtype = (sak == 0x18) ? MfClassicType4k :
                          (sak == 0x09) ? MfClassicTypeMini :
                                          MfClassicType1k;
    uint8_t sectors = mf_classic_get_total_sectors_num(mtype);

    /* recover a key per sector from the top-10 default dictionary */
    MfClassicDeviceKeys keys;
    memset(&keys, 0, sizeof(keys));
    for(uint8_t s = 0; s < sectors; s++) {
        uint8_t blk = mf_classic_get_first_block_num_of_sector(s);
        for(int i = 0; i < N_DEFAULT_KEYS; i++) {
            MfClassicKey k;
            memcpy(k.data, DEFAULT_KEYS[i], 6);
            MfClassicAuthContext ctx;
            if(!(keys.key_a_mask & (1ULL << s)) &&
               mf_classic_poller_sync_auth(app->nfc, blk, &k, MfClassicKeyTypeA, &ctx) ==
                   MfClassicErrorNone) {
                keys.key_a[s] = k;
                keys.key_a_mask |= (1ULL << s);
            }
            if(!(keys.key_b_mask & (1ULL << s)) &&
               mf_classic_poller_sync_auth(app->nfc, blk, &k, MfClassicKeyTypeB, &ctx) ==
                   MfClassicErrorNone) {
                keys.key_b[s] = k;
                keys.key_b_mask |= (1ULL << s);
            }
            if((keys.key_a_mask & (1ULL << s)) && (keys.key_b_mask & (1ULL << s))) break;
        }
    }

    mf_classic_poller_sync_read(app->nfc, &keys, app->src);
    uint8_t sr = 0, kf = 0;
    mf_classic_get_read_sectors_and_keys(app->src, &sr, &kf);
    if(sr == 0) {
        snprintf(app->note, sizeof(app->note), "no default keys");
        return false;
    }
    snprintf(app->src_desc, sizeof(app->src_desc), "read %u/%u sec", sr, sectors);
    return true;
}

/* ---------------- write to target ---------------- */

static void do_write(App* app) {
    const MfClassicData* d = app->src;
    int wrote = 0, failed = 0, skipped = 0;
    bool uid_ok = false;
    uint8_t sectors = mf_classic_get_total_sectors_num(d->type);
    MfClassicKey ff, zero;
    memset(ff.data, 0xFF, sizeof(ff.data));
    memset(zero.data, 0x00, sizeof(zero.data));

    for(uint8_t s = 0; s < sectors; s++) {
        if(!mf_classic_is_sector_read(d, s)) {
            skipped++;
            continue;
        }
        uint8_t first = mf_classic_get_first_block_num_of_sector(s);
        uint8_t nb = mf_classic_get_blocks_num_in_sector(s);
        const MfClassicSectorTrailer* st = mf_classic_get_sector_trailer_by_sector(d, s);
        for(uint8_t b = 0; b < nb; b++) {
            uint8_t bn = first + b;
            MfClassicBlock blk = d->block[bn];
            bool ok = false;
            /* try target default (A, then B — trailers often need B), then the
             * dump's own keys (target may already hold them), then 0s */
            if(mf_classic_poller_sync_write_block(app->nfc, bn, &ff, MfClassicKeyTypeA, &blk) ==
               MfClassicErrorNone)
                ok = true;
            else if(
                mf_classic_poller_sync_write_block(app->nfc, bn, &ff, MfClassicKeyTypeB, &blk) ==
                MfClassicErrorNone)
                ok = true;
            else if(
                mf_classic_poller_sync_write_block(
                    app->nfc, bn, (MfClassicKey*)&st->key_a, MfClassicKeyTypeA, &blk) ==
                MfClassicErrorNone)
                ok = true;
            else if(
                mf_classic_poller_sync_write_block(
                    app->nfc, bn, (MfClassicKey*)&st->key_b, MfClassicKeyTypeB, &blk) ==
                MfClassicErrorNone)
                ok = true;
            else if(
                mf_classic_poller_sync_write_block(app->nfc, bn, &zero, MfClassicKeyTypeA, &blk) ==
                MfClassicErrorNone)
                ok = true;

            if(ok) {
                wrote++;
                if(bn == 0) uid_ok = true;
            } else {
                failed++;
            }
        }
    }

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->wrote = wrote;
    app->failed = failed;
    app->skipped = skipped;
    app->uid_ok = uid_ok;
    if(wrote == 0)
        snprintf(app->note, sizeof(app->note), "no card / wrong keys");
    else if(uid_ok)
        snprintf(app->note, sizeof(app->note), "UID cloned (gen2)");
    else
        snprintf(app->note, sizeof(app->note), "UID unchanged-not gen2");
    app->scene = SceneResult;
    furi_mutex_release(app->mutex);
}

/* -------------------------- GUI -------------------------- */

static void draw_cb(Canvas* c, void* ctx) {
    App* app = ctx;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    canvas_clear(c);
    canvas_set_color(c, ColorBlack);
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 11, "Clone Writer");
    canvas_set_font(c, FontSecondary);

    if(app->scene == SceneMenu) {
        for(int i = 0; i < MENU_COUNT; i++) {
            int y = 26 + i * 12;
            if(app->menu_index == i) {
                canvas_draw_box(c, 0, y - 9, 128, 11);
                canvas_set_color(c, ColorWhite);
                canvas_draw_str(c, 4, y, kMenu[i]);
                canvas_set_color(c, ColorBlack);
            } else {
                canvas_draw_str(c, 4, y, kMenu[i]);
            }
        }
        canvas_draw_str(c, 2, 62, "OVERWRITES target-auth!");
    } else if(app->scene == SceneReadPrompt) {
        canvas_draw_str(c, 2, 28, "Present SOURCE card");
        canvas_draw_str(c, 2, 40, "to copy FROM.");
        canvas_draw_str(c, 2, 62, "OK read   Back menu");
    } else if(app->scene == SceneBusy) {
        canvas_draw_str(c, 2, 32, "Working - keep still");
        canvas_draw_str(c, 2, 44, "read/write...");
    } else if(app->scene == SceneReady) {
        canvas_draw_str(c, 2, 24, app->src_desc);
        canvas_draw_str(c, 2, 36, "Present TARGET blank");
        canvas_draw_str(c, 2, 48, "OK = WRITE (overwrite)");
        canvas_draw_str(c, 2, 62, "Back cancel");
    } else { /* SceneResult */
        char buf[32];
        canvas_set_font(c, FontPrimary);
        canvas_draw_box(c, 0, 15, 128, 13);
        canvas_set_color(c, ColorWhite);
        canvas_draw_str(
            c, 2, 25, (app->wrote > 0 && app->failed == 0) ? "CLONE WRITTEN" : "write issues");
        canvas_set_color(c, ColorBlack);
        canvas_set_font(c, FontSecondary);
        snprintf(buf, sizeof(buf), "wrote %d fail %d skip %d", app->wrote, app->failed, app->skipped);
        canvas_draw_str(c, 2, 40, buf);
        canvas_draw_str(c, 2, 51, app->note);
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
    app->event_queue = furi_message_queue_alloc(8, sizeof(AppEvent));
    app->nfc = nfc_alloc();
    app->src = mf_classic_alloc();
    app->scene = SceneMenu;

    app->dialogs = furi_record_open(RECORD_DIALOGS);
    app->gui = furi_record_open(RECORD_GUI);
    app->view_port = view_port_alloc();
    view_port_draw_callback_set(app->view_port, draw_cb, app);
    view_port_input_callback_set(app->view_port, input_cb, app);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);
    return app;
}

static void app_free(App* app) {
    mf_classic_free(app->src);
    nfc_free(app->nfc);
    gui_remove_view_port(app->gui, app->view_port);
    view_port_free(app->view_port);
    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_DIALOGS);
    furi_message_queue_free(app->event_queue);
    furi_mutex_free(app->mutex);
    free(app);
}

int32_t clone_writer_app(void* p) {
    UNUSED(p);
    App* app = app_alloc();

    bool running = true;
    AppEvent event;
    while(running) {
        if(furi_message_queue_get(app->event_queue, &event, FuriWaitForever) != FuriStatusOk)
            continue;

        int action = 0; /* 1=load saved, 3=read source, 4=write */
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        if(event.type == EvInput) {
            InputEvent* in = &event.input;
            bool press = (in->type == InputTypeShort);
            switch(app->scene) {
            case SceneMenu:
                if(press && in->key == InputKeyUp)
                    app->menu_index = (app->menu_index + MENU_COUNT - 1) % MENU_COUNT;
                else if(press && in->key == InputKeyDown)
                    app->menu_index = (app->menu_index + 1) % MENU_COUNT;
                else if(press && in->key == InputKeyOk) {
                    if(app->menu_index == 0) { /* read source card */
                        app->scene = SceneReadPrompt;
                    } else { /* from saved .nfc */
                        app->scene = SceneBusy;
                        action = 1;
                    }
                } else if(press && in->key == InputKeyBack)
                    running = false;
                break;
            case SceneReadPrompt:
                if(press && in->key == InputKeyOk) {
                    app->scene = SceneBusy;
                    action = 3;
                } else if(press && in->key == InputKeyBack)
                    app->scene = SceneMenu;
                break;
            case SceneReady:
                if(press && in->key == InputKeyOk) {
                    app->scene = SceneBusy;
                    action = 4;
                } else if(press && in->key == InputKeyBack)
                    app->scene = SceneMenu;
                break;
            case SceneResult:
                if(press && in->key == InputKeyOk)
                    app->scene = SceneMenu;
                else if(press && in->key == InputKeyBack)
                    running = false;
                break;
            default:
                break;
            }
        }
        furi_mutex_release(app->mutex);

        if(action == 1) {
            view_port_update(app->view_port);
            bool ok = load_saved(app);
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            app->have_src = ok;
            app->scene = ok ? SceneReady : (app->note[0] ? SceneResult : SceneMenu);
            if(!ok && app->scene == SceneResult) app->wrote = app->failed = app->skipped = 0;
            furi_mutex_release(app->mutex);
        } else if(action == 3) {
            view_port_update(app->view_port);
            bool ok = read_source(app);
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            app->have_src = ok;
            if(ok) {
                app->scene = SceneReady;
            } else {
                app->wrote = app->failed = app->skipped = 0;
                app->scene = SceneResult;
            }
            furi_mutex_release(app->mutex);
        } else if(action == 4) {
            view_port_update(app->view_port);
            do_write(app);
        }
        view_port_update(app->view_port);
    }

    app_free(app);
    return 0;
}
