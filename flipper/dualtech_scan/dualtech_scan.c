/*
 * Dual-Tech Scan — Flipper Zero app
 *
 * Reads a single card on BOTH bands — 125 kHz LF (lfrfid) and 13.56 MHz HF
 * (ISO14443-A) — and reports whether it answers on both. A card that responds
 * on both is a COMBO / dual-technology credential (e.g. HID Prox + iCLASS/Mifare).
 * These are the ones abused by weak "OR" reader logic: clone the trivially-
 * cloneable LF side and get in even though the deployment believes it requires
 * the secure HF side.
 *
 * BLIND SPOT: HID's HF side is usually iCLASS/Picopass, which is NOT ISO14443-A,
 * so this scan won't see it (shows HF=none). Absence of HF here does NOT prove
 * single-tech — only that there's no ISO14443-A HF. (Mifare/DESFire HF is seen.)
 */
#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <lfrfid/lfrfid_worker.h>
#include <lfrfid/protocols/lfrfid_protocols.h>
#include <toolbox/protocols/protocol_dict.h>
#include <nfc/nfc.h>
#include <nfc/nfc_scanner.h>
#include <nfc/nfc_device.h>
#include <nfc/protocols/nfc_protocol.h>

typedef enum {
    SceneIdle,
    SceneScanning,
    SceneResult,
} Scene;

typedef enum {
    EvInput,
    EvScanDone,
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

    ProtocolDict* dict;
    LFRFIDWorker* lf_worker;
    Nfc* nfc;

    Scene scene;
    bool lf_found;
    bool hf_found;
    char lf_result[28];
    char hf_result[28];
} App;

/* -------------------------- LF scan (lfrfid worker + timeout) ------------- */

typedef struct {
    FuriSemaphore* sem;
    bool ok;
    size_t proto;
    uint8_t data[16];
    size_t dsize;
    ProtocolDict* dict;
} LfProbe;

static void lf_read_cb(LFRFIDWorkerReadResult result, ProtocolId protocol, void* ctx) {
    LfProbe* p = ctx;
    if(result == LFRFIDWorkerReadDone && !p->ok) {
        p->proto = (size_t)protocol;
        p->dsize = protocol_dict_get_data_size(p->dict, p->proto);
        if(p->dsize > sizeof(p->data)) p->dsize = sizeof(p->data);
        protocol_dict_get_data(p->dict, p->proto, p->data, p->dsize);
        p->ok = true;
        furi_semaphore_release(p->sem);
    }
}

static void lf_scan(App* app) {
    LfProbe p = {0};
    p.sem = furi_semaphore_alloc(1, 0);
    p.dict = app->dict;

    lfrfid_worker_start_thread(app->lf_worker);
    lfrfid_worker_read_start(app->lf_worker, LFRFIDWorkerReadTypeAuto, lf_read_cb, &p);
    bool ok = (furi_semaphore_acquire(p.sem, furi_ms_to_ticks(2500)) == FuriStatusOk);
    lfrfid_worker_stop(app->lf_worker);
    lfrfid_worker_stop_thread(app->lf_worker);
    furi_semaphore_free(p.sem);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    if(ok && p.ok) {
        const char* name = protocol_dict_get_name(app->dict, p.proto);
        char hex[20] = {0};
        int hp = 0;
        for(size_t i = 0; i < p.dsize && hp < (int)sizeof(hex) - 2; i++)
            hp += snprintf(hex + hp, sizeof(hex) - hp, "%02X", p.data[i]);
        snprintf(app->lf_result, sizeof(app->lf_result), "%s %s", name ? name : "?", hex);
        app->lf_found = true;
    } else {
        snprintf(app->lf_result, sizeof(app->lf_result), "none");
        app->lf_found = false;
    }
    furi_mutex_release(app->mutex);
}

/* -------------------------- HF scan (ISO14443-3A sync read) --------------- */

/* Broad HF detection via the NFC scanner — catches every HF protocol the
 * Flipper core supports (ISO14443-A/B, ISO15693/SLIX, FeliCa, Mifare...).
 * NOTE: iCLASS/Picopass is NOT covered — its stack is not exposed to apps. */
typedef struct {
    FuriSemaphore* sem;
    bool done;
    NfcProtocol top;
    size_t count;
} HfScan;

static void scanner_cb(NfcScannerEvent event, void* ctx) {
    HfScan* r = ctx;
    if(event.type == NfcScannerEventTypeDetected && !r->done) {
        r->count = event.data.protocol_num;
        if(r->count > 0) {
            r->top = event.data.protocols[0];
            for(size_t i = 1; i < r->count; i++) /* highest enum = most specific */
                if(event.data.protocols[i] > r->top) r->top = event.data.protocols[i];
        }
        r->done = true;
        furi_semaphore_release(r->sem);
    }
}

static void hf_scan(App* app) {
    HfScan r = {0};
    r.sem = furi_semaphore_alloc(1, 0);
    NfcScanner* sc = nfc_scanner_alloc(app->nfc);
    nfc_scanner_start(sc, scanner_cb, &r);
    bool ok = (furi_semaphore_acquire(r.sem, furi_ms_to_ticks(2500)) == FuriStatusOk);
    nfc_scanner_stop(sc);
    nfc_scanner_free(sc);
    furi_semaphore_free(r.sem);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    if(ok && r.count > 0) {
        const char* pn = nfc_device_get_protocol_name(r.top);
        snprintf(app->hf_result, sizeof(app->hf_result), "%s", pn ? pn : "?");
        app->hf_found = true;
    } else {
        snprintf(app->hf_result, sizeof(app->hf_result), "none");
        app->hf_found = false;
    }
    furi_mutex_release(app->mutex);
}

/* -------------------------- GUI -------------------------- */

static void draw_cb(Canvas* c, void* ctx) {
    App* app = ctx;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    canvas_clear(c);
    canvas_set_color(c, ColorBlack);
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 11, "Dual-Tech Scan");
    canvas_set_font(c, FontSecondary);

    if(app->scene == SceneIdle) {
        canvas_draw_str(c, 2, 28, "Hold ONE card to the");
        canvas_draw_str(c, 2, 38, "then press OK");
        canvas_draw_str(c, 2, 62, "OK scan   Back exit");
    } else if(app->scene == SceneScanning) {
        canvas_draw_str(c, 2, 32, "Scanning LF+HF...");
        canvas_draw_str(c, 2, 44, "keep card still");
    } else { /* SceneResult */
        char buf[36];
        snprintf(buf, sizeof(buf), "LF: %s", app->lf_result);
        canvas_draw_str(c, 2, 24, buf);
        snprintf(buf, sizeof(buf), "HF: %s", app->hf_result);
        canvas_draw_str(c, 2, 34, buf);

        canvas_set_font(c, FontPrimary);
        if(app->lf_found && app->hf_found) {
            canvas_draw_box(c, 0, 40, 128, 12);
            canvas_set_color(c, ColorWhite);
            canvas_draw_str(c, 2, 50, "DUAL-TECH combo!");
            canvas_set_color(c, ColorBlack);
        } else if(app->lf_found) {
            canvas_draw_str(c, 2, 50, "LF only");
        } else if(app->hf_found) {
            canvas_draw_str(c, 2, 50, "HF only");
        } else {
            canvas_draw_str(c, 2, 50, "no card seen");
        }
        canvas_set_font(c, FontSecondary);
        /* LF present but no ISO14443/15693 HF -> HF is likely iCLASS/Picopass,
         * which this tool can't see (use the stock Picopass app). */
        if(app->lf_found && !app->hf_found)
            canvas_draw_str(c, 2, 62, "iCLASS? HF Card ID/Picopass");
        else
            canvas_draw_str(c, 2, 62, "OK rescan  Back menu");
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
    app->dict = protocol_dict_alloc(lfrfid_protocols, LFRFIDProtocolMax);
    app->lf_worker = lfrfid_worker_alloc(app->dict);
    app->nfc = nfc_alloc();
    app->scene = SceneIdle;

    app->gui = furi_record_open(RECORD_GUI);
    app->view_port = view_port_alloc();
    view_port_draw_callback_set(app->view_port, draw_cb, app);
    view_port_input_callback_set(app->view_port, input_cb, app);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);
    return app;
}

static void app_free(App* app) {
    lfrfid_worker_free(app->lf_worker);
    protocol_dict_free(app->dict);
    nfc_free(app->nfc);
    gui_remove_view_port(app->gui, app->view_port);
    view_port_free(app->view_port);
    furi_record_close(RECORD_GUI);
    furi_message_queue_free(app->event_queue);
    furi_mutex_free(app->mutex);
    free(app);
}

int32_t dualtech_scan_app(void* p) {
    UNUSED(p);
    App* app = app_alloc();

    bool running = true;
    AppEvent event;
    while(running) {
        if(furi_message_queue_get(app->event_queue, &event, FuriWaitForever) != FuriStatusOk)
            continue;

        bool a_scan = false;
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        if(event.type == EvInput) {
            InputEvent* in = &event.input;
            bool press = (in->type == InputTypeShort);
            if(press && in->key == InputKeyOk) {
                if(app->scene == SceneResult) {
                    app->scene = SceneScanning;
                    a_scan = true;
                } else if(app->scene == SceneIdle) {
                    app->scene = SceneScanning;
                    a_scan = true;
                }
            } else if(press && in->key == InputKeyBack) {
                if(app->scene == SceneResult) {
                    app->scene = SceneIdle;
                } else {
                    running = false;
                }
            }
        }
        furi_mutex_release(app->mutex);

        if(a_scan) {
            view_port_update(app->view_port); /* show "Scanning..." */
            lf_scan(app); /* LF first (has a 2.5s timeout) */
            hf_scan(app); /* then HF */
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            app->scene = SceneResult;
            furi_mutex_release(app->mutex);
        }

        view_port_update(app->view_port);
    }

    app_free(app);
    return 0;
}
