/*
 * HF Card ID — Flipper Zero app  (SwissNFC/RFID toolkit)
 *
 * One-tap identifier for 13.56 MHz cards: names the technology and gives a
 * security-posture verdict + which tool/attack applies.
 *
 * IMPORTANT / honest scope: iCLASS/Picopass is NOT in the Flipper's shared NFC
 * protocol library (neither the SDK nor the core firmware expose it — verified),
 * so no external app can read it. The built-in *Picopass* app carries its own
 * stack. This app therefore identifies every EXPOSED HF protocol and, when none
 * answers, flags "likely iCLASS/Picopass -> use the Picopass app / Proxmark".
 *
 * AUTHORIZED USE ONLY.
 */
#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <storage/storage.h>
#include <nfc/nfc.h>
#include <nfc/nfc_scanner.h>
#include <nfc/nfc_device.h>
#include <nfc/protocols/nfc_protocol.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller_sync.h>

typedef enum {
    SceneIdle,
    SceneBusy,
    SceneResult,
} Scene;

typedef struct {
    InputEvent input;
} AppEvent;

typedef struct {
    Gui* gui;
    ViewPort* vp;
    FuriMessageQueue* q;
    FuriMutex* mutex;
    Nfc* nfc;
    Scene scene;

    bool found;
    char type[24];
    char verdict[16];
    char hint[36];
} App;

/* map a detected protocol (+ optional SAK) to a security verdict and tool hint */
static void classify(App* app, NfcProtocol proto, uint8_t sak, bool have_sak) {
    const char* pn = nfc_device_get_protocol_name(proto);
    snprintf(app->type, sizeof(app->type), "%s", pn ? pn : "HF card");

    switch(proto) {
    case NfcProtocolMfClassic:
        snprintf(app->verdict, sizeof(app->verdict), "BROKEN");
        snprintf(app->hint, sizeof(app->hint), "Crypto1 - Card Audit/MFKey");
        break;
    case NfcProtocolMfUltralight:
        snprintf(app->verdict, sizeof(app->verdict), "CLONE");
        snprintf(app->hint, sizeof(app->hint), "unauth pages - dump/clone");
        break;
    case NfcProtocolMfDesfire:
        snprintf(app->verdict, sizeof(app->verdict), "SECURE*");
        snprintf(app->hint, sizeof(app->hint), "AES; config-audit only");
        break;
    case NfcProtocolMfPlus:
        snprintf(app->verdict, sizeof(app->verdict), "SECURE*");
        snprintf(app->hint, sizeof(app->hint), "AES if SL3; UID if SL1");
        break;
    case NfcProtocolIso14443_4a:
    case NfcProtocolIso14443_4b:
        snprintf(app->verdict, sizeof(app->verdict), "SMARTCARD");
        snprintf(app->hint, sizeof(app->hint), "APDU/ISO7816 - app-specific");
        break;
    case NfcProtocolEmv:
        snprintf(app->verdict, sizeof(app->verdict), "PAYMENT");
        snprintf(app->hint, sizeof(app->hint), "EMV - do NOT clone");
        break;
    case NfcProtocolIso15693_3:
    case NfcProtocolSlix:
    case NfcProtocolSt25tb:
        snprintf(app->verdict, sizeof(app->verdict), "15693");
        snprintf(app->hint, sizeof(app->hint), "vicinity tag (NOT iClass)");
        break;
    case NfcProtocolFelica:
        snprintf(app->verdict, sizeof(app->verdict), "FeliCa");
        snprintf(app->hint, sizeof(app->hint), "transit/secure");
        break;
    case NfcProtocolIso14443_3a:
    case NfcProtocolIso14443_3b:
    default:
        snprintf(app->verdict, sizeof(app->verdict), "CLONE");
        snprintf(app->hint, sizeof(app->hint), "UID-only if reader trusts it");
        break;
    }
    UNUSED(sak);
    UNUSED(have_sak);
}

/* ---- NFC scanner ---- */
typedef struct {
    FuriSemaphore* sem;
    bool done;
    NfcProtocol top;
    size_t count;
} Scan;

static void scanner_cb(NfcScannerEvent event, void* ctx) {
    Scan* r = ctx;
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

static void do_identify(App* app) {
    Scan r = {0};
    r.sem = furi_semaphore_alloc(1, 0);
    NfcScanner* sc = nfc_scanner_alloc(app->nfc);
    nfc_scanner_start(sc, scanner_cb, &r);
    bool ok = (furi_semaphore_acquire(r.sem, furi_ms_to_ticks(2500)) == FuriStatusOk);
    nfc_scanner_stop(sc);
    nfc_scanner_free(sc);
    furi_semaphore_free(r.sem);

    if(ok && r.count > 0) {
        classify(app, r.top, 0, false);
        app->found = true;
    } else {
        app->found = false;
        snprintf(app->type, sizeof(app->type), "no std HF card");
        snprintf(app->verdict, sizeof(app->verdict), "iCLASS?");
        snprintf(app->hint, sizeof(app->hint), "if present: use Picopass");
    }

    /* report */
    Storage* st = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(st);
    if(storage_file_open(f, "/ext/hf_card_id.txt", FSAM_WRITE, FSOM_OPEN_APPEND)) {
        char line[96];
        int n = snprintf(
            line, sizeof(line), "%s | %s | %s\n", app->type, app->verdict, app->hint);
        storage_file_write(f, line, n);
    }
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->scene = SceneResult;
    furi_mutex_release(app->mutex);
}

/* ---- GUI ---- */
static void draw_cb(Canvas* c, void* ctx) {
    App* app = ctx;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    canvas_clear(c);
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 11, "HF Card ID");
    canvas_set_font(c, FontSecondary);
    if(app->scene == SceneIdle) {
        canvas_draw_str(c, 2, 28, "Hold an HF card,");
        canvas_draw_str(c, 2, 40, "press OK to identify.");
        canvas_draw_str(c, 2, 62, "OK id     Back exit");
    } else if(app->scene == SceneBusy) {
        canvas_draw_str(c, 2, 34, "Identifying...");
    } else { /* SceneResult */
        canvas_draw_str(c, 2, 24, app->type);
        canvas_set_font(c, FontPrimary);
        canvas_draw_box(c, 0, 30, 128, 13);
        canvas_set_color(c, ColorWhite);
        canvas_draw_str(c, 3, 40, app->verdict);
        canvas_set_color(c, ColorBlack);
        canvas_set_font(c, FontSecondary);
        canvas_draw_str(c, 2, 54, app->hint);
        canvas_draw_str(c, 2, 63, "OK again  Back exit");
    }
    furi_mutex_release(app->mutex);
}

static void input_cb(InputEvent* e, void* ctx) {
    App* app = ctx;
    AppEvent ev = {.input = *e};
    furi_message_queue_put(app->q, &ev, FuriWaitForever);
}

int32_t nfc_id_app(void* p) {
    UNUSED(p);
    App* app = malloc(sizeof(App));
    memset(app, 0, sizeof(App));
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->q = furi_message_queue_alloc(8, sizeof(AppEvent));
    app->nfc = nfc_alloc();
    app->scene = SceneIdle;
    app->gui = furi_record_open(RECORD_GUI);
    app->vp = view_port_alloc();
    view_port_draw_callback_set(app->vp, draw_cb, app);
    view_port_input_callback_set(app->vp, input_cb, app);
    gui_add_view_port(app->gui, app->vp, GuiLayerFullscreen);

    bool running = true;
    AppEvent ev;
    while(running) {
        if(furi_message_queue_get(app->q, &ev, FuriWaitForever) != FuriStatusOk) continue;
        bool go = false;
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        if(ev.input.type == InputTypeShort) {
            if(ev.input.key == InputKeyOk && app->scene != SceneBusy) {
                app->scene = SceneBusy;
                go = true;
            } else if(ev.input.key == InputKeyBack) {
                running = false;
            }
        }
        furi_mutex_release(app->mutex);
        if(go) {
            view_port_update(app->vp);
            do_identify(app);
        }
        view_port_update(app->vp);
    }

    nfc_free(app->nfc);
    gui_remove_view_port(app->gui, app->vp);
    view_port_free(app->vp);
    furi_record_close(RECORD_GUI);
    furi_message_queue_free(app->q);
    furi_mutex_free(app->mutex);
    free(app);
    return 0;
}
