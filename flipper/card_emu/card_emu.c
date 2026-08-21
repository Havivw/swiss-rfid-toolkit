/*
 * Card Emulator — Flipper Zero app  (SwissNFC/RFID toolkit)
 *
 * The "one device" wallet: pick a saved .nfc and the Flipper BECOMES that card.
 * It emulates whatever protocol the file holds — full Mifare Classic (UID + all
 * sectors + keys, so it passes reader auth), plain ISO14443-A UID, or Ultralight/
 * NTAG. For cards that can't be cloned onto a blank (proprietary magic), this is
 * the answer: the Flipper replaces the card directly.
 *
 * AUTHORIZED USE ONLY — emulate only cards you own or are permitted to use.
 */
#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <dialogs/dialogs.h>
#include <nfc/nfc.h>
#include <nfc/nfc_device.h>
#include <nfc/nfc_listener.h>
#include <nfc/protocols/nfc_protocol.h>

#define NFC_DIR "/ext/nfc"

typedef enum {
    SceneIdle,
    SceneEmulate,
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
    DialogsApp* dialogs;
    NfcDevice* dev;
    NfcListener* listener;

    Scene scene;
    bool emulating;
    char name[32];
    char proto[24];
    int reads; /* reader-activity counter */
} App;

static NfcCommand listener_cb(NfcGenericEvent event, void* ctx) {
    UNUSED(event);
    App* app = ctx;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->reads++;
    furi_mutex_release(app->mutex);
    AppEvent e = {0};
    furi_message_queue_put(app->q, &e, 0);
    return NfcCommandContinue;
}

static void emu_stop(App* app) {
    if(app->listener) {
        nfc_listener_stop(app->listener);
        nfc_listener_free(app->listener);
        app->listener = NULL;
    }
    app->emulating = false;
}

/* pick a .nfc, load it, and start emulating whatever protocol it holds */
static bool start_emulate(App* app) {
    FuriString* path = furi_string_alloc();
    furi_string_set(path, NFC_DIR);
    DialogsFileBrowserOptions opts;
    dialog_file_browser_set_basic_options(&opts, ".nfc", NULL);
    opts.base_path = NFC_DIR;
    bool ok = false;
    if(dialog_file_browser_show(app->dialogs, path, path, &opts)) {
        if(nfc_device_load(app->dev, furi_string_get_cstr(path))) {
            NfcProtocol proto = nfc_device_get_protocol(app->dev);
            const NfcDeviceData* data = nfc_device_get_data(app->dev, proto);
            /* basename for display */
            const char* full = furi_string_get_cstr(path);
            const char* base = strrchr(full, '/');
            base = base ? base + 1 : full;
            snprintf(app->name, sizeof(app->name), "%s", base);
            snprintf(app->proto, sizeof(app->proto), "%s", nfc_device_get_name(app->dev, NfcDeviceNameTypeFull));
            app->listener = nfc_listener_alloc(app->nfc, proto, data);
            nfc_listener_start(app->listener, listener_cb, app);
            app->emulating = true;
            app->reads = 0;
            ok = true;
        } else {
            snprintf(app->name, sizeof(app->name), "load failed");
        }
    }
    furi_string_free(path);
    return ok;
}

static void draw_cb(Canvas* c, void* ctx) {
    App* app = ctx;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    canvas_clear(c);
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 11, "Card Emulator");
    canvas_set_font(c, FontSecondary);
    if(app->scene == SceneIdle) {
        canvas_draw_str(c, 2, 28, "Be a saved card:");
        canvas_draw_str(c, 2, 40, "OK = pick .nfc & emulate");
        canvas_draw_str(c, 2, 62, "OK pick   Back exit");
    } else { /* SceneEmulate */
        char buf[40];
        canvas_draw_str(c, 2, 24, app->name);
        canvas_draw_str(c, 2, 36, app->proto);
        snprintf(buf, sizeof(buf), "EMULATING  reads:%d", app->reads);
        canvas_draw_str(c, 2, 50, buf);
        canvas_draw_str(c, 2, 62, "Back: stop");
    }
    furi_mutex_release(app->mutex);
}

static void input_cb(InputEvent* e, void* ctx) {
    App* app = ctx;
    AppEvent ev = {.input = *e};
    furi_message_queue_put(app->q, &ev, FuriWaitForever);
}

int32_t card_emu_app(void* p) {
    UNUSED(p);
    App* app = malloc(sizeof(App));
    memset(app, 0, sizeof(App));
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->q = furi_message_queue_alloc(16, sizeof(AppEvent));
    app->nfc = nfc_alloc();
    app->dev = nfc_device_alloc();
    app->dialogs = furi_record_open(RECORD_DIALOGS);
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
            if(ev.input.key == InputKeyOk && app->scene == SceneIdle) {
                go = true;
            } else if(ev.input.key == InputKeyBack) {
                if(app->scene == SceneEmulate) {
                    emu_stop(app);
                    app->scene = SceneIdle;
                } else {
                    running = false;
                }
            }
        }
        furi_mutex_release(app->mutex);

        if(go) {
            bool ok = start_emulate(app);
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            app->scene = ok ? SceneEmulate : SceneIdle;
            furi_mutex_release(app->mutex);
        }
        view_port_update(app->vp);
    }

    emu_stop(app);
    nfc_device_free(app->dev);
    nfc_free(app->nfc);
    furi_record_close(RECORD_DIALOGS);
    gui_remove_view_port(app->gui, app->vp);
    view_port_free(app->vp);
    furi_record_close(RECORD_GUI);
    furi_message_queue_free(app->q);
    furi_mutex_free(app->mutex);
    free(app);
    return 0;
}
