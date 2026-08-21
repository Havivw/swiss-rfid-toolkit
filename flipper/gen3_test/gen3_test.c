/*
 * Gen3 Probe — Flipper Zero app  (SwissNFC/RFID toolkit)
 *
 * Non-destructively tests whether a Mifare Classic is a Gen3 (APDU) magic card.
 * Gen3 changes its UID via UNauthenticated raw commands sent right after select:
 *   90 F0 CC CC 10 <16-byte block0>   -> write block 0 (UID/BCC/SAK/ATQA)
 *   90 FB CC CC 07 <7-byte uid>       -> write UID only
 *   90 FD 11 11 00                    -> PERMANENT lock  (NEVER sent by this app)
 *
 * We read block 0 (auth default FF), then send 90F0CCCC10 with the SAME block 0
 * back — if the card accepts it, it's Gen3, and the write is a no-op (safe).
 * A normal Classic just NAKs the 0x90 command.
 *
 * AUTHORIZED USE ONLY.
 */
#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <storage/storage.h>
#include <nfc/nfc.h>
#include <nfc/nfc_poller.h>
#include <nfc/protocols/nfc_protocol.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller.h>
#include <nfc/protocols/mf_classic/mf_classic.h>
#include <nfc/protocols/mf_classic/mf_classic_poller_sync.h>
#include <toolbox/bit_buffer.h>

#define TAG "GEN3"

typedef enum { SceneIdle, SceneBusy, SceneResult } Scene;
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

    /* block0 to (re)write */
    uint8_t b0[16];
    bool have_b0;
    /* probe results */
    int rd_err; /* MfClassicError of block0 read */
    int tx_err; /* Iso14443_3aError of the gen3 frame */
    int rx_len;
    uint8_t rx[16];
    char note[40];
} App;

/* ---- gen3 raw command via a fresh iso14443_3a poller (no auth) ---- */
typedef struct {
    FuriSemaphore* sem;
    bool done;
    const uint8_t* b0;
    int tx_err;
    int rx_len;
    uint8_t rx[16];
} Gen3Ctx;

static NfcCommand gen3_cb(NfcGenericEvent event, void* ctx) {
    Gen3Ctx* g = ctx;
    if(g->done) return NfcCommandStop;
    Iso14443_3aPoller* poller = (Iso14443_3aPoller*)event.instance;
    Iso14443_3aPollerEvent* ev = (Iso14443_3aPollerEvent*)event.event_data;
    if(ev && ev->type == Iso14443_3aPollerEventTypeReady) {
        BitBuffer* tx = bit_buffer_alloc(32);
        BitBuffer* rx = bit_buffer_alloc(32);
        /* 90 F0 CC CC 10 <16 bytes block0> ; send_standard_frame appends CRC */
        bit_buffer_append_byte(tx, 0x90);
        bit_buffer_append_byte(tx, 0xF0);
        bit_buffer_append_byte(tx, 0xCC);
        bit_buffer_append_byte(tx, 0xCC);
        bit_buffer_append_byte(tx, 0x10);
        for(int i = 0; i < 16; i++) bit_buffer_append_byte(tx, g->b0[i]);
        Iso14443_3aError e =
            iso14443_3a_poller_send_standard_frame(poller, tx, rx, 200000);
        g->tx_err = e;
        size_t n = bit_buffer_get_size_bytes(rx);
        g->rx_len = (int)n;
        for(size_t i = 0; i < n && i < sizeof(g->rx); i++) g->rx[i] = bit_buffer_get_byte(rx, i);
        FURI_LOG_I(TAG, "gen3 90F0 err=%d rxlen=%u", e, (unsigned)n);
        bit_buffer_free(tx);
        bit_buffer_free(rx);
        g->done = true;
        furi_semaphore_release(g->sem);
        return NfcCommandStop;
    }
    return NfcCommandContinue;
}

static void do_probe(App* app) {
    /* 1) read current block 0 with default key A */
    MfClassicKey ff;
    memset(ff.data, 0xFF, sizeof(ff.data));
    MfClassicBlock blk;
    MfClassicError re = mf_classic_poller_sync_read_block(app->nfc, 0, &ff, MfClassicKeyTypeA, &blk);
    app->rd_err = re;
    if(re != MfClassicErrorNone) {
        snprintf(app->note, sizeof(app->note), "blk0 read fail (e%d)", re);
        app->have_b0 = false;
    } else {
        memcpy(app->b0, blk.data, 16);
        app->have_b0 = true;
    }

    /* 2) send gen3 90F0 with the same block0 (non-destructive) */
    app->tx_err = -99;
    app->rx_len = 0;
    if(app->have_b0) {
        Gen3Ctx g = {0};
        g.sem = furi_semaphore_alloc(1, 0);
        g.b0 = app->b0;
        g.tx_err = -99;
        NfcPoller* poller = nfc_poller_alloc(app->nfc, NfcProtocolIso14443_3a);
        nfc_poller_start(poller, gen3_cb, &g);
        furi_semaphore_acquire(g.sem, furi_ms_to_ticks(3000));
        nfc_poller_stop(poller);
        nfc_poller_free(poller);
        furi_semaphore_free(g.sem);
        app->tx_err = g.tx_err;
        app->rx_len = g.rx_len;
        memcpy(app->rx, g.rx, sizeof(app->rx));

        if(g.tx_err == 0)
            snprintf(app->note, sizeof(app->note), "GEN3! accepted 90F0");
        else
            snprintf(app->note, sizeof(app->note), "not gen3 (tx e%d)", g.tx_err);
    }

    /* write results to SD */
    Storage* st = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(st);
    if(storage_file_open(f, "/ext/gen3_probe.txt", FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        char line[160];
        int hp = snprintf(
            line,
            sizeof(line),
            "rd_err=%d tx_err=%d rx_len=%d\nblk0:",
            app->rd_err,
            app->tx_err,
            app->rx_len);
        for(int i = 0; i < 16 && app->have_b0; i++)
            hp += snprintf(line + hp, sizeof(line) - hp, "%02X", app->b0[i]);
        hp += snprintf(line + hp, sizeof(line) - hp, "\nrx:");
        for(int i = 0; i < app->rx_len && i < 16; i++)
            hp += snprintf(line + hp, sizeof(line) - hp, "%02X", app->rx[i]);
        hp += snprintf(line + hp, sizeof(line) - hp, "\nnote=%s\n", app->note);
        storage_file_write(f, line, hp);
    }
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->scene = SceneResult;
    furi_mutex_release(app->mutex);
}

static void draw_cb(Canvas* c, void* ctx) {
    App* app = ctx;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    canvas_clear(c);
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 11, "Gen3 Probe");
    canvas_set_font(c, FontSecondary);
    if(app->scene == SceneIdle) {
        canvas_draw_str(c, 2, 26, "Hold card, press OK.");
        canvas_draw_str(c, 2, 38, "Non-destructive test");
        canvas_draw_str(c, 2, 50, "for Gen3 APDU magic.");
        canvas_draw_str(c, 2, 62, "OK probe   Back exit");
    } else if(app->scene == SceneBusy) {
        canvas_draw_str(c, 2, 34, "Probing - keep still");
    } else {
        char b[40];
        canvas_draw_str(c, 2, 26, app->note);
        snprintf(b, sizeof(b), "rd:e%d tx:e%d rx:%d", app->rd_err, app->tx_err, app->rx_len);
        canvas_draw_str(c, 2, 40, b);
        canvas_draw_str(c, 2, 50, "/ext/gen3_probe.txt");
        canvas_draw_str(c, 2, 62, "OK again   Back exit");
    }
    furi_mutex_release(app->mutex);
}

static void input_cb(InputEvent* e, void* ctx) {
    App* app = ctx;
    AppEvent ev = {.input = *e};
    furi_message_queue_put(app->q, &ev, FuriWaitForever);
}

int32_t gen3_test_app(void* p) {
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
            do_probe(app);
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
