/*
 * EM4100 Stepper — Flipper Zero app
 *
 * Purpose: for a lab that uses a bulk of EM4100 cards with sequential IDs to
 * identify things. Read one card to get a base ID, then step the 40-bit ID up
 * or down by a selectable step, and emulate the resulting ID to your reader.
 *
 * Screens:
 *   Menu  -> "Read a card" | "Manual / continue"
 *   Read  -> live LF read; on an EM4100 hit, jumps to Edit with the ID loaded
 *   Edit  -> Up/Down = +/- step ; Left/Right = step size ; OK = emulate toggle
 *
 * Emulation is live: editing the ID while emulating restarts the emulation with
 * the new value, so you can sweep IDs against the reader in real time.
 */
#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <lfrfid/lfrfid_worker.h>
#include <lfrfid/lfrfid_dict_file.h>
#include <lfrfid/protocols/lfrfid_protocols.h>
#include <toolbox/protocols/protocol_dict.h>
#include <dialogs/dialogs.h>

#define LFRFID_DIR "/ext/lfrfid"

#define MAX_DATA 16 /* max LF protocol data blob (bytes) we handle */

static const uint32_t STEPS[] = {1, 10, 100, 1000, 10000};
#define STEP_COUNT (sizeof(STEPS) / sizeof(STEPS[0]))

typedef enum {
    SceneMenu,
    SceneRead,
    SceneEdit,
} Scene;

/* What the single LF worker is currently doing. Used so we never stop an
 * already-idle worker (that trips a furi_check) or start a second operation
 * without stopping the first. */
typedef enum {
    WkIdle,
    WkRead,
    WkEmu,
} WorkerMode;

typedef enum {
    EvInput,
    EvReadDone,
    EvAutoTick, /* auto-sweep timer fired: step + emulate next ID */
} AppEventType;

typedef struct {
    AppEventType type;
    InputEvent input;
} AppEvent;

/* Editable fields on the Edit screen, selected with Left/Right. */
typedef enum {
    FieldId, /* the ID itself (Up/Down = +/- step) */
    FieldPos, /* which byte to step: -1 = whole value, else byte index */
    FieldStep, /* step size */
    FieldDelay, /* ms of dwell per card in auto mode */
    FieldDir, /* sweep direction */
    FieldCount,
} Field;

#define DELAY_MIN 100u
#define DELAY_MAX 10000u
#define DELAY_INC 100u

typedef struct {
    Gui* gui;
    ViewPort* view_port;
    DialogsApp* dialogs; /* for the file browser (load) */
    FuriMessageQueue* event_queue;
    FuriMutex* mutex;
    FuriTimer* auto_timer; /* periodic tick for auto-sweep */

    ProtocolDict* dict;
    LFRFIDWorker* worker;
    WorkerMode worker_mode; /* current LF worker state */
    size_t protocol; /* current LF protocol id (default EM4100) */
    size_t data_size; /* bytes of current protocol's data blob */

    Scene scene;
    int menu_index;

    uint8_t id[MAX_DATA]; /* current working data (big-endian) */
    int step_pos; /* -1 = step whole value; else step only this byte index */
    int step_index;
    uint32_t delay_ms; /* time between cards in auto mode */
    int dir; /* +1 or -1 */
    int cursor; /* selected Field */
    bool auto_on; /* sweep active (emulating; may be paused) */
    bool paused; /* sweep paused: timer stopped, still emulating current ID */
    bool reading;

    /* filled by the worker thread on a completed read */
    volatile bool read_ok;
    size_t read_protocol;
    size_t read_data_size;
    uint8_t read_id[MAX_DATA];

    char message[32]; /* transient status line on the Read screen */
    char decoded[32]; /* protocol-decoded fields (e.g. HID FC/Card) */
} App;

/* -------------------------- ID helpers -------------------------- */

/* Interpret up to 8 trailing bytes as a big-endian integer (for the decimal
 * readout only; stepping itself is done on the raw byte array). */
static uint64_t id_to_u64(const uint8_t* id, int len) {
    uint64_t v = 0;
    int start = (len > 8) ? len - 8 : 0;
    for(int i = start; i < len; i++) v = (v << 8) | id[i];
    return v;
}

/* value -> decimal string (avoids 64-bit printf, which the Flipper's reduced
 * libc does not support). */
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

/* Add/subtract STEP to the data blob as a big-endian integer of data_size
 * bytes, wrapping within that width. Works for any protocol width. */
static void step_id(App* app, int dir) {
    uint32_t step = STEPS[app->step_index];
    int n = (int)app->data_size;
    if(n <= 0 || n > MAX_DATA) return;

    /* single-byte (truncation-test) mode: change only the selected byte */
    if(app->step_pos >= 0 && app->step_pos < n) {
        int i = app->step_pos;
        int v = (int)app->id[i] + (dir > 0 ? (int)step : -(int)step);
        v %= 256;
        if(v < 0) v += 256;
        app->id[i] = (uint8_t)v;
        return;
    }

    if(dir > 0) {
        uint32_t carry = step;
        for(int i = n - 1; i >= 0 && carry; i--) {
            uint32_t v = app->id[i] + (carry & 0xFF);
            app->id[i] = (uint8_t)(v & 0xFF);
            carry = (carry >> 8) + (v >> 8);
        }
    } else {
        uint32_t s = step;
        for(int i = n - 1; i >= 0 && s; i--) {
            int32_t sub = (int32_t)(s & 0xFF);
            s >>= 8;
            int32_t v = (int32_t)app->id[i] - sub;
            if(v < 0) {
                v += 256;
                s += 1; /* borrow into next byte */
            }
            app->id[i] = (uint8_t)v;
        }
    }
}

/* Refresh the protocol-decoded string (e.g. HID facility code + card number)
 * using the lfrfid library's own field renderer. Call from the main thread. */
static void update_decoded(App* app) {
    FuriString* s = furi_string_alloc();
    protocol_dict_set_data(app->dict, app->protocol, app->id, app->data_size);
    protocol_dict_render_brief_data(app->dict, s, app->protocol);
    const char* cs = furi_string_get_cstr(s);
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    int j = 0;
    for(int i = 0; cs[i] && j < (int)sizeof(app->decoded) - 1; i++)
        app->decoded[j++] = (cs[i] == '\n' || cs[i] == '\r') ? ' ' : cs[i];
    app->decoded[j] = '\0';
    furi_mutex_release(app->mutex);
    furi_string_free(s);
}

/* -------------------------- worker actions (call WITHOUT holding mutex) ------ */

/* Return the LF worker to Idle *synchronously*.
 *
 * lfrfid_worker_stop() only SIGNALS the worker thread — mode_index is not Idle
 * when it returns. But lfrfid_worker_emulate_start()/read_start() assert
 * furi_check(mode_index == Idle). So to safely switch modes (which the
 * auto-sweep does on every tick) we stop the mode and cycle the worker thread:
 * stop_thread joins the thread, which guarantees the mode is Idle before we
 * start the next one. */
static void worker_go_idle(App* app) {
    if(app->worker_mode == WkIdle) return;
    lfrfid_worker_stop(app->worker);
    lfrfid_worker_stop_thread(app->worker); /* joins -> guaranteed idle */
    lfrfid_worker_start_thread(app->worker);
    app->worker_mode = WkIdle;
}

static void worker_stop(App* app) {
    worker_go_idle(app);
}

static void read_cb(LFRFIDWorkerReadResult result, ProtocolId protocol, void* ctx);

static void worker_start_read(App* app) {
    worker_go_idle(app);
    app->read_ok = false;
    lfrfid_worker_read_start(app->worker, LFRFIDWorkerReadTypeAuto, read_cb, app);
    app->worker_mode = WkRead;
}

static void worker_start_emulate(App* app) {
    worker_go_idle(app);
    protocol_dict_set_data(app->dict, app->protocol, app->id, app->data_size);
    lfrfid_worker_emulate_start(app->worker, (LFRFIDProtocol)app->protocol);
    app->worker_mode = WkEmu;
}

/* ---- load / save of standard Flipper .rfid files (call WITHOUT the mutex; the
 * file browser is a blocking GUI call) ------------------------------------- */

static void do_load(App* app) {
    worker_stop(app); /* loading rewrites the dict; must not be emulating */

    FuriString* path = furi_string_alloc();
    furi_string_set(path, LFRFID_DIR);
    DialogsFileBrowserOptions opts;
    dialog_file_browser_set_basic_options(&opts, ".rfid", NULL);
    opts.base_path = LFRFID_DIR;
    bool picked = dialog_file_browser_show(app->dialogs, path, path, &opts);

    if(picked) {
        ProtocolId pid = lfrfid_dict_file_load(app->dict, furi_string_get_cstr(path));
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        if(pid != PROTOCOL_NO) {
            app->protocol = (size_t)pid;
            app->data_size = protocol_dict_get_data_size(app->dict, app->protocol);
            if(app->data_size > MAX_DATA) app->data_size = MAX_DATA;
            protocol_dict_get_data(app->dict, app->protocol, app->id, app->data_size);
            app->message[0] = '\0';
            app->scene = SceneEdit;
        } else {
            snprintf(app->message, sizeof(app->message), "Load failed");
            app->scene = SceneMenu;
        }
        furi_mutex_release(app->mutex);
    }
    furi_string_free(path);
}

static void do_save(App* app) {
    worker_stop(app);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    uint8_t id[MAX_DATA];
    size_t n = app->data_size;
    size_t proto = app->protocol;
    memcpy(id, app->id, n);
    furi_mutex_release(app->mutex);

    /* hex of the data blob for a unique, human-readable filename */
    char hex[MAX_DATA * 2 + 1];
    for(size_t i = 0; i < n && i < MAX_DATA; i++) snprintf(hex + i * 2, 3, "%02X", id[i]);
    const char* pname = protocol_dict_get_name(app->dict, proto);

    char fn[96];
    snprintf(fn, sizeof(fn), LFRFID_DIR "/STEP_%s_%s.rfid", pname, hex);

    protocol_dict_set_data(app->dict, proto, id, n);
    bool ok = lfrfid_dict_file_save(app->dict, proto, fn);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    snprintf(app->message, sizeof(app->message), ok ? "Saved to lfrfid" : "Save failed");
    furi_mutex_release(app->mutex);
}

/* -------------------------- GUI -------------------------- */

static const char* const kMenu[] = {
    "Read a card",
    "Load saved (.rfid)",
    "Manual / continue",
    "Save current ID",
};
#define MENU_COUNT ((int)(sizeof(kMenu) / sizeof(kMenu[0])))

static void draw_menu(Canvas* c, App* app) {
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 11, "RFID Stepper");
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
    if(app->message[0]) {
        canvas_draw_str(c, 2, 63, app->message);
    } else {
        canvas_draw_str(c, 2, 63, "OK select   Back exit");
    }
}

static void draw_read(Canvas* c, App* app) {
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 12, "Reading LF card...");
    canvas_set_font(c, FontSecondary);
    canvas_draw_str(c, 2, 30, "Hold card to back");
    if(app->message[0]) canvas_draw_str(c, 2, 44, app->message);
    canvas_draw_str(c, 2, 62, "Back: cancel");
}

/* Draw a token at (x, baseline_y); if highlighted, invert it. Returns the x
 * just past the drawn text so tokens can be laid out left-to-right. */
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
    canvas_draw_rframe(c, x, y, 9, 7, 3);
    canvas_draw_dot(c, x + 2, y + 3);
    canvas_draw_dot(c, x + 6, y + 3);
    canvas_draw_dot(c, x + 4, y + 4);
    canvas_draw_line(c, x + 2, y + 7, x + 2, y + 8);
    canvas_draw_line(c, x + 4, y + 7, x + 4, y + 8);
    canvas_draw_line(c, x + 6, y + 7, x + 6, y + 8);
}

static void draw_edit(Canvas* c, App* app) {
    char buf[40];

    /* ID in hex (field 0), variable width by protocol */
    canvas_set_font(c, FontPrimary);
    char hexbuf[MAX_DATA * 3 + 1];
    int hp = 0;
    for(size_t i = 0; i < app->data_size && i < MAX_DATA; i++)
        hp += snprintf(hexbuf + hp, sizeof(hexbuf) - hp, "%02X ", app->id[i]);
    if(hp > 0) hexbuf[hp - 1] = '\0';
    draw_token(c, 2, 11, hexbuf, app->cursor == FieldId);

    /* decoded fields when the protocol renders them (HID facility/card, etc.);
     * otherwise protocol name + decimal (for EM4100-style sequential IDs) */
    canvas_set_font(c, FontSecondary);
    const char* pname = protocol_dict_get_name(app->dict, app->protocol);
    if(app->decoded[0]) {
        snprintf(buf, sizeof(buf), "%s", app->decoded);
    } else if(app->data_size <= 8) {
        char dec[24];
        u64_to_dec(id_to_u64(app->id, (int)app->data_size), dec, sizeof(dec));
        snprintf(buf, sizeof(buf), "%s  %s", pname ? pname : "?", dec);
    } else {
        snprintf(buf, sizeof(buf), "%s  (%ub)", pname ? pname : "?", (unsigned)app->data_size);
    }
    canvas_draw_str(c, 2, 23, buf);

    /* fields row: step, delay, direction, byte-position (truncation test) */
    snprintf(buf, sizeof(buf), "x%lu", (unsigned long)STEPS[app->step_index]);
    draw_token(c, 2, 36, buf, app->cursor == FieldStep);

    snprintf(
        buf,
        sizeof(buf),
        "%lu.%lus",
        (unsigned long)(app->delay_ms / 1000),
        (unsigned long)((app->delay_ms % 1000) / 100));
    draw_token(c, 30, 36, buf, app->cursor == FieldDelay);

    snprintf(buf, sizeof(buf), "D%c", app->dir > 0 ? '+' : '-');
    draw_token(c, 70, 36, buf, app->cursor == FieldDir);

    if(app->step_pos < 0)
        snprintf(buf, sizeof(buf), "all");
    else
        snprintf(buf, sizeof(buf), "B%d", app->step_pos);
    draw_token(c, 96, 36, buf, app->cursor == FieldPos);

    /* status line — every decodable 125 kHz credential is a cloneable static
     * ID (no secure LF exists; see VULN_CATALOG.md), so idle shows the verdict */
    const char* status = app->auto_on ? (app->paused ? "AUTO paused" : "AUTO sweeping") :
                                         "CLONE  LF static";
    if(app->message[0]) {
        /* transient confirmation (e.g. "Saved") until the next keypress */
        canvas_draw_box(c, 0, 40, 128, 11);
        canvas_set_color(c, ColorWhite);
        canvas_draw_str(c, 2, 49, app->message);
        canvas_set_color(c, ColorBlack);
    } else if(app->auto_on) {
        canvas_draw_box(c, 0, 40, 128, 11);
        canvas_set_color(c, ColorWhite);
        canvas_draw_str(c, 2, 49, status);
        canvas_set_color(c, ColorBlack);
    } else {
        draw_skull(c, 2, 41);
        canvas_draw_str(c, 14, 49, status);
    }

    /* hint */
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

/* Auto-sweep timer — runs in the timer service thread. Just notify the main
 * loop; all worker/state changes happen there. Non-blocking put so a backed-up
 * queue drops a tick instead of stalling the timer service. */
static void auto_timer_cb(void* ctx) {
    App* app = ctx;
    AppEvent ev = {.type = EvAutoTick};
    furi_message_queue_put(app->event_queue, &ev, 0);
}

/* Worker read callback — runs on the worker thread. Keep it minimal: capture
 * the ID and notify the main loop via the event queue (no mutex here to avoid
 * a deadlock with worker stop). */
static void read_cb(LFRFIDWorkerReadResult result, ProtocolId protocol, void* ctx) {
    App* app = ctx;
    if(result != LFRFIDWorkerReadDone) return;
    /* accept any LF protocol the Flipper decoded */
    app->read_protocol = (size_t)protocol;
    app->read_data_size = protocol_dict_get_data_size(app->dict, (size_t)protocol);
    if(app->read_data_size > MAX_DATA) app->read_data_size = MAX_DATA;
    protocol_dict_get_data(app->dict, (size_t)protocol, app->read_id, app->read_data_size);
    app->read_ok = true;
    AppEvent ev = {.type = EvReadDone};
    /* timeout 0: never block the worker thread here — the main loop may be
     * joining this very thread in worker_go_idle(), and a blocking put would
     * deadlock. A dropped duplicate read is harmless. */
    furi_message_queue_put(app->event_queue, &ev, 0);
}

/* -------------------------- app lifecycle -------------------------- */

static App* app_alloc(void) {
    App* app = malloc(sizeof(App));
    memset(app, 0, sizeof(App));

    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->event_queue = furi_message_queue_alloc(16, sizeof(AppEvent));
    app->auto_timer = furi_timer_alloc(auto_timer_cb, FuriTimerTypePeriodic, app);

    app->dict = protocol_dict_alloc(lfrfid_protocols, LFRFIDProtocolMax);
    app->protocol = LFRFIDProtocolEM4100; /* default until a read/load */
    app->data_size = protocol_dict_get_data_size(app->dict, app->protocol);
    if(app->data_size > MAX_DATA) app->data_size = MAX_DATA;
    app->worker = lfrfid_worker_alloc(app->dict);
    lfrfid_worker_start_thread(app->worker);

    app->scene = SceneMenu;
    app->menu_index = 0;
    app->step_index = 0;
    app->step_pos = -1;
    app->delay_ms = 500;
    app->dir = +1;
    app->cursor = FieldId;

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
    if(app->worker_mode != WkIdle) lfrfid_worker_stop(app->worker);
    lfrfid_worker_stop_thread(app->worker);
    lfrfid_worker_free(app->worker);
    protocol_dict_free(app->dict);

    gui_remove_view_port(app->gui, app->view_port);
    view_port_free(app->view_port);
    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_DIALOGS);

    furi_message_queue_free(app->event_queue);
    furi_mutex_free(app->mutex);
    free(app);
}

int32_t em4100_stepper_app(void* p) {
    UNUSED(p);
    App* app = app_alloc();

    bool running = true;
    AppEvent event;
    while(running) {
        if(furi_message_queue_get(app->event_queue, &event, FuriWaitForever) != FuriStatusOk)
            continue;

        /* deferred worker actions, decided under the mutex, executed after */
        bool a_stop = false, a_read = false, a_emu = false;
        bool a_timer_start = false, a_timer_stop = false;
        bool a_load = false, a_save = false;

        furi_mutex_acquire(app->mutex, FuriWaitForever);

        if(event.type == EvReadDone) {
            if(app->read_ok) {
                app->protocol = app->read_protocol;
                app->data_size = app->read_data_size;
                memcpy(app->id, app->read_id, app->data_size);
                app->reading = false;
                app->message[0] = '\0';
                app->scene = SceneEdit;
                a_stop = true; /* stop the reader once we have a card */
            }
        } else if(event.type == EvAutoTick) {
            /* auto-sweep: advance one step and re-emulate (unless paused) */
            if(app->auto_on && !app->paused) {
                step_id(app, app->dir);
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
                    case 0: /* Read a card */
                        app->scene = SceneRead;
                        app->reading = true;
                        a_read = true;
                        break;
                    case 1: /* Load saved */
                        a_load = true; /* blocking file browser, run after unlock */
                        break;
                    case 2: /* Manual / continue */
                        app->scene = SceneEdit;
                        break;
                    case 3: /* Save current ID */
                        a_save = true;
                        break;
                    }
                } else if(press && in->key == InputKeyBack) {
                    running = false;
                }
            } else if(app->scene == SceneRead) {
                if((press || in->type == InputTypeLong) && in->key == InputKeyBack) {
                    app->reading = false;
                    app->message[0] = '\0';
                    app->scene = SceneMenu;
                    a_stop = true;
                }
            } else { /* SceneEdit */
                bool ud = (press || repeat);
                if(press || in->type == InputTypeLong)
                    app->message[0] = '\0'; /* dismiss prior confirmation */
                if(ud && in->key == InputKeyUp) {
                    switch(app->cursor) {
                    case FieldId:
                        step_id(app, +1);
                        if(app->auto_on) a_emu = true;
                        break;
                    case FieldPos:
                        if(app->step_pos < (int)app->data_size - 1)
                            app->step_pos++;
                        else
                            app->step_pos = -1;
                        break;
                    case FieldStep:
                        if(app->step_index < (int)STEP_COUNT - 1) app->step_index++;
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
                    case FieldId:
                        step_id(app, -1);
                        if(app->auto_on) a_emu = true;
                        break;
                    case FieldPos:
                        if(app->step_pos < 0)
                            app->step_pos = (int)app->data_size - 1;
                        else
                            app->step_pos--;
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
                        app->paused = true; /* hold current ID, keep emulating */
                        a_timer_stop = true;
                    } else {
                        app->paused = false;
                        a_timer_start = true;
                    }
                } else if(in->key == InputKeyOk && in->type == InputTypeLong) {
                    /* OK hold: quick-save current ID (stops emulation) */
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

        /* Perform worker + timer ops outside the mutex. Order matters: a fresh
         * emulate implies stopping any prior operation first. */
        if(a_emu) {
            worker_start_emulate(app); /* self-stops any prior mode first */
        } else if(a_stop) {
            worker_stop(app);
        }
        if(a_timer_stop) {
            furi_timer_stop(app->auto_timer);
        }
        if(a_timer_start) {
            furi_timer_stop(app->auto_timer);
            furi_timer_start(app->auto_timer, furi_ms_to_ticks(app->delay_ms));
        }
        if(a_read) {
            worker_start_read(app);
        }
        if(a_load) {
            do_load(app); /* blocking file browser + load */
        }
        if(a_save) {
            do_save(app);
        }

        if(app->scene == SceneEdit) update_decoded(app);
        view_port_update(app->view_port);
    }

    app_free(app);
    return 0;
}
