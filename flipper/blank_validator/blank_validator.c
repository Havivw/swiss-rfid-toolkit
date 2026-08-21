/*
 * Blank Validator — Flipper Zero app  (SwissNFC/RFID toolkit)
 *
 * Tests whether an unknown/blank card is WRITEABLE, non-destructively:
 *   read original -> write a distinctive test value -> read back to confirm the
 *   write took -> restore the original.
 *
 *   LF (T5577/EM4305): writes a test EM4100 ID (one-call lfrfid write).
 *   HF (NTAG/UL, Mifare Classic): writes a test to a user page / data block.
 *
 * LIMITATION: HF tests MEMORY writeability only. It does NOT test magic-card UID
 * rewriting (gen1a/gen2) — those commands are not exposed to apps; use the stock
 * NFC app for magic UID cloning.
 *
 * Keep the card still until "DONE"; moving it mid-write can leave the test value
 * (re-run to restore, or it was blank anyway).
 */
#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <storage/storage.h>
#include <lfrfid/lfrfid_worker.h>
#include <lfrfid/protocols/lfrfid_protocols.h>
#include <toolbox/protocols/protocol_dict.h>
#include <nfc/nfc.h>
#include <nfc/nfc_poller.h>
#include <nfc/protocols/nfc_protocol.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller_sync.h>
#include <toolbox/bit_buffer.h>
#include <nfc/protocols/mf_classic/mf_classic.h>
#include <nfc/protocols/mf_classic/mf_classic_poller.h>
#include <nfc/protocols/mf_classic/mf_classic_poller_sync.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight_poller_sync.h>

typedef enum {
    SceneMenu,
    SceneBusy,
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
    FuriMessageQueue* event_queue;
    FuriMutex* mutex;

    ProtocolDict* dict;
    LFRFIDWorker* worker;
    Nfc* nfc;

    Scene scene;
    int menu_index;
    /* results */
    bool writeable;
    bool restored;
    char orig_type[20];
    char note[28];
    /* auto (LF+HF) combined results */
    bool have_both;
    bool lf_w;
    bool hf_w;
    char lf_type[20];
    char lf_note[28];
    char hf_type[20];
    char hf_note[28];
} App;

static const uint8_t TEST_ID[5] = {0xC0, 0xFF, 0xEE, 0xBA, 0xBE};

static const uint8_t DEFAULT_KEYS[][6] = {
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
    {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7},
    {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5},
    {0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD},
    {0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A},
    {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    {0x71, 0x4C, 0x5C, 0x88, 0x6E, 0x97},
    {0x58, 0x7E, 0xE5, 0xF9, 0x35, 0x0F},
};
#define N_DEFAULT_KEYS ((int)(sizeof(DEFAULT_KEYS) / sizeof(DEFAULT_KEYS[0])))

/* ============================ LF path ============================ */

typedef struct {
    FuriSemaphore* sem;
    bool ok;
    size_t proto;
    uint8_t data[16];
    size_t dsize;
    ProtocolDict* dict;
} RProbe;

static void rd_cb(LFRFIDWorkerReadResult result, ProtocolId protocol, void* ctx) {
    RProbe* p = ctx;
    if(result == LFRFIDWorkerReadDone && !p->ok) {
        p->proto = (size_t)protocol;
        p->dsize = protocol_dict_get_data_size(p->dict, p->proto);
        if(p->dsize > sizeof(p->data)) p->dsize = sizeof(p->data);
        protocol_dict_get_data(p->dict, p->proto, p->data, p->dsize);
        p->ok = true;
        furi_semaphore_release(p->sem);
    }
}

typedef struct {
    FuriSemaphore* sem;
    LFRFIDWorkerWriteResult res;
    bool done;
} WProbe;

static void wr_cb(LFRFIDWorkerWriteResult result, void* ctx) {
    WProbe* p = ctx;
    if(!p->done) {
        p->res = result;
        p->done = true;
        furi_semaphore_release(p->sem);
    }
}

static void wk_reset(App* app) {
    lfrfid_worker_stop(app->worker);
    lfrfid_worker_stop_thread(app->worker);
    lfrfid_worker_start_thread(app->worker);
}

static bool lf_read(App* app, size_t* proto, uint8_t* data, size_t* dsize) {
    RProbe p = {0};
    p.sem = furi_semaphore_alloc(1, 0);
    p.dict = app->dict;
    lfrfid_worker_read_start(app->worker, LFRFIDWorkerReadTypeAuto, rd_cb, &p);
    bool ok = (furi_semaphore_acquire(p.sem, furi_ms_to_ticks(2500)) == FuriStatusOk);
    furi_semaphore_free(p.sem);
    if(ok && p.ok) {
        *proto = p.proto;
        memcpy(data, p.data, p.dsize);
        *dsize = p.dsize;
        return true;
    }
    return false;
}

static bool lf_write(App* app, size_t proto, const uint8_t* data, size_t dsize) {
    protocol_dict_set_data(app->dict, proto, data, dsize);
    WProbe w = {0};
    w.sem = furi_semaphore_alloc(1, 0);
    lfrfid_worker_write_start(app->worker, (LFRFIDProtocol)proto, wr_cb, &w);
    bool ok = (furi_semaphore_acquire(w.sem, furi_ms_to_ticks(6000)) == FuriStatusOk);
    furi_semaphore_free(w.sem);
    return ok && w.res == LFRFIDWorkerWriteOK;
}

static void validate_lf(App* app) {
    size_t oproto = 0, odsize = 0;
    uint8_t odata[16] = {0};

    lfrfid_worker_start_thread(app->worker);
    bool have_orig = lf_read(app, &oproto, odata, &odsize);
    wk_reset(app);
    bool write_ok = lf_write(app, LFRFIDProtocolEM4100, TEST_ID, sizeof(TEST_ID));
    wk_reset(app);

    size_t rproto = 0, rdsize = 0;
    uint8_t rdata[16] = {0};
    bool verified = false;
    if(write_ok && lf_read(app, &rproto, rdata, &rdsize))
        verified = (rproto == LFRFIDProtocolEM4100) && (rdsize == sizeof(TEST_ID)) &&
                   (memcmp(rdata, TEST_ID, sizeof(TEST_ID)) == 0);
    wk_reset(app);

    bool restored = false;
    if(have_orig) restored = lf_write(app, oproto, odata, odsize);
    lfrfid_worker_stop_thread(app->worker);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->writeable = write_ok && verified;
    app->restored = restored;
    if(have_orig) {
        const char* pn = protocol_dict_get_name(app->dict, oproto);
        snprintf(app->orig_type, sizeof(app->orig_type), "LF %s", pn ? pn : "?");
    } else {
        snprintf(app->orig_type, sizeof(app->orig_type), "LF blank");
    }
    if(!write_ok)
        snprintf(app->note, sizeof(app->note), "write refused/no card");
    else if(!verified)
        snprintf(app->note, sizeof(app->note), "wrote but readback bad");
    else if(have_orig && !restored)
        snprintf(app->note, sizeof(app->note), "RESTORE FAILED-rerun!");
    else
        snprintf(app->note, sizeof(app->note), have_orig ? "original restored" : "was blank");
    app->scene = SceneResult;
    furi_mutex_release(app->mutex);

    /* LF diagnostics to /ext/bv_lf.txt */
    {
        Storage* storage = furi_record_open(RECORD_STORAGE);
        File* f = storage_file_alloc(storage);
        if(storage_file_open(f, "/ext/bv_lf.txt", FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
            char line[128];
            const char* pn = have_orig ? protocol_dict_get_name(app->dict, oproto) : "none";
            int n = snprintf(
                line,
                sizeof(line),
                "have_orig=%d proto=%s write_ok=%d verified=%d restored=%d note=%s\n",
                have_orig,
                pn ? pn : "?",
                write_ok,
                verified,
                restored,
                app->note);
            storage_file_write(f, line, n);
        }
        storage_file_close(f);
        storage_file_free(f);
        furi_record_close(RECORD_STORAGE);
    }
}

/* ============================ HF path ============================ */

/* Gen1a backdoor probe: HALT, then the magic wakeup 0x40 (7-bit) -> expect ACK
 * 0x0A, then 0x43 -> expect 0x0A. A normal card never ACKs these. Best-effort:
 * a wrong frame just fails to detect (safe). Must run inside the poller cb. */
#define GEN1A_FWT 60000U
#define TAG "BVDBG"
/* returns: 0 = no backdoor, 1 = 0x40 ACK only, 2 = full 0x40+0x43. *ack40 gets
 * the first byte the card returned to 0x40 (0xFF if none). gen1a is decided on
 * the 0x40 ACK alone (the discriminating step); 0x43 is a bonus confirm. */
static int gen1a_unlock(Iso14443_3aPoller* poller, uint8_t* ack40) {
    iso14443_3a_poller_halt(poller);
    BitBuffer* tx = bit_buffer_alloc(4);
    BitBuffer* rx = bit_buffer_alloc(4);
    int code = 0;
    *ack40 = 0xFF;

    bit_buffer_reset(tx);
    bit_buffer_append_byte(tx, 0x40);
    bit_buffer_set_size(tx, 7); /* 7-bit short frame */
    Iso14443_3aError e = iso14443_3a_poller_txrx_custom_parity(poller, tx, rx, GEN1A_FWT);
    size_t n = bit_buffer_get_size(rx);
    if(e == Iso14443_3aErrorNone && n >= 4) *ack40 = bit_buffer_get_byte(rx, 0);
    FURI_LOG_I(TAG, "gen1a 0x40: err=%d bits=%u ack=0x%02X", e, (unsigned)n, *ack40);
    if(e == Iso14443_3aErrorNone && n >= 4 && (*ack40 & 0x0F) == 0x0A) {
        code = 1;
        bit_buffer_reset(tx);
        bit_buffer_append_byte(tx, 0x43);
        Iso14443_3aError e2 = iso14443_3a_poller_txrx(poller, tx, rx, GEN1A_FWT);
        uint8_t a2 = (bit_buffer_get_size(rx) >= 4) ? bit_buffer_get_byte(rx, 0) : 0xFF;
        FURI_LOG_I(TAG, "gen1a 0x43: err=%d ack=0x%02X", e2, a2);
        if(e2 == Iso14443_3aErrorNone && (a2 & 0x0F) == 0x0A) code = 2;
    }
    bit_buffer_free(tx);
    bit_buffer_free(rx);
    return code;
}

typedef struct {
    FuriSemaphore* sem;
    bool done;
    int code;
    uint8_t ack40;
} Gen1Probe;

/* ---- gen2/CUID probe via the UNGUARDED low-level poller: auth sector 0,
 * toggle a manufacturer byte in block 0 with a raw write, read back, restore.
 * The sync write API guards block 0 (returns Protocol); this does not. ---- */
typedef struct {
    FuriSemaphore* sem;
    bool done;
    MfClassicKey key;
    MfClassicKeyType ktype;
    int auth_err;
    int write_err;
    int bd_auth_err; /* backdoor-auth attempt */
    int bd_write_err;
    bool verified;
    bool via_backdoor;
    bool restored;
} Gen2Probe;

/* auth (optionally via backdoor), read block0, toggle byte 8, write, read back;
 * returns true if the toggled write verified. Restores original on success. */
static bool gen2_try(
    MfClassicPoller* poller,
    MfClassicKey* key,
    MfClassicKeyType kt,
    bool backdoor,
    int* auth_err,
    int* write_err,
    bool* restored) {
    MfClassicAuthContext actx;
    int ae = mf_classic_poller_auth(poller, 0, key, kt, &actx, backdoor);
    if(auth_err) *auth_err = ae;
    if(ae != MfClassicErrorNone) return false;
    MfClassicBlock b0, b0t, rb;
    if(mf_classic_poller_read_block(poller, 0, &b0) != MfClassicErrorNone) return false;
    b0t = b0;
    b0t.data[8] ^= 0xFF; /* flip manufacturer data byte; UID+BCC intact */
    int we = mf_classic_poller_write_block(poller, 0, &b0t);
    if(write_err) *write_err = we;
    if(we != MfClassicErrorNone) return false;
    if(mf_classic_poller_read_block(poller, 0, &rb) != MfClassicErrorNone) return false;
    if(rb.data[8] != b0t.data[8]) return false;
    if(restored)
        *restored = (mf_classic_poller_write_block(poller, 0, &b0) == MfClassicErrorNone);
    return true;
}

static NfcCommand gen2_cb(NfcGenericEvent event, void* ctx) {
    Gen2Probe* g = ctx;
    if(g->done) return NfcCommandStop;
    MfClassicPoller* poller = (MfClassicPoller*)event.instance;
    MfClassicPollerEvent* ev = (MfClassicPollerEvent*)event.event_data;
    if(ev && ev->type == MfClassicPollerEventTypeRequestMode) {
        /* 1) standard auth + raw write */
        if(gen2_try(poller, &g->key, g->ktype, false, &g->auth_err, &g->write_err, &g->restored)) {
            g->verified = true;
        } else {
            /* 2) backdoor auth (static-nonce / GDM-style magic) */
            mf_classic_poller_halt(poller);
            if(gen2_try(
                   poller,
                   &g->key,
                   g->ktype,
                   true,
                   &g->bd_auth_err,
                   &g->bd_write_err,
                   &g->restored)) {
                g->verified = true;
                g->via_backdoor = true;
            }
        }
        g->done = true;
        furi_semaphore_release(g->sem);
        return NfcCommandStop;
    }
    return NfcCommandContinue;
}

/* returns true if block 0 accepted the raw write (=> gen2/CUID). Fills a compact
 * diagnostic string (auth/write errors, backdoor path) into dbg. */
static bool run_gen2_probe(App* app, MfClassicKey* key, MfClassicKeyType kt, char* dbg, size_t dbgsz, bool* via_bd) {
    Gen2Probe g = {0};
    g.sem = furi_semaphore_alloc(1, 0);
    g.key = *key;
    g.ktype = kt;
    g.auth_err = -1;
    g.write_err = -1;
    g.bd_auth_err = -1;
    g.bd_write_err = -1;
    NfcPoller* poller = nfc_poller_alloc(app->nfc, NfcProtocolMfClassic);
    nfc_poller_start(poller, gen2_cb, &g);
    furi_semaphore_acquire(g.sem, furi_ms_to_ticks(4000));
    nfc_poller_stop(poller);
    nfc_poller_free(poller);
    furi_semaphore_free(g.sem);
    if(dbg)
        snprintf(
            dbg,
            dbgsz,
            "a=%d w=%d bda=%d bdw=%d bd=%d",
            g.auth_err,
            g.write_err,
            g.bd_auth_err,
            g.bd_write_err,
            g.via_backdoor);
    if(via_bd) *via_bd = g.via_backdoor;
    return g.verified;
}

/* ---- gen3 (APDU) probe: rewrite block 0 with its OWN data via 90F0CCCC10
 * (non-destructive). If the card accepts it, it is a Gen3 magic card. ---- */
typedef struct {
    FuriSemaphore* sem;
    bool done;
    uint8_t b0[16];
    int tx_err;
} Gen3P;

static NfcCommand gen3_probe_cb(NfcGenericEvent event, void* ctx) {
    Gen3P* g = ctx;
    if(g->done) return NfcCommandStop;
    Iso14443_3aPoller* poller = (Iso14443_3aPoller*)event.instance;
    Iso14443_3aPollerEvent* ev = (Iso14443_3aPollerEvent*)event.event_data;
    if(ev && ev->type == Iso14443_3aPollerEventTypeReady) {
        BitBuffer* tx = bit_buffer_alloc(32);
        BitBuffer* rx = bit_buffer_alloc(32);
        bit_buffer_append_byte(tx, 0x90);
        bit_buffer_append_byte(tx, 0xF0);
        bit_buffer_append_byte(tx, 0xCC);
        bit_buffer_append_byte(tx, 0xCC);
        bit_buffer_append_byte(tx, 0x10);
        for(int i = 0; i < 16; i++) bit_buffer_append_byte(tx, g->b0[i]);
        g->tx_err = iso14443_3a_poller_send_standard_frame(poller, tx, rx, 200000);
        bit_buffer_free(tx);
        bit_buffer_free(rx);
        g->done = true;
        furi_semaphore_release(g->sem);
        return NfcCommandStop;
    }
    return NfcCommandContinue;
}

static bool run_gen3_probe(App* app, const uint8_t* b0) {
    Gen3P g = {0};
    g.sem = furi_semaphore_alloc(1, 0);
    memcpy(g.b0, b0, 16);
    g.tx_err = -99;
    NfcPoller* poller = nfc_poller_alloc(app->nfc, NfcProtocolIso14443_3a);
    nfc_poller_start(poller, gen3_probe_cb, &g);
    furi_semaphore_acquire(g.sem, furi_ms_to_ticks(3000));
    nfc_poller_stop(poller);
    nfc_poller_free(poller);
    furi_semaphore_free(g.sem);
    return g.tx_err == 0;
}

static NfcCommand gen1_cb(NfcGenericEvent event, void* ctx) {
    Gen1Probe* p = ctx;
    if(!p->done) {
        Iso14443_3aPoller* poller = (Iso14443_3aPoller*)event.instance;
        Iso14443_3aPollerEvent* ev = (Iso14443_3aPollerEvent*)event.event_data;
        if(ev && ev->type == Iso14443_3aPollerEventTypeReady)
            p->code = gen1a_unlock(poller, &p->ack40);
        p->done = true;
        furi_semaphore_release(p->sem);
    }
    return NfcCommandStop;
}

/* runs the gen1a probe; returns the code (0/1/2), writes the 0x40 ack to *ack40 */
static int run_gen1a_probe(App* app, uint8_t* ack40) {
    Gen1Probe p = {0};
    p.ack40 = 0xFF;
    p.sem = furi_semaphore_alloc(1, 0);
    NfcPoller* poller = nfc_poller_alloc(app->nfc, NfcProtocolIso14443_3a);
    nfc_poller_start(poller, gen1_cb, &p);
    bool ok = (furi_semaphore_acquire(p.sem, furi_ms_to_ticks(2000)) == FuriStatusOk);
    nfc_poller_stop(poller);
    *ack40 = p.ack40;
    nfc_poller_free(poller);
    furi_semaphore_free(p.sem);
    return ok ? p.code : 0;
}

static void validate_hf(App* app) {
    Iso14443_3aData* d = iso14443_3a_alloc();
    Iso14443_3aError err = iso14443_3a_poller_sync_read(app->nfc, d);
    bool writeable = false, restored = false;
    char type[20] = "none", note[28] = "no HF card";
    /* diagnostics captured for /ext/bv_debug.txt */
    int dbg_sak = -1, dbg_gcode = -1, dbg_fk = -2;
    uint8_t dbg_g40 = 0xFF;
    char dbg_gen2[40] = "n/a";

    if(err == Iso14443_3aErrorNone) {
        uint8_t sak = d->sak;
        dbg_sak = sak;
        if(sak == 0x00 && d->atqa[0] == 0x44) { /* NTAG / Ultralight — user page 4 */
            snprintf(type, sizeof(type), "HF NTAG/UL");
            MfUltralightPage orig, test, back;
            if(mf_ultralight_poller_sync_read_page(app->nfc, 4, &orig) == MfUltralightErrorNone) {
                memcpy(test.data, TEST_ID, 4);
                bool w = mf_ultralight_poller_sync_write_page(app->nfc, 4, &test) ==
                         MfUltralightErrorNone;
                bool v = w &&
                         mf_ultralight_poller_sync_read_page(app->nfc, 4, &back) ==
                             MfUltralightErrorNone &&
                         memcmp(back.data, test.data, 4) == 0;
                if(v) {
                    writeable = true;
                    restored = mf_ultralight_poller_sync_write_page(app->nfc, 4, &orig) ==
                               MfUltralightErrorNone;
                    snprintf(note, sizeof(note), restored ? "page4 restored" : "RESTORE FAILED");
                } else {
                    snprintf(note, sizeof(note), "page write refused");
                }
            } else {
                snprintf(note, sizeof(note), "page read-protected");
            }
        } else if(sak == 0x08 || sak == 0x18 || sak == 0x09) { /* Mifare Classic — block 1 */
            snprintf(type, sizeof(type), "HF MF Classic");
            uint8_t g40 = 0xFF;
            int gcode = run_gen1a_probe(app, &g40);
            dbg_gcode = gcode;
            dbg_g40 = g40;
            FURI_LOG_I(TAG, "gen1a code=%d ack40=0x%02X", gcode, g40);
            if(gcode >= 1) {
                writeable = true;
                restored = true; /* backdoor probe is read-only */
                snprintf(type, sizeof(type), "HF gen1a");
                snprintf(note, sizeof(note), gcode == 2 ? "backdoor 40+43" : "backdoor 0x40 ACK");
            } else {
            int fk = -1, ktype = 0;
            for(int i = 0; i < N_DEFAULT_KEYS && fk < 0; i++) {
                MfClassicKey k;
                memcpy(k.data, DEFAULT_KEYS[i], 6);
                MfClassicAuthContext ctx;
                if(mf_classic_poller_sync_auth(app->nfc, 0, &k, MfClassicKeyTypeA, &ctx) ==
                   MfClassicErrorNone) {
                    fk = i;
                    ktype = 0;
                } else if(mf_classic_poller_sync_auth(app->nfc, 0, &k, MfClassicKeyTypeB, &ctx) ==
                          MfClassicErrorNone) {
                    fk = i;
                    ktype = 1;
                }
            }
            dbg_fk = fk;
            FURI_LOG_I(TAG, "sec0 dict key idx=%d type=%c", fk, ktype ? 'B' : 'A');
            if(fk >= 0) {
                MfClassicKey k;
                memcpy(k.data, DEFAULT_KEYS[fk], 6);
                MfClassicKeyType kt = ktype ? MfClassicKeyTypeB : MfClassicKeyTypeA;

                /* 1) CUID/gen2 test via the UNGUARDED poller: try a raw block-0
                 * write (the sync API refuses block 0). If it takes, the card is
                 * a UID-writeable magic. Toggle one manufacturer byte, verify,
                 * restore. */
                bool via_bd = false;
                bool cuid = run_gen2_probe(app, &k, kt, dbg_gen2, sizeof(dbg_gen2), &via_bd);
                FURI_LOG_I(TAG, "gen2 %s verified=%d", dbg_gen2, cuid);

                /* gen3 (APDU) check: rewrite block 0 with its own data via 90F0 */
                bool gen3 = false;
                if(!cuid) {
                    MfClassicBlock cur;
                    if(mf_classic_poller_sync_read_block(app->nfc, 0, &k, kt, &cur) ==
                       MfClassicErrorNone)
                        gen3 = run_gen3_probe(app, cur.data);
                    FURI_LOG_I(TAG, "gen3 accepted=%d", gen3);
                }

                if(cuid) {
                    writeable = true;
                    restored = true;
                    snprintf(type, sizeof(type), "HF CUID/gen2");
                    snprintf(note, sizeof(note), via_bd ? "UID magic (backdoor)" : "UID-writeable magic");
                } else if(gen3) {
                    writeable = true;
                    restored = true;
                    snprintf(type, sizeof(type), "HF gen3");
                    snprintf(note, sizeof(note), "APDU UID-magic");
                } else {
                    /* 2) normal memory-writeable test on data block 1 */
                    MfClassicBlock orig, test, back;
                    if(mf_classic_poller_sync_read_block(app->nfc, 1, &k, kt, &orig) ==
                       MfClassicErrorNone) {
                        memset(test.data, 0, sizeof(test.data));
                        memcpy(test.data, TEST_ID, sizeof(TEST_ID));
                        bool w = mf_classic_poller_sync_write_block(app->nfc, 1, &k, kt, &test) ==
                                 MfClassicErrorNone;
                        bool v = w &&
                                 mf_classic_poller_sync_read_block(app->nfc, 1, &k, kt, &back) ==
                                     MfClassicErrorNone &&
                                 memcmp(back.data, test.data, 16) == 0;
                        if(v) {
                            writeable = true;
                            restored =
                                mf_classic_poller_sync_write_block(app->nfc, 1, &k, kt, &orig) ==
                                MfClassicErrorNone;
                            snprintf(note, sizeof(note), restored ? "mem RW; UID:NFC Magic" : "blk1 RESTORE FAIL");
                        } else {
                            snprintf(note, sizeof(note), "not magic; wr refused");
                        }
                    } else {
                        snprintf(note, sizeof(note), "block read failed");
                    }
                }
            } else {
                snprintf(note, sizeof(note), "no def key g40=%02X", g40);
            }
            } /* end: not gen1a */
        } else {
            snprintf(type, sizeof(type), "HF other");
            snprintf(note, sizeof(note), "write not supported");
        }
    }
    iso14443_3a_free(d);

    /* dump diagnostics to /ext/bv_debug.txt for offline inspection */
    {
        Storage* storage = furi_record_open(RECORD_STORAGE);
        File* f = storage_file_alloc(storage);
        if(storage_file_open(f, "/ext/bv_debug.txt", FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
            char line[160];
            int n = snprintf(
                line,
                sizeof(line),
                "sak=0x%02X gen1a_code=%d ack40=0x%02X sec0_key_idx=%d\n"
                "gen2[%s]\n"
                "type=%s note=%s writeable=%d\n",
                dbg_sak,
                dbg_gcode,
                dbg_g40,
                dbg_fk,
                dbg_gen2,
                type,
                note,
                writeable);
            storage_file_write(f, line, n);
        }
        storage_file_close(f);
        storage_file_free(f);
        furi_record_close(RECORD_STORAGE);
    }

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->writeable = writeable;
    app->restored = restored;
    snprintf(app->orig_type, sizeof(app->orig_type), "%s", type);
    snprintf(app->note, sizeof(app->note), "%s", note);
    app->scene = SceneResult;
    furi_mutex_release(app->mutex);
}

/* -------------------------- GUI -------------------------- */

static const char* const kMenu[] = {"Auto: LF then HF", "Test LF only", "Test HF only"};
#define MENU_COUNT ((int)(sizeof(kMenu) / sizeof(kMenu[0])))

static void draw_cb(Canvas* c, void* ctx) {
    App* app = ctx;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    canvas_clear(c);
    canvas_set_color(c, ColorBlack);
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 11, "Blank Validator");
    canvas_set_font(c, FontSecondary);

    if(app->scene == SceneMenu) {
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
        canvas_draw_str(c, 2, 62, "OK test   Back exit");
    } else if(app->scene == SceneBusy) {
        canvas_draw_str(c, 2, 30, "Testing - keep still");
        canvas_draw_str(c, 2, 42, "read/write/verify");
    } else if(app->have_both) { /* SceneResult, combined LF+HF */
        char line[40];
        /* type strings already carry the band (e.g. "LF T5577", "HF gen1a") */
        snprintf(line, sizeof(line), "%s%s", app->lf_w ? "[W] " : "[-] ", app->lf_type);
        canvas_draw_str(c, 2, 22, line);
        canvas_draw_str(c, 6, 31, app->lf_note);
        canvas_draw_line(c, 0, 35, 128, 35);
        snprintf(line, sizeof(line), "%s%s", app->hf_w ? "[W] " : "[-] ", app->hf_type);
        canvas_draw_str(c, 2, 46, line);
        canvas_draw_str(c, 6, 55, app->hf_note);
        canvas_draw_str(c, 2, 63, "OK menu  Back exit");
    } else { /* SceneResult, single band */
        canvas_set_font(c, FontPrimary);
        canvas_draw_box(c, 0, 16, 128, 13);
        canvas_set_color(c, ColorWhite);
        canvas_draw_str(c, 2, 26, app->writeable ? "WRITEABLE" : "not writeable");
        canvas_set_color(c, ColorBlack);
        canvas_set_font(c, FontSecondary);
        canvas_draw_str(c, 2, 40, app->orig_type);
        canvas_draw_str(c, 2, 50, app->note);
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
    app->dict = protocol_dict_alloc(lfrfid_protocols, LFRFIDProtocolMax);
    app->worker = lfrfid_worker_alloc(app->dict);
    app->nfc = nfc_alloc();
    app->scene = SceneMenu;

    app->gui = furi_record_open(RECORD_GUI);
    app->view_port = view_port_alloc();
    view_port_draw_callback_set(app->view_port, draw_cb, app);
    view_port_input_callback_set(app->view_port, input_cb, app);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);
    return app;
}

static void app_free(App* app) {
    lfrfid_worker_free(app->worker);
    protocol_dict_free(app->dict);
    nfc_free(app->nfc);
    gui_remove_view_port(app->gui, app->view_port);
    view_port_free(app->view_port);
    furi_record_close(RECORD_GUI);
    furi_message_queue_free(app->event_queue);
    furi_mutex_free(app->mutex);
    free(app);
}

int32_t blank_validator_app(void* p) {
    UNUSED(p);
    App* app = app_alloc();

    bool running = true;
    AppEvent event;
    while(running) {
        if(furi_message_queue_get(app->event_queue, &event, FuriWaitForever) != FuriStatusOk)
            continue;

        int action = 0; /* 1 = LF, 2 = HF */
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        if(event.type == EvInput) {
            InputEvent* in = &event.input;
            bool press = (in->type == InputTypeShort);
            if(app->scene == SceneMenu) {
                if(press && in->key == InputKeyUp)
                    app->menu_index = (app->menu_index + MENU_COUNT - 1) % MENU_COUNT;
                else if(press && in->key == InputKeyDown)
                    app->menu_index = (app->menu_index + 1) % MENU_COUNT;
                else if(press && in->key == InputKeyOk) {
                    app->scene = SceneBusy;
                    app->have_both = false;
                    action = (app->menu_index == 0) ? 3 : (app->menu_index == 1 ? 1 : 2);
                } else if(press && in->key == InputKeyBack)
                    running = false;
            } else if(app->scene == SceneResult) {
                if(press && in->key == InputKeyOk)
                    app->scene = SceneMenu;
                else if(press && in->key == InputKeyBack)
                    running = false;
            }
        }
        furi_mutex_release(app->mutex);

        if(action == 1) {
            view_port_update(app->view_port);
            validate_lf(app);
        } else if(action == 2) {
            view_port_update(app->view_port);
            validate_hf(app);
        } else if(action == 3) {
            /* auto: LF first, snapshot, then HF, show both */
            view_port_update(app->view_port);
            validate_lf(app);
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            snprintf(app->lf_type, sizeof(app->lf_type), "%s", app->orig_type);
            snprintf(app->lf_note, sizeof(app->lf_note), "%s", app->note);
            app->lf_w = app->writeable;
            app->scene = SceneBusy; /* keep "Testing" up during HF phase */
            furi_mutex_release(app->mutex);
            view_port_update(app->view_port);
            validate_hf(app);
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            snprintf(app->hf_type, sizeof(app->hf_type), "%s", app->orig_type);
            snprintf(app->hf_note, sizeof(app->hf_note), "%s", app->note);
            app->hf_w = app->writeable;
            app->have_both = true;
            app->scene = SceneResult;
            furi_mutex_release(app->mutex);
        }
        view_port_update(app->view_port);
    }

    app_free(app);
    return 0;
}
