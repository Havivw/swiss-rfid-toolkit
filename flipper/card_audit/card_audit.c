/*
 * Card Audit — Flipper Zero app  (SwissNFC/RFID toolkit)
 *
 * AUTHORIZED, DEFENSIVE use only. Reads a card, classifies its security, ACTIVELY
 * verifies the weakness where feasible, and writes a timestamped report to the SD
 * card. Active checks are non-destructive (reads / default-key auth attempts):
 *   - Mifare Classic : try a default-key dictionary (auth block 0) -> confirmed weak
 *   - DESFire        : GetVersion -> exact generation (orig 3DES = broken)
 *   - UL/NTAG, LF    : a successful read proves the credential is cloneable
 *
 * Reports go to  /ext/swissnfcrfid_reports/  and carry an authorization notice.
 */
#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <input/input.h>
#include <storage/storage.h>
#include <datetime/datetime.h>

#include <lfrfid/lfrfid_worker.h>
#include <lfrfid/protocols/lfrfid_protocols.h>
#include <toolbox/protocols/protocol_dict.h>

#include <nfc/nfc.h>
#include <nfc/nfc_poller.h>
#include <nfc/nfc_device.h>
#include <nfc/protocols/nfc_protocol.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller_sync.h>
#include <nfc/protocols/mf_desfire/mf_desfire.h>
#include <nfc/protocols/mf_desfire/mf_desfire_poller.h>
#include <nfc/protocols/mf_classic/mf_classic.h>
#include <nfc/protocols/mf_classic/mf_classic_poller_sync.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight_poller_sync.h>
#include <nfc/nfc_device.h>
#include <dialogs/dialogs.h>

#define REPORT_DIR "/ext/swissnfcrfid_reports"
#define NFC_DIR "/ext/nfc"

typedef enum {
    SceneAuth, /* authorization gate */
    SceneMenu,
    SceneBusy,
    SceneResult,
    SceneReportList,
    SceneReportView,
} Scene;

typedef enum {
    EvInput,
    EvDone,
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

    ProtocolDict* dict;
    LFRFIDWorker* lf_worker;
    Nfc* nfc;

    Scene scene;
    int menu_index;

    /* last audit result (for the Result screen) */
    char r_type[24];
    char r_verdict[16];
    char r_detail[48];
    char r_proof[64]; /* recovered protected data (real proof), if any */
    char r_file[40];

    /* report viewer */
    char reports[40][40];
    int report_count;
    int report_sel;
    char view_buf[1024];
    int view_scroll;
} App;

/* Top-10 well-known Mifare Classic default keys (factory / MAD / NDEF / common
 * transit & vendor defaults) — the set attackers try first. */
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

/* Fudan/clone backdoor key (Quarkslab 2024, eprint 2024/1275): FM11RF08S and
 * kin authenticate under this single production-wide key, recovering every key
 * even when fully diversified. If block 0 auths with it -> backdoored silicon. */
static const uint8_t FUDAN_BACKDOOR[6] = {0xA3, 0x96, 0xEF, 0xA4, 0xE2, 0x4F};

/* ---- DESFire GetVersion (reused pattern) ---- */
typedef struct {
    FuriSemaphore* sem;
    bool done;
    bool ok; /* GetVersion succeeded (is a DESFire) */
    MfDesfireVersion version;
    /* unauthenticated config/exposure reads */
    bool have_settings;
    MfDesfireKeySettings settings;
    bool have_kv;
    uint8_t key_ver; /* PICC master key version */
    bool have_fm;
    MfDesfireFreeMemory freemem;
} DesfireProbe;

/* Runs inside the poller callback — card is active. Reads GetVersion, then the
 * PICC key settings / key version / free memory, all WITHOUT authentication. */
static NfcCommand desfire_probe_cb(NfcGenericEvent event, void* ctx) {
    DesfireProbe* p = ctx;
    if(!p->done) {
        MfDesfirePoller* poller = (MfDesfirePoller*)event.instance;
        p->ok = (mf_desfire_poller_read_version(poller, &p->version) == MfDesfireErrorNone);
        p->have_settings =
            (mf_desfire_poller_read_key_settings(poller, &p->settings) == MfDesfireErrorNone);
        MfDesfireKeyVersion kv = 0;
        p->have_kv = (mf_desfire_poller_read_key_version(poller, 0, &kv) == MfDesfireErrorNone);
        if(p->have_kv) p->key_ver = kv;
        p->have_fm =
            (mf_desfire_poller_read_free_memory(poller, &p->freemem) == MfDesfireErrorNone);
        p->done = true;
        furi_semaphore_release(p->sem);
    }
    return NfcCommandStop;
}

static bool desfire_probe(App* app, DesfireProbe* out) {
    memset(out, 0, sizeof(*out));
    out->sem = furi_semaphore_alloc(1, 0);
    NfcPoller* poller = nfc_poller_alloc(app->nfc, NfcProtocolMfDesfire);
    nfc_poller_start(poller, desfire_probe_cb, out);
    bool ok = (furi_semaphore_acquire(out->sem, furi_ms_to_ticks(3000)) == FuriStatusOk);
    nfc_poller_stop(poller);
    nfc_poller_free(poller);
    furi_semaphore_free(out->sem);
    out->sem = NULL;
    return ok && out->ok;
}

/* ---- report writer ---- */
static void write_report(App* app, const char* band, const char* uidhex, const char* extra) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_common_mkdir(storage, REPORT_DIR);

    DateTime dt;
    furi_hal_rtc_get_datetime(&dt);
    snprintf(
        app->r_file,
        sizeof(app->r_file),
        "audit_%04u%02u%02u_%02u%02u%02u.txt",
        dt.year,
        dt.month,
        dt.day,
        dt.hour,
        dt.minute,
        dt.second);

    char path[80];
    snprintf(path, sizeof(path), "%s/%s", REPORT_DIR, app->r_file);

    char body[600];
    int n = snprintf(
        body,
        sizeof(body),
        "=== SwissNFC/RFID Card Audit ===\n"
        "AUTHORIZED USE ONLY. Only assess cards/systems you own or are\n"
        "contracted/permitted (in writing) to test.\n\n"
        "Time: %04u-%02u-%02u %02u:%02u:%02u\n"
        "Band: %s\n"
        "Type: %s\n"
        "UID/ID: %s\n"
        "Verdict: %s\n"
        "Detail: %s\n"
        "%s\n"
        "%s\n"
        "================================\n",
        dt.year,
        dt.month,
        dt.day,
        dt.hour,
        dt.minute,
        dt.second,
        band,
        app->r_type,
        uidhex,
        app->r_verdict,
        app->r_detail,
        app->r_proof[0] ? app->r_proof : "(no protected data recovered)",
        extra ? extra : "");

    File* f = storage_file_alloc(storage);
    if(storage_file_open(f, path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        storage_file_write(f, body, n);
        storage_file_close(f);
    } else {
        snprintf(app->r_file, sizeof(app->r_file), "(write failed)");
    }
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
}

/* ---- HF audit ---- */
static void audit_hf(App* app) {
    Iso14443_3aData* d = iso14443_3a_alloc();
    Iso14443_3aError err = iso14443_3a_poller_sync_read(app->nfc, d);

    if(err != Iso14443_3aErrorNone) {
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        snprintf(app->r_type, sizeof(app->r_type), "no HF card");
        snprintf(app->r_verdict, sizeof(app->r_verdict), "-");
        snprintf(app->r_detail, sizeof(app->r_detail), "read failed / not ISO14443-A");
        app->r_proof[0] = '\0';
        app->r_file[0] = '\0';
        app->scene = SceneResult;
        furi_mutex_release(app->mutex);
        iso14443_3a_free(d);
        return;
    }

    size_t len = 0;
    const uint8_t* uid = iso14443_3a_get_uid(d, &len);
    uint8_t sak = d->sak;
    char uidhex[24] = {0};
    int hp = 0;
    for(size_t i = 0; i < len && hp < (int)sizeof(uidhex) - 3; i++)
        hp += snprintf(uidhex + hp, sizeof(uidhex) - hp, "%02X ", uid[i]);
    if(hp > 0) uidhex[hp - 1] = '\0';

    char type[24], verdict[16], detail[48], extra[96];
    char proof_line[64];
    extra[0] = '\0';
    proof_line[0] = '\0';

    if(sak == 0x08 || sak == 0x18 || sak == 0x09) {
        snprintf(type, sizeof(type), "%s", sak == 0x18 ? "MFClassic4K" : (sak == 0x09 ? "MF Mini" : "MFClassic1K"));
        snprintf(verdict, sizeof(verdict), "BROKEN");

        MfClassicType mtype =
            (sak == 0x18) ? MfClassicType4k : (sak == 0x09) ? MfClassicTypeMini : MfClassicType1k;
        uint8_t sectors = mf_classic_get_total_sectors_num(mtype);

        /* recover a key per sector from the top-10 default dictionary */
        MfClassicDeviceKeys keys;
        memset(&keys, 0, sizeof(keys));
        int sec0_key = -1, sec0_ktype = 0;
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
                    if(s == 0 && sec0_key < 0) sec0_key = i, sec0_ktype = 0;
                }
                if(!(keys.key_b_mask & (1ULL << s)) &&
                   mf_classic_poller_sync_auth(app->nfc, blk, &k, MfClassicKeyTypeB, &ctx) ==
                       MfClassicErrorNone) {
                    keys.key_b[s] = k;
                    keys.key_b_mask |= (1ULL << s);
                    if(s == 0 && sec0_key < 0) sec0_key = i, sec0_ktype = 1;
                }
                if((keys.key_a_mask & (1ULL << s)) && (keys.key_b_mask & (1ULL << s))) break;
            }
        }

        /* static-key check: same Key A across all recovered sectors means the
         * whole install shares one key -> clone-once / open-all (Critical). */
        bool static_key = false;
        {
            int found = 0;
            bool same = true, have_ref = false;
            MfClassicKey ref;
            for(uint8_t s = 0; s < sectors; s++) {
                if(keys.key_a_mask & (1ULL << s)) {
                    found++;
                    if(!have_ref) {
                        ref = keys.key_a[s];
                        have_ref = true;
                    } else if(memcmp(keys.key_a[s].data, ref.data, 6) != 0) {
                        same = false;
                    }
                }
            }
            static_key = (found >= 2 && same);
        }

        /* Fudan backdoor probe: a normal card would never key on A396EFA4E24F,
         * so a successful auth is a strong "backdoored clone silicon" signal. */
        bool fudan = false;
        {
            MfClassicKey bk;
            memcpy(bk.data, FUDAN_BACKDOOR, 6);
            MfClassicAuthContext ctx;
            if(mf_classic_poller_sync_auth(app->nfc, 0, &bk, MfClassicKeyTypeA, &ctx) ==
                   MfClassicErrorNone ||
               mf_classic_poller_sync_auth(app->nfc, 0, &bk, MfClassicKeyTypeB, &ctx) ==
                   MfClassicErrorNone)
                fudan = true;
        }

        if(sec0_key >= 0) {
            snprintf(
                detail,
                sizeof(detail),
                "%sKEY %c %02X%02X%02X%02X%02X%02X",
                static_key ? "STATIC " : "DEFAULT ",
                sec0_ktype ? 'B' : 'A',
                DEFAULT_KEYS[sec0_key][0],
                DEFAULT_KEYS[sec0_key][1],
                DEFAULT_KEYS[sec0_key][2],
                DEFAULT_KEYS[sec0_key][3],
                DEFAULT_KEYS[sec0_key][4],
                DEFAULT_KEYS[sec0_key][5]);

            /* FULL DUMP with the recovered default keys, then save a clone .nfc */
            MfClassicData* data = mf_classic_alloc();
            mf_classic_poller_sync_read(app->nfc, &keys, data);
            uint8_t sec_read = 0, keys_found = 0;
            mf_classic_get_read_sectors_and_keys(data, &sec_read, &keys_found);

            char clonefile[40];
            clonefile[0] = '\0';
            if(sec_read > 0) {
                char uc[16] = "card";
                if(len > 0) {
                    int q = 0;
                    for(size_t b = 0; b < len && q < 12; b++)
                        q += snprintf(uc + q, sizeof(uc) - q, "%02X", uid[b]);
                }
                Storage* st = furi_record_open(RECORD_STORAGE);
                storage_common_mkdir(st, "/ext/nfc");
                furi_record_close(RECORD_STORAGE);
                char path[80];
                snprintf(path, sizeof(path), "/ext/nfc/CLONE_%s.nfc", uc);
                NfcDevice* dev = nfc_device_alloc();
                nfc_device_set_data(dev, NfcProtocolMfClassic, (const NfcDeviceData*)data);
                if(nfc_device_save(dev, path))
                    snprintf(clonefile, sizeof(clonefile), "CLONE_%s.nfc", uc);
                nfc_device_free(dev);
            }
            mf_classic_free(data);

            if(sec_read >= sectors && clonefile[0]) {
                snprintf(proof_line, sizeof(proof_line), "DUMP %u/%u -> %s", sec_read, sectors, clonefile);
                snprintf(
                    extra,
                    sizeof(extra),
                    "%sfull card dumped; clone in /ext/nfc.",
                    static_key ? "STATIC KEY (clone-once/open-all)! " : "CONFIRMED: ");
            } else if(sec_read > 0) {
                snprintf(proof_line, sizeof(proof_line), "DUMP %u/%u sectors (default keys)", sec_read, sectors);
                snprintf(extra, sizeof(extra), "Partial %u/%u; rest need nested attack (stock NFC app).", sec_read, sectors);
            } else {
                snprintf(proof_line, sizeof(proof_line), "sector0 default key");
                snprintf(extra, sizeof(extra), "CONFIRMED: sector 0 default key (read blocked).");
            }
        } else {
            snprintf(detail, sizeof(detail), "no default key (Crypto1 still broken)");
            snprintf(extra, sizeof(extra), "Crypto1 broken via nested/hardnested (keys not default).");
        }

        if(fudan) {
            snprintf(detail, sizeof(detail), "FUDAN backdoor A396EFA4E24F");
            snprintf(
                extra,
                sizeof(extra),
                "BACKDOORED clone silicon: all keys recoverable (eprint 2024/1275).");
        }
    } else if(sak & 0x20) {
        DesfireProbe pr;
        if(desfire_probe(app, &pr)) {
            bool secure = true;
            switch(pr.version.hw_major) {
            case 0x00:
                snprintf(type, sizeof(type), "DESFire orig");
                snprintf(detail, sizeof(detail), "MF3ICD40 3DES side-channel");
                secure = false;
                break;
            case 0x01: snprintf(type, sizeof(type), "DESFire EV1"); break;
            case 0x08: snprintf(type, sizeof(type), "DESFireLight"); break;
            case 0x12: snprintf(type, sizeof(type), "DESFire EV2"); break;
            case 0x30:
            case 0x33: snprintf(type, sizeof(type), "DESFire EV3"); break;
            default: snprintf(type, sizeof(type), "DESFire EVx"); break;
            }
            /* CONFIG/EXPOSURE audit (unauthenticated) */
            bool weakcfg = pr.have_settings &&
                           (pr.settings.is_free_directory_list || pr.settings.is_free_create_delete);
            if(!secure) {
                snprintf(verdict, sizeof(verdict), "BROKEN");
                snprintf(extra, sizeof(extra), "Original DESFire 3DES: side-channel key extraction (lab).");
            } else if(weakcfg) {
                snprintf(verdict, sizeof(verdict), "WEAK-CFG");
                snprintf(detail, sizeof(detail), "AES ok; weak config");
                snprintf(extra, sizeof(extra), "WEAK CONFIG: free dir-list/create without auth.");
            } else {
                snprintf(verdict, sizeof(verdict), "SECURE");
                snprintf(detail, sizeof(detail), "AES-128, no public break");
            }
            /* PROOF: the actual config bytes read off the card without a key */
            if(pr.have_settings) {
                snprintf(
                    proof_line,
                    sizeof(proof_line),
                    "cfg mkChg=%d dirList=%d crDel=%d kv0=%d",
                    pr.settings.is_master_key_changeable ? 1 : 0,
                    pr.settings.is_free_directory_list ? 1 : 0,
                    pr.settings.is_free_create_delete ? 1 : 0,
                    pr.have_kv ? (int)pr.key_ver : -1);
            }
        } else {
            snprintf(type, sizeof(type), "Type-4");
            snprintf(verdict, sizeof(verdict), "UNK");
            snprintf(detail, sizeof(detail), "ISO14443-4 (EMV/JCOP/SL3?) not resolved");
        }
    } else if(sak == 0x00 && d->atqa[0] == 0x44) {
        snprintf(type, sizeof(type), "UL/NTAG");
        snprintf(verdict, sizeof(verdict), "CLONE");
        /* ACTIVE: read a user data page (4) with no authentication */
        MfUltralightPage pg;
        if(mf_ultralight_poller_sync_read_page(app->nfc, 4, &pg) == MfUltralightErrorNone) {
            snprintf(detail, sizeof(detail), "user pages read w/o auth");
            snprintf(
                proof_line,
                sizeof(proof_line),
                "PROOF pg4:%02X%02X%02X%02X",
                pg.data[0],
                pg.data[1],
                pg.data[2],
                pg.data[3]);
            snprintf(extra, sizeof(extra), "CONFIRMED: memory readable w/o auth; cloneable.");
        } else {
            snprintf(detail, sizeof(detail), "pages read-protected");
            snprintf(verdict, sizeof(verdict), "UNK");
            snprintf(extra, sizeof(extra), "Read-protected: possibly secure UL-AES/NTAG-424.");
        }
    } else {
        snprintf(type, sizeof(type), "ISO14443-3A");
        snprintf(verdict, sizeof(verdict), "CLONE");
        snprintf(detail, sizeof(detail), "plain UID, no crypto");
    }

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    snprintf(app->r_type, sizeof(app->r_type), "%s", type);
    snprintf(app->r_verdict, sizeof(app->r_verdict), "%s", verdict);
    snprintf(app->r_detail, sizeof(app->r_detail), "%s", detail);
    snprintf(app->r_proof, sizeof(app->r_proof), "%s", proof_line);
    furi_mutex_release(app->mutex);

    write_report(app, "HF 13.56MHz", uidhex, extra);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->scene = SceneResult;
    furi_mutex_release(app->mutex);
    iso14443_3a_free(d);
}

/* ---- LF audit ---- */
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

static void audit_lf(App* app) {
    LfProbe p = {0};
    p.sem = furi_semaphore_alloc(1, 0);
    p.dict = app->dict;
    lfrfid_worker_start_thread(app->lf_worker);
    lfrfid_worker_read_start(app->lf_worker, LFRFIDWorkerReadTypeAuto, lf_read_cb, &p);
    bool ok = (furi_semaphore_acquire(p.sem, furi_ms_to_ticks(3000)) == FuriStatusOk);
    lfrfid_worker_stop(app->lf_worker);
    lfrfid_worker_stop_thread(app->lf_worker);
    furi_semaphore_free(p.sem);

    if(!(ok && p.ok)) {
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        snprintf(app->r_type, sizeof(app->r_type), "no LF card");
        snprintf(app->r_verdict, sizeof(app->r_verdict), "-");
        snprintf(app->r_detail, sizeof(app->r_detail), "no 125kHz decode");
        app->r_proof[0] = '\0';
        app->r_file[0] = '\0';
        app->scene = SceneResult;
        furi_mutex_release(app->mutex);
        return;
    }

    const char* name = protocol_dict_get_name(app->dict, p.proto);
    char idhex[24] = {0};
    int hp = 0;
    for(size_t i = 0; i < p.dsize && hp < (int)sizeof(idhex) - 2; i++)
        hp += snprintf(idhex + hp, sizeof(idhex) - hp, "%02X", p.data[i]);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    snprintf(app->r_type, sizeof(app->r_type), "%s", name ? name : "LF");
    snprintf(app->r_verdict, sizeof(app->r_verdict), "CLONE");
    snprintf(app->r_detail, sizeof(app->r_detail), "static ID read = cloneable to T5577");
    snprintf(app->r_proof, sizeof(app->r_proof), "PROOF id:%s", idhex);
    furi_mutex_release(app->mutex);

    write_report(app, "LF 125kHz", idhex, "CONFIRMED: no LF crypto; migrate to 13.56MHz AES.");

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->scene = SceneResult;
    furi_mutex_release(app->mutex);
}

/* ---- offline audit of a saved .nfc file ---- */
static void do_load_saved(App* app) {
    FuriString* path = furi_string_alloc();
    furi_string_set(path, NFC_DIR);
    DialogsFileBrowserOptions opts;
    dialog_file_browser_set_basic_options(&opts, ".nfc", NULL);
    opts.base_path = NFC_DIR;
    bool picked = dialog_file_browser_show(app->dialogs, path, path, &opts);
    if(!picked) {
        furi_string_free(path);
        return;
    }

    NfcDevice* dev = nfc_device_alloc();
    bool ok = nfc_device_load(dev, furi_string_get_cstr(path));

    char type[24] = "?", verdict[16] = "UNK", detail[48] = "", proof[64] = "", extra[96] = "";
    char uidhex[24] = "-";
    if(ok) {
        NfcProtocol proto = nfc_device_get_protocol(dev);
        const char* pn = nfc_device_get_protocol_name(proto);
        snprintf(type, sizeof(type), "%s", pn ? pn : "?");
        size_t ul = 0;
        const uint8_t* uid = nfc_device_get_uid(dev, &ul);
        int hp = 0;
        for(size_t i = 0; i < ul && hp < (int)sizeof(uidhex) - 3; i++)
            hp += snprintf(uidhex + hp, sizeof(uidhex) - hp, "%02X ", uid[i]);
        if(hp > 0) uidhex[hp - 1] = '\0';

        if(proto == NfcProtocolMfClassic) {
            snprintf(verdict, sizeof(verdict), "BROKEN");
            const MfClassicData* d = (const MfClassicData*)nfc_device_get_data(dev, proto);
            uint8_t sectors = mf_classic_get_total_sectors_num(d->type);
            int def = 0;
            for(uint8_t s = 0; s < sectors; s++) {
                bool ka = d->key_a_mask & (1ULL << s);
                bool kb = d->key_b_mask & (1ULL << s);
                const MfClassicSectorTrailer* st = mf_classic_get_sector_trailer_by_sector(d, s);
                bool isdef = false;
                for(int i = 0; i < N_DEFAULT_KEYS; i++) {
                    if(ka && memcmp(st->key_a.data, DEFAULT_KEYS[i], 6) == 0) isdef = true;
                    if(kb && memcmp(st->key_b.data, DEFAULT_KEYS[i], 6) == 0) isdef = true;
                }
                if(isdef) def++;
            }
            snprintf(detail, sizeof(detail), "saved dump; keys in file");
            snprintf(proof, sizeof(proof), "default keys %d/%u sectors", def, sectors);
            snprintf(extra, sizeof(extra), "Offline: %d/%u sectors use a default key.", def, sectors);
        } else if(proto == NfcProtocolMfUltralight) {
            snprintf(verdict, sizeof(verdict), "CLONE");
            snprintf(detail, sizeof(detail), "UL/NTAG dump");
        } else if(proto == NfcProtocolIso14443_3a) {
            snprintf(verdict, sizeof(verdict), "CLONE");
            snprintf(detail, sizeof(detail), "UID card");
        } else if(proto == NfcProtocolMfDesfire) {
            snprintf(verdict, sizeof(verdict), "SECURE");
            snprintf(detail, sizeof(detail), "DESFire (AES)");
        }
    } else {
        snprintf(type, sizeof(type), "load failed");
    }
    nfc_device_free(dev);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    snprintf(app->r_type, sizeof(app->r_type), "%s", type);
    snprintf(app->r_verdict, sizeof(app->r_verdict), "%s", verdict);
    snprintf(app->r_detail, sizeof(app->r_detail), "%s", detail);
    snprintf(app->r_proof, sizeof(app->r_proof), "%s", proof);
    app->scene = SceneResult;
    furi_mutex_release(app->mutex);

    if(ok) write_report(app, "FILE (offline)", uidhex, extra);
    furi_string_free(path);
}

/* ---- report viewer ---- */
static void list_reports(App* app) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    app->report_count = 0;
    app->report_sel = 0;
    File* dir = storage_file_alloc(storage);
    if(storage_dir_open(dir, REPORT_DIR)) {
        FileInfo info;
        char name[40];
        while(app->report_count < 40 && storage_dir_read(dir, &info, name, sizeof(name))) {
            if(!file_info_is_dir(&info) && name[0]) {
                strncpy(app->reports[app->report_count], name, sizeof(app->reports[0]) - 1);
                app->reports[app->report_count][sizeof(app->reports[0]) - 1] = '\0';
                app->report_count++;
            }
        }
        storage_dir_close(dir);
    }
    storage_file_free(dir);
    furi_record_close(RECORD_STORAGE);
}

static void load_report(App* app, int idx) {
    app->view_buf[0] = '\0';
    app->view_scroll = 0;
    if(idx < 0 || idx >= app->report_count) return;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(storage);
    char path[80];
    snprintf(path, sizeof(path), "%s/%s", REPORT_DIR, app->reports[idx]);
    if(storage_file_open(f, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        size_t n = storage_file_read(f, app->view_buf, sizeof(app->view_buf) - 1);
        app->view_buf[n] = '\0';
        storage_file_close(f);
    }
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
}

/* -------------------------- GUI -------------------------- */

static const char* const kMenu[] = {
    "Audit HF card",
    "Audit LF card",
    "Load .nfc (offline)",
    "View reports"};
#define MENU_COUNT ((int)(sizeof(kMenu) / sizeof(kMenu[0])))

static void draw_cb(Canvas* c, void* ctx) {
    App* app = ctx;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    canvas_clear(c);
    canvas_set_color(c, ColorBlack);

    if(app->scene == SceneAuth) {
        canvas_set_font(c, FontPrimary);
        canvas_draw_str(c, 2, 11, "Card Audit");
        canvas_set_font(c, FontSecondary);
        canvas_draw_str(c, 2, 24, "AUTHORIZED USE ONLY.");
        canvas_draw_str(c, 2, 34, "Only what you own or");
        canvas_draw_str(c, 2, 44, "authorized to test.");
        canvas_draw_str(c, 2, 62, "OK confirm  Back exit");
    } else if(app->scene == SceneMenu) {
        canvas_set_font(c, FontPrimary);
        canvas_draw_str(c, 2, 11, "Card Audit");
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
        canvas_draw_str(c, 2, 62, "OK select   Back exit");
    } else if(app->scene == SceneBusy) {
        canvas_set_font(c, FontPrimary);
        canvas_draw_str(c, 2, 20, "Auditing...");
        canvas_set_font(c, FontSecondary);
        canvas_draw_str(c, 2, 36, "hold card to Flipper,");
        canvas_draw_str(c, 2, 46, "keep still");
    } else if(app->scene == SceneResult) {
        char buf[64];
        canvas_set_font(c, FontPrimary);
        snprintf(buf, sizeof(buf), "%s  %s", app->r_type, app->r_verdict);
        canvas_draw_str(c, 2, 11, buf);
        canvas_set_font(c, FontSecondary);
        canvas_draw_str(c, 2, 23, app->r_detail);
        if(app->r_proof[0]) canvas_draw_str(c, 2, 34, app->r_proof);
        if(app->r_file[0]) {
            snprintf(buf, sizeof(buf), "saved: %s", app->r_file);
            canvas_draw_str(c, 2, 46, buf);
        } else {
            canvas_draw_str(c, 2, 46, "(no report)");
        }
        canvas_draw_str(c, 2, 62, "OK menu   Back exit");
    } else if(app->scene == SceneReportList) {
        canvas_set_font(c, FontPrimary);
        canvas_draw_str(c, 2, 11, "Reports");
        canvas_set_font(c, FontSecondary);
        if(app->report_count == 0) {
            canvas_draw_str(c, 2, 30, "(none yet)");
        } else {
            int start = app->report_sel - 2;
            if(start < 0) start = 0;
            for(int i = 0; i < 5 && start + i < app->report_count; i++) {
                int idx = start + i;
                int y = 22 + i * 9;
                if(idx == app->report_sel) {
                    canvas_draw_box(c, 0, y - 8, 128, 9);
                    canvas_set_color(c, ColorWhite);
                    canvas_draw_str(c, 2, y, app->reports[idx]);
                    canvas_set_color(c, ColorBlack);
                } else {
                    canvas_draw_str(c, 2, y, app->reports[idx]);
                }
            }
        }
        canvas_draw_str(c, 2, 63, "OK view   Back menu");
    } else { /* SceneReportView */
        canvas_set_font(c, FontSecondary);
        const char* p = app->view_buf;
        int line = 0, y = 9;
        while(*p) {
            const char* nl = strchr(p, '\n');
            int len = nl ? (int)(nl - p) : (int)strlen(p);
            if(line >= app->view_scroll && line < app->view_scroll + 6) {
                char tmp[36];
                int L = len < 35 ? len : 35;
                memcpy(tmp, p, L);
                tmp[L] = '\0';
                canvas_draw_str(c, 2, y, tmp);
                y += 9;
            }
            line++;
            if(!nl) break;
            p = nl + 1;
        }
        canvas_draw_str(c, 2, 63, "^v scroll  Back list");
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
    app->scene = SceneAuth;

    app->dialogs = furi_record_open(RECORD_DIALOGS);
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
    furi_record_close(RECORD_DIALOGS);
    furi_message_queue_free(app->event_queue);
    furi_mutex_free(app->mutex);
    free(app);
}

int32_t card_audit_app(void* p) {
    UNUSED(p);
    App* app = app_alloc();

    bool running = true;
    AppEvent event;
    while(running) {
        if(furi_message_queue_get(app->event_queue, &event, FuriWaitForever) != FuriStatusOk)
            continue;

        int action = 0; /* 1 = audit HF, 2 = audit LF */
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        if(event.type == EvInput) {
            InputEvent* in = &event.input;
            bool press = (in->type == InputTypeShort);
            if(app->scene == SceneAuth) {
                if(press && in->key == InputKeyOk)
                    app->scene = SceneMenu;
                else if(press && in->key == InputKeyBack)
                    running = false;
            } else if(app->scene == SceneMenu) {
                if(press && in->key == InputKeyUp)
                    app->menu_index = (app->menu_index + MENU_COUNT - 1) % MENU_COUNT;
                else if(press && in->key == InputKeyDown)
                    app->menu_index = (app->menu_index + 1) % MENU_COUNT;
                else if(press && in->key == InputKeyOk) {
                    if(app->menu_index == 0) {
                        app->scene = SceneBusy;
                        action = 1; /* audit HF */
                    } else if(app->menu_index == 1) {
                        app->scene = SceneBusy;
                        action = 2; /* audit LF */
                    } else if(app->menu_index == 2) {
                        action = 5; /* load saved .nfc (offline) */
                    } else {
                        action = 3; /* list reports */
                    }
                } else if(press && in->key == InputKeyBack)
                    running = false;
            } else if(app->scene == SceneResult) {
                if(press && in->key == InputKeyOk)
                    app->scene = SceneMenu;
                else if(press && in->key == InputKeyBack)
                    running = false;
            } else if(app->scene == SceneReportList) {
                if(app->report_count > 0 && press && in->key == InputKeyUp)
                    app->report_sel = (app->report_sel + app->report_count - 1) % app->report_count;
                else if(app->report_count > 0 && press && in->key == InputKeyDown)
                    app->report_sel = (app->report_sel + 1) % app->report_count;
                else if(app->report_count > 0 && press && in->key == InputKeyOk)
                    action = 4; /* load + view selected */
                else if(press && in->key == InputKeyBack)
                    app->scene = SceneMenu;
            } else if(app->scene == SceneReportView) {
                bool ud = (press || in->type == InputTypeRepeat);
                if(ud && in->key == InputKeyDown)
                    app->view_scroll++;
                else if(ud && in->key == InputKeyUp) {
                    if(app->view_scroll > 0) app->view_scroll--;
                } else if(press && in->key == InputKeyBack)
                    app->scene = SceneReportList;
            }
        }
        furi_mutex_release(app->mutex);

        if(action == 1) {
            view_port_update(app->view_port); /* show Busy */
            audit_hf(app);
        } else if(action == 2) {
            view_port_update(app->view_port);
            audit_lf(app);
        } else if(action == 3) {
            list_reports(app);
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            app->scene = SceneReportList;
            furi_mutex_release(app->mutex);
        } else if(action == 4) {
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            int sel = app->report_sel;
            furi_mutex_release(app->mutex);
            load_report(app, sel);
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            app->scene = SceneReportView;
            furi_mutex_release(app->mutex);
        } else if(action == 5) {
            do_load_saved(app); /* blocking browser; sets scene to Result */
        }

        view_port_update(app->view_port);
    }

    app_free(app);
    return 0;
}
