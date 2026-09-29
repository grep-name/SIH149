/* kv_audit.h - Reporting and Audit Management System.
 *
 * The audit log is an append-only hash chain: record N stores the SHA-256 of
 * (prev_hash || canonical_record_N), so altering or deleting any past record
 * breaks every hash after it. The chain is additionally sealed with an
 * HMAC-SHA256 under a session key so an attacker who can rewrite the whole
 * file still cannot forge a valid seal without the key.
 */
#ifndef KV_AUDIT_H
#define KV_AUDIT_H

#include "kv_common.h"
#include "kv_crypto.h"
#include "kv_erase.h"
#include "kv_carve.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    KV_EV_SESSION_START, KV_EV_SESSION_END, KV_EV_DEVICE_ENUM,
    KV_EV_ERASE_BEGIN, KV_EV_ERASE_PASS, KV_EV_ERASE_VERIFY, KV_EV_ERASE_END,
    KV_EV_FILE_ERASE, KV_EV_FREESPACE,
    KV_EV_SCAN_BEGIN, KV_EV_SCAN_FILE, KV_EV_SCAN_END,
    KV_EV_CUSTODY, KV_EV_ERROR, KV_EV_REFUSED
} kv_event;

const char *kv_event_name(kv_event e);

typedef struct kv_audit kv_audit;

/* `key` seals the chain; pass NULL to derive a random session key which is
 * printed once at session start so the operator can archive it separately. */
kv_status kv_audit_open(kv_audit **out, const char *log_path,
                        const uint8_t *key, size_t keylen,
                        const char *operator_name, const char *case_id);
void      kv_audit_close(kv_audit *a);

/* Append one event. `detail_json` must be a JSON object body without the
 * outer braces, or NULL. */
kv_status kv_audit_event(kv_audit *a, kv_event e, kv_status st,
                         const char *subject, const char *detail_json);
kv_status kv_audit_eventf(kv_audit *a, kv_event e, kv_status st,
                          const char *subject, const char *fmt, ...);

const char *kv_audit_session_id(const kv_audit *a);
uint64_t    kv_audit_record_count(const kv_audit *a);
const char *kv_audit_head_hash(const kv_audit *a);

typedef struct {
    uint64_t records;
    uint64_t sessions;           /* a log accumulates one chain per session   */
    uint64_t first_bad_record;   /* 0 when intact                             */
    int      chain_ok;
    int      seal_ok;
    int      seal_checked;
    char     head_hash[65];
    char     message[256];
    char     session_id[33];
    char     started_at[32];
    char     operator_name[96];
    char     case_id[96];
} kv_audit_verify;

/* Re-walk a log file and prove the chain (and, with a key, the seal). */
kv_status kv_audit_verify_file(const char *log_path,
                               const uint8_t *key, size_t keylen,
                               kv_audit_verify *out);

/* ========================================================================== */
/*  Reports                                                                   */
/* ========================================================================== */

typedef enum { KV_RPT_JSON, KV_RPT_HTML, KV_RPT_CSV, KV_RPT_TEXT } kv_report_fmt;

typedef struct {
    const char *case_id;
    const char *operator_name;
    const char *organisation;
    const char *notes;
    const char *audit_log_path;
    const char *audit_head_hash;
    const char *session_id;
} kv_report_meta;

kv_status kv_report_drive(const kv_drive_result *r, const kv_report_meta *m,
                          kv_report_fmt fmt, const char *out_path);
kv_status kv_report_files(const kv_file_result *r, const kv_report_meta *m,
                          kv_report_fmt fmt, const char *out_path);
kv_status kv_report_scan(const kv_scan_result *r, const kv_report_meta *m,
                         kv_report_fmt fmt, const char *out_path);

/* Serialise to a buffer instead of a file (used by the HTTP API). */
kv_status kv_report_drive_buf(const kv_drive_result *r, const kv_report_meta *m,
                              kv_report_fmt fmt, kv_buf *out);
kv_status kv_report_scan_buf(const kv_scan_result *r, const kv_report_meta *m,
                             kv_report_fmt fmt, kv_buf *out);
kv_status kv_report_files_buf(const kv_file_result *r, const kv_report_meta *m,
                              kv_report_fmt fmt, kv_buf *out);

/* 32-hex-char random identifier used for report_id / session_id. */
void kv_make_id(char out[33]);

#ifdef __cplusplus
}
#endif
#endif /* KV_AUDIT_H */
