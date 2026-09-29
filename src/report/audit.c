
#include "forge/fg_audit.h"
#include "forge/fg_json.h"
#include "forge/fg_platform.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct fg_audit {
    FILE     *fp;
    char      path[4096];
    char      session_id[33];
    char      operator_name[96];
    char      case_id[96];
    char      started_at[32];
    uint8_t   key[32];
    size_t    keylen;
    uint8_t   head[32];
    char      head_hex[65];
    uint64_t  count;
    fg_mutex *lock;
};

const char *fg_event_name(fg_event e)
{
    switch (e) {
    case FG_EV_SESSION_START: return "session.start";
    case FG_EV_SESSION_END:   return "session.end";
    case FG_EV_DEVICE_ENUM:   return "device.enumerate";
    case FG_EV_ERASE_BEGIN:   return "erase.begin";
    case FG_EV_ERASE_PASS:    return "erase.pass";
    case FG_EV_ERASE_VERIFY:  return "erase.verify";
    case FG_EV_ERASE_END:     return "erase.end";
    case FG_EV_FILE_ERASE:    return "file.erase";
    case FG_EV_FREESPACE:     return "freespace.wipe";
    case FG_EV_SCAN_BEGIN:    return "scan.begin";
    case FG_EV_SCAN_FILE:     return "scan.file";
    case FG_EV_SCAN_END:      return "scan.end";
    case FG_EV_CUSTODY:       return "custody";
    case FG_EV_ERROR:         return "error";
    case FG_EV_REFUSED:       return "refused";
    }
    return "unknown";
}

void fg_make_id(char out[33])
{
    uint8_t r[16];
    if (fg_os_random(r, sizeof r) != FG_OK) {
        uint64_t t = fg_now_ms();
        size_t i;
        for (i = 0; i < sizeof r; i++) r[i] = (uint8_t)(t >> ((i % 8) * 8)) ^ (uint8_t)(i * 37);
    }
    fg_hex_encode(r, 16, out);
}

/* The canonical form hashed for each record. Keeping it separate from the
 * rendered JSON means whitespace or key-order changes cannot silently alter
 * what was signed. Every attributable field is covered - the operator name and
 * case identifier especially, because "who did this" is the part of a forensic
 * log an attacker most wants to change. */
static void canon(fg_buf *b, uint64_t seq, const char *ts, const char *session,
                  const char *oper, const char *casei, const char *ev,
                  int status, const char *subject, const char *detail)
{
    fg_buf_printf(b, "%llu\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%d\x1f%s\x1f%s",
                  (unsigned long long)seq, ts, session ? session : "",
                  oper ? oper : "", casei ? casei : "", ev, status,
                  subject ? subject : "", detail ? detail : "");
}

static void chain_step(fg_audit *a, const fg_buf *canonical)
{
    fg_sha256 c;
    fg_sha256_init(&c);
    fg_sha256_update(&c, a->head, sizeof a->head);
    fg_sha256_update(&c, canonical->data, canonical->len);
    fg_sha256_final(&c, a->head);
    fg_hex_encode(a->head, 32, a->head_hex);
}

fg_status fg_audit_open(fg_audit **out, const char *log_path,
                        const uint8_t *key, size_t keylen,
                        const char *operator_name, const char *case_id)
{
    fg_audit *a;
    if (!out || !log_path) return FG_ERR_INVALID;
    *out = NULL;
    a = (fg_audit *)fg_xcalloc(1, sizeof *a);
    if (!a) return FG_ERR_NOMEM;

    snprintf(a->path, sizeof a->path, "%s", log_path);
    a->fp = fopen(log_path, "ab");
    if (!a->fp) { free(a); return FG_ERR_PERM; }
    fg_mutex_create(&a->lock);

    if (key && keylen) {
        a->keylen = FG_MIN(keylen, sizeof a->key);
        memcpy(a->key, key, a->keylen);
    } else {
        fg_os_random(a->key, sizeof a->key);
        a->keylen = sizeof a->key;
    }
    fg_make_id(a->session_id);
    fg_iso8601_utc(a->started_at, sizeof a->started_at);
    snprintf(a->operator_name, sizeof a->operator_name, "%s",
             operator_name ? operator_name : "unknown");
    snprintf(a->case_id, sizeof a->case_id, "%s", case_id ? case_id : "");
    memset(a->head, 0, sizeof a->head);
    fg_hex_encode(a->head, 32, a->head_hex);

    {
        char host[128], user[128], os[160];
        fg_buf d;
        fg_hostname(host, sizeof host);
        fg_username(user, sizeof user);
        fg_os_describe(os, sizeof os);
        fg_buf_init(&d);
        fg_buf_printf(&d, "\"product\":\"%s %s\",\"host\":\"", FG_PRODUCT, FG_VERSION_STR);
        fg_json_escape(&d, host);
        fg_buf_puts(&d, "\",\"user\":\"");
        fg_json_escape(&d, user);
        fg_buf_puts(&d, "\",\"os\":\"");
        fg_json_escape(&d, os);
        fg_buf_printf(&d, "\",\"elevated\":%s", fg_is_elevated() ? "true" : "false");
        *out = a;
        fg_audit_event(a, FG_EV_SESSION_START, FG_OK, a->session_id, d.data);
        fg_buf_free(&d);
    }
    return FG_OK;
}

fg_status fg_audit_event(fg_audit *a, fg_event e, fg_status st,
                         const char *subject, const char *detail_json)
{
    char ts[32];
    fg_buf c;
    uint64_t seq;

    if (!a) return FG_ERR_INVALID;
    fg_mutex_lock(a->lock);
    seq = ++a->count;
    fg_iso8601_utc(ts, sizeof ts);
    fg_buf_init(&c);
    canon(&c, seq, ts, a->session_id, a->operator_name, a->case_id,
          fg_event_name(e), (int)st, subject, detail_json);
    chain_step(a, &c);
    fg_buf_free(&c);

    fprintf(a->fp,
            "{\"seq\":%llu,\"ts\":\"%s\",\"session\":\"%s\",\"event\":\"%s\","
            "\"status\":%d,\"operator\":\"%s\",\"case\":\"%s\",\"subject\":\"",
            (unsigned long long)seq, ts, a->session_id, fg_event_name(e), (int)st,
            a->operator_name, a->case_id);
    {
        fg_buf esc;
        fg_buf_init(&esc);
        fg_json_escape(&esc, subject ? subject : "");
        fwrite(esc.data ? esc.data : "", 1, esc.len, a->fp);
        fg_buf_free(&esc);
    }
    fprintf(a->fp, "\",\"detail\":{%s},\"prev\":\"%s\"}\n",
            detail_json ? detail_json : "", a->head_hex);
    fflush(a->fp);
    fg_mutex_unlock(a->lock);
    return FG_OK;
}

fg_status fg_audit_eventf(fg_audit *a, fg_event e, fg_status st,
                          const char *subject, const char *fmt, ...)
{
    fg_buf b;
    va_list ap;
    int n;
    fg_status r;
    fg_buf_init(&b);
    va_start(ap, fmt);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n > 0 && fg_buf_reserve(&b, (size_t)n + 1) == FG_OK) {
        va_start(ap, fmt);
        vsnprintf(b.data, (size_t)n + 1, fmt, ap);
        va_end(ap);
        b.len = (size_t)n;
    }
    r = fg_audit_event(a, e, st, subject, b.data ? b.data : "");
    fg_buf_free(&b);
    return r;
}

void fg_audit_close(fg_audit *a)
{
    uint8_t mac[32];
    char machex[65];
    if (!a) return;
    fg_audit_eventf(a, FG_EV_SESSION_END, FG_OK, a->session_id,
                    "\"records\":%llu", (unsigned long long)a->count);
    fg_hmac_buf(a->key, a->keylen, a->head, sizeof a->head, mac);
    fg_hex_encode(mac, 32, machex);
    fprintf(a->fp, "{\"seal\":\"%s\",\"head\":\"%s\",\"records\":%llu,"
                   "\"session\":\"%s\",\"alg\":\"HMAC-SHA256\"}\n",
            machex, a->head_hex, (unsigned long long)a->count, a->session_id);
    fflush(a->fp);
    fclose(a->fp);
    fg_secure_zero(a->key, sizeof a->key);
    fg_mutex_destroy(a->lock);
    free(a);
}

const char *fg_audit_session_id(const fg_audit *a) { return a ? a->session_id : ""; }
uint64_t    fg_audit_record_count(const fg_audit *a) { return a ? a->count : 0; }
const char *fg_audit_head_hash(const fg_audit *a) { return a ? a->head_hex : ""; }

/* -------------------------------------------------------------------------- */
/*  verification                                                              */
/* -------------------------------------------------------------------------- */
static char *json_str_field(const char *line, const char *key, char *out, size_t outsz)
{
    char pat[64];
    const char *p;
    size_t i = 0;
    snprintf(pat, sizeof pat, "\"%s\":\"", key);
    p = strstr(line, pat);
    out[0] = '\0';
    if (!p) return NULL;
    p += strlen(pat);
    while (*p && *p != '"' && i + 1 < outsz) {
        if (*p == '\\' && p[1]) {
            /* undo the escapes the writer produced */
            p++;
            switch (*p) {
            case 'n': out[i++] = '\n'; break;
            case 't': out[i++] = '\t'; break;
            case 'r': out[i++] = '\r'; break;
            case 'b': out[i++] = '\b'; break;
            case 'f': out[i++] = '\f'; break;
            case 'u': {
                unsigned cp = 0;
                int k;
                for (k = 1; k <= 4 && p[k]; k++) {
                    char ch = p[k];
                    cp <<= 4;
                    if (ch >= '0' && ch <= '9') cp |= (unsigned)(ch - '0');
                    else if (ch >= 'a' && ch <= 'f') cp |= (unsigned)(ch - 'a' + 10);
                    else if (ch >= 'A' && ch <= 'F') cp |= (unsigned)(ch - 'A' + 10);
                }
                p += 4;
                out[i++] = (char)(cp & 0x7F);
                break;
            }
            default: out[i++] = *p;
            }
            p++;
        } else {
            out[i++] = *p++;
        }
    }
    out[i] = '\0';
    return out;
}

static const char *json_obj_field(const char *line, const char *key)
{
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\":{", key);
    {
        const char *p = strstr(line, pat);
        return p ? p + strlen(pat) : NULL;
    }
}

fg_status fg_audit_verify_file(const char *log_path,
                               const uint8_t *key, size_t keylen,
                               fg_audit_verify *out)
{
    FILE *f;
    char *line;
    size_t cap = 1 << 16;
    uint8_t head[32];
    char head_hex[65];
    uint64_t seq = 0, total = 0;
    int seals_seen = 0, seals_ok = 0, seals_checked = 0;

    if (!log_path || !out) return FG_ERR_INVALID;
    memset(out, 0, sizeof *out);
    out->chain_ok = 1;

    f = fopen(log_path, "rb");
    if (!f) return FG_ERR_NOTFOUND;
    line = (char *)malloc(cap);
    if (!line) { fclose(f); return FG_ERR_NOMEM; }
    memset(head, 0, sizeof head);
    fg_hex_encode(head, 32, head_hex);

    /* A log file accumulates one independent hash chain per session, each
     * terminated by its own seal, because sessions append to the same file. */
    while (fgets(line, (int)cap, f)) {
        char ts[32], ev[64], subj[1024], prev[80];
        char sess[33], oper[96], casei[96];
        const char *detail;
        int status = 0;
        fg_buf c;
        uint64_t got_seq = 0;

        if (strstr(line, "\"seal\":\"")) {
            char seal_hex[65] = "", seal_head[65] = "";
            json_str_field(line, "seal", seal_hex, sizeof seal_hex);
            json_str_field(line, "head", seal_head, sizeof seal_head);
            seals_seen++;
            if (strcmp(seal_head, head_hex) && out->chain_ok) {
                out->chain_ok = 0;
                out->first_bad_record = total;
                snprintf(out->message, sizeof out->message,
                         "the sealed head hash of session %llu does not match "
                         "the recomputed chain", (unsigned long long)out->sessions);
            }
            if (key && keylen) {
                uint8_t mac[32], want[32];
                fg_hmac_buf(key, keylen, head, sizeof head, mac);
                memset(want, 0, sizeof want);
                fg_hex_decode(seal_hex, want, sizeof want);
                seals_checked++;
                if (fg_ct_equal(mac, want, sizeof mac)) seals_ok++;
            }
            /* Keep this session's sealed head as the reported one, then start
             * the next session's chain from zero. */
            snprintf(out->head_hash, sizeof out->head_hash, "%s", head_hex);
            memset(head, 0, sizeof head);
            fg_hex_encode(head, 32, head_hex);
            seq = 0;
            continue;
        }
        {
            const char *p = strstr(line, "\"seq\":");
            if (!p) continue;
            got_seq = strtoull(p + 6, NULL, 10);
        }
        if (got_seq == 1 && seq != 0) {
            /* An unsealed session ended (the tool was interrupted) and a new
             * one begins. Not tampering - start a fresh chain. */
            memset(head, 0, sizeof head);
            fg_hex_encode(head, 32, head_hex);
            seq = 0;
        }
        if (got_seq == 1) out->sessions++;
        seq++;
        total++;
        if (got_seq != seq && out->chain_ok) {
            out->chain_ok = 0;
            out->first_bad_record = total;
            snprintf(out->message, sizeof out->message,
                     "record %llu is out of sequence (file says %llu): records "
                     "were reordered or removed",
                     (unsigned long long)seq, (unsigned long long)got_seq);
        }

        json_str_field(line, "ts", ts, sizeof ts);
        json_str_field(line, "event", ev, sizeof ev);
        json_str_field(line, "subject", subj, sizeof subj);
        json_str_field(line, "prev", prev, sizeof prev);
        json_str_field(line, "session", sess, sizeof sess);
        json_str_field(line, "operator", oper, sizeof oper);
        json_str_field(line, "case", casei, sizeof casei);
        {
            const char *p = strstr(line, "\"status\":");
            if (p) status = atoi(p + 9);
        }
        detail = json_obj_field(line, "detail");

        if (seq == 1) {
            /* Report the most recent session's identity. */
            snprintf(out->session_id, sizeof out->session_id, "%s", sess);
            snprintf(out->started_at, sizeof out->started_at, "%s", ts);
            snprintf(out->operator_name, sizeof out->operator_name, "%s", oper);
            snprintf(out->case_id, sizeof out->case_id, "%s", casei);
        }

        fg_buf_init(&c);
        {
            /* detail runs to the matching close brace before ",\"prev\"" */
            char dbuf[8192] = "";
            if (detail) {
                const char *e = strstr(detail, "},\"prev\":");
                size_t n = e ? (size_t)(e - detail) : 0;
                if (n && n < sizeof dbuf) { memcpy(dbuf, detail, n); dbuf[n] = '\0'; }
            }
            canon(&c, seq, ts, sess, oper, casei, ev, status, subj, dbuf);
        }
        {
            fg_sha256 sh;
            fg_sha256_init(&sh);
            fg_sha256_update(&sh, head, sizeof head);
            fg_sha256_update(&sh, c.data, c.len);
            fg_sha256_final(&sh, head);
            fg_hex_encode(head, 32, head_hex);
        }
        fg_buf_free(&c);

        if (strcmp(prev, head_hex) && out->chain_ok) {
            out->chain_ok = 0;
            out->first_bad_record = total;
            snprintf(out->message, sizeof out->message,
                     "hash mismatch at record %llu of session %llu: this record "
                     "or an earlier one in the same session was altered",
                     (unsigned long long)seq, (unsigned long long)out->sessions);
        }
    }
    fclose(f);
    free(line);

    out->records = total;
    /* An unsealed trailing session (the tool was interrupted) reports its own
     * running head; a clean log keeps the last seal's head from above. */
    if (seq) snprintf(out->head_hash, sizeof out->head_hash, "%s", head_hex);

    if (seals_checked) {
        out->seal_checked = 1;
        out->seal_ok = (seals_ok == seals_checked);
        /* A broken chain is the more specific finding; do not mask it. */
        if (!out->seal_ok && out->chain_ok)
            snprintf(out->message, sizeof out->message,
                     "%d of %d HMAC seal(s) did not verify under the supplied key",
                     seals_checked - seals_ok, seals_checked);
    }

    if (out->chain_ok && !out->message[0])
        snprintf(out->message, sizeof out->message,
                 "hash chain intact across %llu record(s) in %llu session(s)%s",
                 (unsigned long long)out->records, (unsigned long long)out->sessions,
                 out->seal_checked ? (out->seal_ok ? "; all HMAC seals verified"
                                                   : "; HMAC seal INVALID") :
                 (seals_seen ? "; seals present but no key supplied" : ""));
    return (out->chain_ok && (!out->seal_checked || out->seal_ok)) ? FG_OK : FG_ERR_VERIFY;
}
