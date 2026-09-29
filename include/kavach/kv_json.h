/* kv_json.h - minimal JSON writer and DOM parser (no dependencies).
 * The writer is used for reports and the HTTP API; the parser only has to
 * cope with the small request bodies the dashboard sends.
 */
#ifndef KV_JSON_H
#define KV_JSON_H

#include "kv_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- writer -------------------------------------------------------------- */
typedef struct {
    kv_buf buf;
    int    depth;
    int    need_comma[32];
    int    pretty;
} kv_jw;

void kv_jw_init(kv_jw *w, int pretty);
void kv_jw_obj(kv_jw *w);
void kv_jw_obj_end(kv_jw *w);
void kv_jw_arr(kv_jw *w);
void kv_jw_arr_end(kv_jw *w);
void kv_jw_key(kv_jw *w, const char *k);
void kv_jw_str(kv_jw *w, const char *v);
void kv_jw_i64(kv_jw *w, int64_t v);
void kv_jw_u64(kv_jw *w, uint64_t v);
void kv_jw_dbl(kv_jw *w, double v);
void kv_jw_bool(kv_jw *w, int v);
void kv_jw_null(kv_jw *w);
void kv_jw_raw(kv_jw *w, const char *json);
/* convenience: key + value in one call */
void kv_jw_kstr(kv_jw *w, const char *k, const char *v);
void kv_jw_ku64(kv_jw *w, const char *k, uint64_t v);
void kv_jw_ki64(kv_jw *w, const char *k, int64_t v);
void kv_jw_kdbl(kv_jw *w, const char *k, double v);
void kv_jw_kbool(kv_jw *w, const char *k, int v);
const char *kv_jw_text(kv_jw *w);   /* NUL-terminated, owned by the writer */
size_t kv_jw_len(kv_jw *w);
void kv_jw_free(kv_jw *w);

/* Escape `s` into a JSON string body (without the surrounding quotes). */
void kv_json_escape(kv_buf *b, const char *s);

/* ---- parser -------------------------------------------------------------- */
typedef enum {
    KV_JS_NULL, KV_JS_BOOL, KV_JS_NUM, KV_JS_STR, KV_JS_ARR, KV_JS_OBJ
} kv_jtype;

typedef struct kv_jval kv_jval;
struct kv_jval {
    kv_jtype  type;
    char     *str;      /* KV_JS_STR: value; object member: key           */
    double    num;
    int       boolean;
    kv_jval  *child;    /* first child for ARR/OBJ                        */
    kv_jval  *next;     /* next sibling                                   */
};

kv_jval    *kv_json_parse(const char *text);
void        kv_json_free(kv_jval *v);
kv_jval    *kv_json_get(const kv_jval *obj, const char *key);
const char *kv_json_gets(const kv_jval *obj, const char *key, const char *fallback);
double      kv_json_getn(const kv_jval *obj, const char *key, double fallback);
int         kv_json_getb(const kv_jval *obj, const char *key, int fallback);

#ifdef __cplusplus
}
#endif
#endif /* KV_JSON_H */
