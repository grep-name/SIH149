/* fg_json.h - minimal JSON writer and DOM parser (no dependencies).
 * The writer is used for reports and the HTTP API; the parser only has to
 * cope with the small request bodies the dashboard sends.
 */
#ifndef FG_JSON_H
#define FG_JSON_H

#include "fg_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- writer -------------------------------------------------------------- */
typedef struct {
    fg_buf buf;
    int    depth;
    int    need_comma[32];
    int    pretty;
} fg_jw;

void fg_jw_init(fg_jw *w, int pretty);
void fg_jw_obj(fg_jw *w);
void fg_jw_obj_end(fg_jw *w);
void fg_jw_arr(fg_jw *w);
void fg_jw_arr_end(fg_jw *w);
void fg_jw_key(fg_jw *w, const char *k);
void fg_jw_str(fg_jw *w, const char *v);
void fg_jw_i64(fg_jw *w, int64_t v);
void fg_jw_u64(fg_jw *w, uint64_t v);
void fg_jw_dbl(fg_jw *w, double v);
void fg_jw_bool(fg_jw *w, int v);
void fg_jw_null(fg_jw *w);
void fg_jw_raw(fg_jw *w, const char *json);
/* convenience: key + value in one call */
void fg_jw_kstr(fg_jw *w, const char *k, const char *v);
void fg_jw_ku64(fg_jw *w, const char *k, uint64_t v);
void fg_jw_ki64(fg_jw *w, const char *k, int64_t v);
void fg_jw_kdbl(fg_jw *w, const char *k, double v);
void fg_jw_kbool(fg_jw *w, const char *k, int v);
const char *fg_jw_text(fg_jw *w);   /* NUL-terminated, owned by the writer */
size_t fg_jw_len(fg_jw *w);
void fg_jw_free(fg_jw *w);

/* Escape `s` into a JSON string body (without the surrounding quotes). */
void fg_json_escape(fg_buf *b, const char *s);

/* ---- parser -------------------------------------------------------------- */
typedef enum {
    FG_JS_NULL, FG_JS_BOOL, FG_JS_NUM, FG_JS_STR, FG_JS_ARR, FG_JS_OBJ
} fg_jtype;

typedef struct fg_jval fg_jval;
struct fg_jval {
    fg_jtype  type;
    char     *str;      /* FG_JS_STR: value; object member: key           */
    double    num;
    int       boolean;
    fg_jval  *child;    /* first child for ARR/OBJ                        */
    fg_jval  *next;     /* next sibling                                   */
};

fg_jval    *fg_json_parse(const char *text);
void        fg_json_free(fg_jval *v);
fg_jval    *fg_json_get(const fg_jval *obj, const char *key);
const char *fg_json_gets(const fg_jval *obj, const char *key, const char *fallback);
double      fg_json_getn(const fg_jval *obj, const char *key, double fallback);
int         fg_json_getb(const fg_jval *obj, const char *key, int fallback);

#ifdef __cplusplus
}
#endif
#endif /* FG_JSON_H */
