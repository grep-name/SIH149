#include "forge/fg_json.h"
#include <stdlib.h>
#include <string.h>


void fg_jw_init(fg_jw *w, int pretty)
{
    fg_buf_init(&w->buf);
    w->depth = 0;
    w->pretty = pretty;
    memset(w->need_comma, 0, sizeof w->need_comma);
}

static void jw_pre(fg_jw *w)
{
    if (w->depth > 0 && w->need_comma[w->depth]) fg_buf_puts(&w->buf, ",");
    if (w->pretty && w->depth > 0) {
        int i;
        fg_buf_puts(&w->buf, "\n");
        for (i = 0; i < w->depth; i++) fg_buf_puts(&w->buf, "  ");
    }
    if (w->depth > 0) w->need_comma[w->depth] = 1;
}

static void jw_open(fg_jw *w, const char *br)
{
    jw_pre(w);
    fg_buf_puts(&w->buf, br);
    if (w->depth < 31) w->depth++;
    w->need_comma[w->depth] = 0;
}

static void jw_close(fg_jw *w, const char *br)
{
    int had = w->need_comma[w->depth];
    if (w->depth > 0) w->depth--;
    if (w->pretty && had) {
        int i;
        fg_buf_puts(&w->buf, "\n");
        for (i = 0; i < w->depth; i++) fg_buf_puts(&w->buf, "  ");
    }
    fg_buf_puts(&w->buf, br);
}

void fg_jw_obj(fg_jw *w)     { jw_open(w, "{"); }
void fg_jw_obj_end(fg_jw *w) { jw_close(w, "}"); }
void fg_jw_arr(fg_jw *w)     { jw_open(w, "["); }
void fg_jw_arr_end(fg_jw *w) { jw_close(w, "]"); }

void fg_json_escape(fg_buf *b, const char *s)
{
    if (!s) return;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  fg_buf_puts(b, "\\\""); break;
        case '\\': fg_buf_puts(b, "\\\\"); break;
        case '\n': fg_buf_puts(b, "\\n");  break;
        case '\r': fg_buf_puts(b, "\\r");  break;
        case '\t': fg_buf_puts(b, "\\t");  break;
        case '\b': fg_buf_puts(b, "\\b");  break;
        case '\f': fg_buf_puts(b, "\\f");  break;
        default:
            if (c < 0x20) fg_buf_printf(b, "\\u%04x", c);
            else          fg_buf_append(b, &c, 1);
        }
    }
}

void fg_jw_key(fg_jw *w, const char *k)
{
    jw_pre(w);
    fg_buf_puts(&w->buf, "\"");
    fg_json_escape(&w->buf, k);
    fg_buf_puts(&w->buf, w->pretty ? "\": " : "\":");
    w->need_comma[w->depth] = 0;
}


static void jw_val_done(fg_jw *w) { w->need_comma[w->depth] = 1; }

void fg_jw_str(fg_jw *w, const char *v)
{
    if (!v) { fg_jw_null(w); return; }
    jw_pre(w);
    fg_buf_puts(&w->buf, "\"");
    fg_json_escape(&w->buf, v);
    fg_buf_puts(&w->buf, "\"");
    jw_val_done(w);
}

void fg_jw_i64(fg_jw *w, int64_t v)
{ jw_pre(w); fg_buf_printf(&w->buf, "%lld", (long long)v); jw_val_done(w); }

void fg_jw_u64(fg_jw *w, uint64_t v)
{ jw_pre(w); fg_buf_printf(&w->buf, "%llu", (unsigned long long)v); jw_val_done(w); }

void fg_jw_dbl(fg_jw *w, double v)
{ jw_pre(w); fg_buf_printf(&w->buf, "%.4f", v); jw_val_done(w); }

void fg_jw_bool(fg_jw *w, int v)
{ jw_pre(w); fg_buf_puts(&w->buf, v ? "true" : "false"); jw_val_done(w); }

void fg_jw_null(fg_jw *w)
{ jw_pre(w); fg_buf_puts(&w->buf, "null"); jw_val_done(w); }

void fg_jw_raw(fg_jw *w, const char *json)
{ jw_pre(w); fg_buf_puts(&w->buf, json); jw_val_done(w); }

void fg_jw_kstr(fg_jw *w, const char *k, const char *v)  { fg_jw_key(w, k); fg_jw_str(w, v); }
void fg_jw_ku64(fg_jw *w, const char *k, uint64_t v)     { fg_jw_key(w, k); fg_jw_u64(w, v); }
void fg_jw_ki64(fg_jw *w, const char *k, int64_t v)      { fg_jw_key(w, k); fg_jw_i64(w, v); }
void fg_jw_kdbl(fg_jw *w, const char *k, double v)       { fg_jw_key(w, k); fg_jw_dbl(w, v); }
void fg_jw_kbool(fg_jw *w, const char *k, int v)         { fg_jw_key(w, k); fg_jw_bool(w, v); }

const char *fg_jw_text(fg_jw *w) { return w->buf.data ? w->buf.data : ""; }
size_t      fg_jw_len(fg_jw *w)  { return w->buf.len; }
void        fg_jw_free(fg_jw *w) { fg_buf_free(&w->buf); }


typedef struct { const char *p; int err; } jp;

static void skip_ws(jp *s) { while (*s->p == ' ' || *s->p == '\t' || *s->p == '\n' || *s->p == '\r') s->p++; }
static fg_jval *parse_value(jp *s);

static fg_jval *newval(fg_jtype t)
{
    fg_jval *v = (fg_jval *)fg_xcalloc(1, sizeof *v);
    if (v) v->type = t;
    return v;
}

static char *parse_string_raw(jp *s)
{
    fg_buf b;
    fg_buf_init(&b);
    if (*s->p != '"') { s->err = 1; return NULL; }
    s->p++;
    while (*s->p && *s->p != '"') {
        if (*s->p == '\\') {
            s->p++;
            switch (*s->p) {
            case 'n': fg_buf_puts(&b, "\n"); break;
            case 't': fg_buf_puts(&b, "\t"); break;
            case 'r': fg_buf_puts(&b, "\r"); break;
            case 'b': fg_buf_puts(&b, "\b"); break;
            case 'f': fg_buf_puts(&b, "\f"); break;
            case 'u': {
                unsigned cp = 0;
                int i;
                for (i = 1; i <= 4; i++) {
                    char c = s->p[i];
                    cp <<= 4;
                    if (c >= '0' && c <= '9') cp |= (unsigned)(c - '0');
                    else if (c >= 'a' && c <= 'f') cp |= (unsigned)(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') cp |= (unsigned)(c - 'A' + 10);
                    else { s->err = 1; fg_buf_free(&b); return NULL; }
                }
                s->p += 4;
                if (cp < 0x80) { char c = (char)cp; fg_buf_append(&b, &c, 1); }
                else if (cp < 0x800) {
                    char c[2];
                    c[0] = (char)(0xC0 | (cp >> 6)); c[1] = (char)(0x80 | (cp & 0x3F));
                    fg_buf_append(&b, c, 2);
                } else {
                    char c[3];
                    c[0] = (char)(0xE0 | (cp >> 12));
                    c[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    c[2] = (char)(0x80 | (cp & 0x3F));
                    fg_buf_append(&b, c, 3);
                }
                break;
            }
            default: fg_buf_append(&b, s->p, 1);
            }
            s->p++;
        } else {
            fg_buf_append(&b, s->p, 1);
            s->p++;
        }
    }
    if (*s->p != '"') { s->err = 1; fg_buf_free(&b); return NULL; }
    s->p++;
    if (!b.data) { b.data = fg_strdup(""); }
    return b.data;
}

static fg_jval *parse_value(jp *s)
{
    skip_ws(s);
    if (*s->p == '{') {
        fg_jval *o = newval(FG_JS_OBJ), *tail = NULL;
        if (!o) { s->err = 1; return NULL; }
        s->p++;
        skip_ws(s);
        if (*s->p == '}') { s->p++; return o; }
        for (;;) {
            fg_jval *m;
            char *key;
            skip_ws(s);
            key = parse_string_raw(s);
            if (s->err) { fg_json_free(o); return NULL; }
            skip_ws(s);
            if (*s->p != ':') { s->err = 1; free(key); fg_json_free(o); return NULL; }
            s->p++;
            m = parse_value(s);
            if (!m) { s->err = 1; free(key); fg_json_free(o); return NULL; }
            free(m->str);
            if (m->type == FG_JS_STR) {
        
            }
            m->str = key;
            if (tail) tail->next = m; else o->child = m;
            tail = m;
            skip_ws(s);
            if (*s->p == ',') { s->p++; continue; }
            if (*s->p == '}') { s->p++; break; }
            s->err = 1; fg_json_free(o); return NULL;
        }
        return o;
    }
    if (*s->p == '[') {
        fg_jval *a = newval(FG_JS_ARR), *tail = NULL;
        if (!a) { s->err = 1; return NULL; }
        s->p++;
        skip_ws(s);
        if (*s->p == ']') { s->p++; return a; }
        for (;;) {
            fg_jval *m = parse_value(s);
            if (!m) { s->err = 1; fg_json_free(a); return NULL; }
            if (tail) tail->next = m; else a->child = m;
            tail = m;
            skip_ws(s);
            if (*s->p == ',') { s->p++; continue; }
            if (*s->p == ']') { s->p++; break; }
            s->err = 1; fg_json_free(a); return NULL;
        }
        return a;
    }
    if (*s->p == '"') {
        fg_jval *v = newval(FG_JS_STR);
        char *t;
        if (!v) { s->err = 1; return NULL; }
        t = parse_string_raw(s);
        if (s->err) { free(v); return NULL; }
    
        v->child = newval(FG_JS_STR);
        if (v->child) v->child->str = t; else free(t);
        return v;
    }
    if (!strncmp(s->p, "true", 4))  { fg_jval *v = newval(FG_JS_BOOL); s->p += 4; if (v) v->boolean = 1; return v; }
    if (!strncmp(s->p, "false", 5)) { fg_jval *v = newval(FG_JS_BOOL); s->p += 5; return v; }
    if (!strncmp(s->p, "null", 4))  { fg_jval *v = newval(FG_JS_NULL); s->p += 4; return v; }
    {
        char *end;
        double d = strtod(s->p, &end);
        fg_jval *v;
        if (end == s->p) { s->err = 1; return NULL; }
        v = newval(FG_JS_NUM);
        if (!v) { s->err = 1; return NULL; }
        v->num = d;
        s->p = end;
        return v;
    }
}

fg_jval *fg_json_parse(const char *text)
{
    jp s;
    fg_jval *v;
    if (!text) return NULL;
    s.p = text; s.err = 0;
    v = parse_value(&s);
    if (s.err) { fg_json_free(v); return NULL; }
    return v;
}

void fg_json_free(fg_jval *v)
{
    while (v) {
        fg_jval *n = v->next;
        fg_json_free(v->child);
        free(v->str);
        free(v);
        v = n;
    }
}

fg_jval *fg_json_get(const fg_jval *obj, const char *key)
{
    fg_jval *c;
    if (!obj || obj->type != FG_JS_OBJ) return NULL;
    for (c = obj->child; c; c = c->next)
        if (c->str && !strcmp(c->str, key)) return c;
    return NULL;
}

const char *fg_json_gets(const fg_jval *obj, const char *key, const char *fb)
{
    fg_jval *v = fg_json_get(obj, key);
    if (!v || v->type != FG_JS_STR || !v->child) return fb;
    return v->child->str ? v->child->str : fb;
}

double fg_json_getn(const fg_jval *obj, const char *key, double fb)
{
    fg_jval *v = fg_json_get(obj, key);
    return (v && v->type == FG_JS_NUM) ? v->num : fb;
}

int fg_json_getb(const fg_jval *obj, const char *key, int fb)
{
    fg_jval *v = fg_json_get(obj, key);
    if (!v) return fb;
    if (v->type == FG_JS_BOOL) return v->boolean;
    if (v->type == FG_JS_NUM)  return v->num != 0.0;
    return fb;
}
