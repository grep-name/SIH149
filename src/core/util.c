#include "forge/fg_common.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>



const char *fg_strerror(fg_status st)
{
    switch (st) {
    case FG_OK:              return "ok";
    case FG_ERR_GENERIC:     return "operation failed";
    case FG_ERR_NOMEM:       return "out of memory";
    case FG_ERR_INVALID:     return "invalid argument";
    case FG_ERR_NOTFOUND:    return "not found";
    case FG_ERR_PERM:        return "permission denied (run elevated)";
    case FG_ERR_IO:          return "I/O error";
    case FG_ERR_UNSUPPORTED: return "not supported on this platform or device";
    case FG_ERR_BUSY:        return "device or file is in use";
    case FG_ERR_VERIFY:      return "verification failed: residual data found";
    case FG_ERR_ABORTED:     return "cancelled by operator";
    case FG_ERR_REFUSED:     return "refused by safety interlock";
    case FG_ERR_CORRUPT:     return "on-disk structure is corrupt";
    case FG_ERR_RANGE:       return "value out of range";
    case FG_ERR_TIMEOUT:     return "timed out";
    }
    return "unknown error";
}





static fg_log_level g_level  = FG_LOG_INFO;
static FILE        *g_stream = NULL;

void fg_log_set_level(fg_log_level lv) { g_level = lv; }
fg_log_level fg_log_get_level(void)    { return g_level; }
void fg_log_set_stream(FILE *fp)       { g_stream = fp; }

void fg_log(fg_log_level lv, const char *fmt, ...)
{
    static const char *tag[] = { "trace", "debug", "info ", "warn ", "error" };
    va_list ap;
    FILE *fp;
    if (lv < g_level || lv >= FG_LOG_SILENT) return;
    fp = g_stream ? g_stream : stderr;
    fprintf(fp, "[%s] ", tag[lv]);
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    fputc('\n', fp);
    fflush(fp);
}

int fg_progress_report(const fg_progress *p, const char *phase,
                       uint64_t done, uint64_t total, const char *detail)
{
    if (!p || !p->fn) return 0;
    return p->fn(p->user, phase, done, total, detail);
}



void fg_buf_init(fg_buf *b) { b->data = NULL; b->len = 0; b->cap = 0; }

fg_status fg_buf_reserve(fg_buf *b, size_t need)
{
    size_t cap;
    char *p;
    if (b->cap >= b->len + need + 1) return FG_OK;
    cap = b->cap ? b->cap : 256;
    while (cap < b->len + need + 1) {
        if (cap > (size_t)-1 / 2) return FG_ERR_NOMEM;
        cap *= 2;
    }
    p = (char *)realloc(b->data, cap);
    if (!p) return FG_ERR_NOMEM;
    b->data = p;
    b->cap = cap;
    return FG_OK;
}

fg_status fg_buf_append(fg_buf *b, const void *p, size_t n)
{
    fg_status st = fg_buf_reserve(b, n);
    if (st != FG_OK) return st;
    memcpy(b->data + b->len, p, n);
    b->len += n;
    b->data[b->len] = '\0';
    return FG_OK;
}

fg_status fg_buf_puts(fg_buf *b, const char *s) { return fg_buf_append(b, s, strlen(s)); }

fg_status fg_buf_printf(fg_buf *b, const char *fmt, ...)
{
    va_list ap;
    int n;
    fg_status st;
    va_start(ap, fmt);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) return FG_ERR_INVALID;
    st = fg_buf_reserve(b, (size_t)n + 1);
    if (st != FG_OK) return st;
    va_start(ap, fmt);
    vsnprintf(b->data + b->len, (size_t)n + 1, fmt, ap);
    va_end(ap);
    b->len += (size_t)n;
    return FG_OK;
}

void fg_buf_free(fg_buf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

void fg_secure_zero(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

void *fg_xcalloc(size_t n, size_t sz)
{
    if (n && sz > (size_t)-1 / n) return NULL;
    return calloc(n, sz);
}

char *fg_strdup(const char *s)
{
    size_t n;
    char *p;
    if (!s) return NULL;
    n = strlen(s) + 1;
    p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static int lower(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

int fg_strcaseeq(const char *a, const char *b)
{
    if (!a || !b) return a == b;
    while (*a && *b) {
        if (lower((unsigned char)*a) != lower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == *b;
}

int fg_str_endswith(const char *s, const char *suffix)
{
    size_t ls, lt;
    if (!s || !suffix) return 0;
    ls = strlen(s); lt = strlen(suffix);
    return lt <= ls && fg_strcaseeq(s + ls - lt, suffix);
}

void fg_hex_encode(const uint8_t *in, size_t n, char *out)
{
    static const char hx[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[i * 2]     = hx[in[i] >> 4];
        out[i * 2 + 1] = hx[in[i] & 15];
    }
    out[n * 2] = '\0';
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int fg_hex_decode(const char *hex, uint8_t *out, size_t outsz)
{
    size_t i = 0;
    while (hex[0] && hex[1] && i < outsz) {
        int hi = hexval((unsigned char)hex[0]), lo = hexval((unsigned char)hex[1]);
        if (hi < 0 || lo < 0) return -1;
        out[i++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return hex[0] ? -1 : (int)i;
}

void fg_human_size(uint64_t bytes, char *out, size_t outsz)
{
    static const char *u[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB" };
    double v = (double)bytes;
    int i = 0;
    while (v >= 1024.0 && i < 5) { v /= 1024.0; i++; }
    if (i == 0) snprintf(out, outsz, "%llu B", (unsigned long long)bytes);
    else        snprintf(out, outsz, "%.2f %s", v, u[i]);
}

void fg_human_duration(double s, char *out, size_t outsz)
{
    unsigned long t = (unsigned long)(s + 0.5);
    if (s < 60.0)       snprintf(out, outsz, "%.1fs", s);
    else if (t < 3600)  snprintf(out, outsz, "%lum %lus", t / 60, t % 60);
    else                snprintf(out, outsz, "%luh %lum %lus", t / 3600, (t % 3600) / 60, t % 60);
}

uint64_t fg_now_ms(void)
{
#if FG_WINDOWS
    return (uint64_t)clock() * 1000u / CLOCKS_PER_SEC;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
#endif
}

void fg_iso8601_from_unix(int64_t unix_sec, char *out, size_t outsz)
{
    time_t t = (time_t)unix_sec;
    struct tm tmv;
#if FG_WINDOWS
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    strftime(out, outsz, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

void fg_iso8601_utc(char *out, size_t outsz)
{
    fg_iso8601_from_unix((int64_t)time(NULL), out, outsz);
}


static uint32_t g_crc_tab[256];
static int g_crc_ready = 0;

static void crc_init(void)
{
    uint32_t i, j, c;
    for (i = 0; i < 256; i++) {
        c = i;
        for (j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        g_crc_tab[i] = c;
    }
    g_crc_ready = 1;
}

uint32_t fg_crc32(uint32_t seed, const void *data, size_t n)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t c = seed ^ 0xFFFFFFFFu;
    if (!g_crc_ready) crc_init();
    while (n--) c = g_crc_tab[(c ^ *p++) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

double fg_shannon_entropy(const uint8_t *data, size_t n)
{
    uint32_t freq[256];
    double h = 0.0, inv;
    size_t i;
    if (!n) return 0.0;
    memset(freq, 0, sizeof freq);
    for (i = 0; i < n; i++) freq[data[i]]++;
    inv = 1.0 / (double)n;
    for (i = 0; i < 256; i++) {
        double p = (double)freq[i] * inv;
        if (p > 0.0) {

            double lg = 0.0, x = p;
            int e = 0;
            while (x < 0.5) { x *= 2.0; e--; }
            while (x >= 1.0) { x /= 2.0; e++; }

            {
                double u = (x - 1.0) / (x + 1.0), u2 = u * u, term = u, sum = u;
                int k;
                for (k = 1; k < 12; k++) { term *= u2; sum += term / (2 * k + 1); }
                lg = (double)e + 2.0 * sum * 1.4426950408889634; /* /ln2 */
            }
            h -= p * lg;
        }
    }
    return h;
}
