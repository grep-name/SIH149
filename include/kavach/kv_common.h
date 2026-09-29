/* kv_common.h - shared types, error codes and portability shims for KAVACH.
 *
 * KAVACH - Integrated Secure Data Erasure & Forensic Recovery Platform
 * SIH 2025 PS 26149 (NTRO). Licensed under the project LICENSE file.
 */
#ifndef KV_COMMON_H
#define KV_COMMON_H

/* Feature-test macros must be set before the first system header is pulled in,
 * and every translation unit includes this header first. */
#if !defined(_WIN32) && !defined(_WIN64)
#  ifndef _GNU_SOURCE
#    define _GNU_SOURCE 1
#  endif
#  ifndef _DARWIN_C_SOURCE
#    define _DARWIN_C_SOURCE 1
#  endif
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KV_VERSION_MAJOR 1
#define KV_VERSION_MINOR 0
#define KV_VERSION_PATCH 0
#define KV_VERSION_STR   "1.0.0"
#define KV_PRODUCT       "KAVACH"
#define KV_TAGLINE       "Integrated Secure Data Erasure & Forensic Recovery Platform"

/* ---- platform detection -------------------------------------------------- */
#if defined(_WIN32) || defined(_WIN64)
#  define KV_WINDOWS 1
#  define KV_PATH_SEP '\\'
#elif defined(__APPLE__)
#  define KV_MACOS 1
#  define KV_POSIX 1
#  define KV_PATH_SEP '/'
#elif defined(__linux__)
#  define KV_LINUX 1
#  define KV_POSIX 1
#  define KV_PATH_SEP '/'
#else
#  define KV_POSIX 1
#  define KV_PATH_SEP '/'
#endif

#ifndef KV_WINDOWS
#  define KV_WINDOWS 0
#endif
#ifndef KV_LINUX
#  define KV_LINUX 0
#endif
#ifndef KV_MACOS
#  define KV_MACOS 0
#endif

#if defined(_MSC_VER)
#  define KV_INLINE __inline
#  define KV_NORETURN __declspec(noreturn)
#else
#  define KV_INLINE inline
#  define KV_NORETURN __attribute__((noreturn))
#endif

#define KV_UNUSED(x) ((void)(x))
#define KV_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define KV_MIN(a, b) ((a) < (b) ? (a) : (b))
#define KV_MAX(a, b) ((a) > (b) ? (a) : (b))

/* ---- error codes --------------------------------------------------------- */
typedef enum {
    KV_OK                = 0,
    KV_ERR_GENERIC       = -1,
    KV_ERR_NOMEM         = -2,
    KV_ERR_INVALID       = -3,   /* bad argument from caller                   */
    KV_ERR_NOTFOUND      = -4,
    KV_ERR_PERM          = -5,   /* needs Administrator / root                 */
    KV_ERR_IO            = -6,
    KV_ERR_UNSUPPORTED   = -7,   /* not available on this OS / device          */
    KV_ERR_BUSY          = -8,   /* device mounted or in use                   */
    KV_ERR_VERIFY        = -9,   /* verification pass found residual data      */
    KV_ERR_ABORTED       = -10,  /* user cancelled                             */
    KV_ERR_REFUSED       = -11,  /* safety interlock refused the operation     */
    KV_ERR_CORRUPT       = -12,  /* on-disk structure failed sanity checks     */
    KV_ERR_RANGE         = -13,
    KV_ERR_TIMEOUT       = -14
} kv_status;

const char *kv_strerror(kv_status st);

/* ---- logging ------------------------------------------------------------- */
typedef enum {
    KV_LOG_TRACE = 0, KV_LOG_DEBUG, KV_LOG_INFO,
    KV_LOG_WARN, KV_LOG_ERROR, KV_LOG_SILENT
} kv_log_level;

void kv_log_set_level(kv_log_level lv);
kv_log_level kv_log_get_level(void);
void kv_log_set_stream(FILE *fp);
void kv_log(kv_log_level lv, const char *fmt, ...);

#define KV_TRACE(...) kv_log(KV_LOG_TRACE, __VA_ARGS__)
#define KV_DEBUG(...) kv_log(KV_LOG_DEBUG, __VA_ARGS__)
#define KV_INFO(...)  kv_log(KV_LOG_INFO,  __VA_ARGS__)
#define KV_WARN(...)  kv_log(KV_LOG_WARN,  __VA_ARGS__)
#define KV_ERROR(...) kv_log(KV_LOG_ERROR, __VA_ARGS__)

/* ---- progress callback --------------------------------------------------- */
/* Return non-zero from the callback to request cancellation of the job. */
typedef int (*kv_progress_fn)(void *user,
                              const char *phase,
                              uint64_t done,
                              uint64_t total,
                              const char *detail);

typedef struct {
    kv_progress_fn fn;
    void          *user;
} kv_progress;

int kv_progress_report(const kv_progress *p, const char *phase,
                       uint64_t done, uint64_t total, const char *detail);

/* ---- growable byte buffer ------------------------------------------------ */
typedef struct {
    char   *data;
    size_t  len;
    size_t  cap;
} kv_buf;

void       kv_buf_init(kv_buf *b);
kv_status  kv_buf_reserve(kv_buf *b, size_t need);
kv_status  kv_buf_append(kv_buf *b, const void *p, size_t n);
kv_status  kv_buf_puts(kv_buf *b, const char *s);
kv_status  kv_buf_printf(kv_buf *b, const char *fmt, ...);
void       kv_buf_free(kv_buf *b);

/* ---- misc helpers -------------------------------------------------------- */
void  kv_secure_zero(void *p, size_t n);
void *kv_xcalloc(size_t n, size_t sz);          /* NULL on failure, never aborts */
char *kv_strdup(const char *s);
int   kv_strcaseeq(const char *a, const char *b);
int   kv_str_endswith(const char *s, const char *suffix);
void  kv_hex_encode(const uint8_t *in, size_t n, char *out /* 2n+1 */);
int   kv_hex_decode(const char *hex, uint8_t *out, size_t outsz);
void  kv_human_size(uint64_t bytes, char *out, size_t outsz);
void  kv_human_duration(double seconds, char *out, size_t outsz);
uint64_t kv_now_ms(void);
void  kv_iso8601_utc(char *out, size_t outsz);   /* e.g. 2026-09-18T12:00:00Z */
void  kv_iso8601_from_unix(int64_t unix_sec, char *out, size_t outsz);
uint32_t kv_crc32(uint32_t seed, const void *data, size_t n);
double kv_shannon_entropy(const uint8_t *data, size_t n); /* bits/byte, 0..8 */

/* Little/big endian readers used everywhere by the on-disk parsers. */
static KV_INLINE uint16_t kv_rd16le(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
}
static KV_INLINE uint32_t kv_rd32le(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static KV_INLINE uint64_t kv_rd64le(const void *p) {
    return (uint64_t)kv_rd32le(p) | ((uint64_t)kv_rd32le((const uint8_t *)p + 4) << 32);
}
static KV_INLINE uint16_t kv_rd16be(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)(((uint16_t)b[0] << 8) | b[1]);
}
static KV_INLINE uint32_t kv_rd32be(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}
static KV_INLINE uint64_t kv_rd64be(const void *p) {
    return ((uint64_t)kv_rd32be(p) << 32) | kv_rd32be((const uint8_t *)p + 4);
}

#ifdef __cplusplus
}
#endif
#endif /* KV_COMMON_H */
