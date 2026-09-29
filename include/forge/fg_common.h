/* fg_common.h - shared types, error codes and portability shims for FORGE.
 *
 * FORGE - Integrated Secure Data Erasure & Forensic Recovery Platform
 * SIH 2025 PS 26149 (NTRO). Licensed under the project LICENSE file.
 */
#ifndef FG_COMMON_H
#define FG_COMMON_H

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

#define FG_VERSION_MAJOR 1
#define FG_VERSION_MINOR 0
#define FG_VERSION_PATCH 0
#define FG_VERSION_STR   "1.0.0"
#define FG_PRODUCT       "FORGE"
#define FG_TAGLINE       "Integrated Secure Data Erasure & Forensic Recovery Platform"

/* ---- platform detection -------------------------------------------------- */
#if defined(_WIN32) || defined(_WIN64)
#  define FG_WINDOWS 1
#  define FG_PATH_SEP '\\'
#elif defined(__APPLE__)
#  define FG_MACOS 1
#  define FG_POSIX 1
#  define FG_PATH_SEP '/'
#elif defined(__linux__)
#  define FG_LINUX 1
#  define FG_POSIX 1
#  define FG_PATH_SEP '/'
#else
#  define FG_POSIX 1
#  define FG_PATH_SEP '/'
#endif

#ifndef FG_WINDOWS
#  define FG_WINDOWS 0
#endif
#ifndef FG_LINUX
#  define FG_LINUX 0
#endif
#ifndef FG_MACOS
#  define FG_MACOS 0
#endif

#if defined(_MSC_VER)
#  define FG_INLINE __inline
#  define FG_NORETURN __declspec(noreturn)
#else
#  define FG_INLINE inline
#  define FG_NORETURN __attribute__((noreturn))
#endif

#define FG_UNUSED(x) ((void)(x))
#define FG_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define FG_MIN(a, b) ((a) < (b) ? (a) : (b))
#define FG_MAX(a, b) ((a) > (b) ? (a) : (b))

/* ---- error codes --------------------------------------------------------- */
typedef enum {
    FG_OK                = 0,
    FG_ERR_GENERIC       = -1,
    FG_ERR_NOMEM         = -2,
    FG_ERR_INVALID       = -3,   /* bad argument from caller                   */
    FG_ERR_NOTFOUND      = -4,
    FG_ERR_PERM          = -5,   /* needs Administrator / root                 */
    FG_ERR_IO            = -6,
    FG_ERR_UNSUPPORTED   = -7,   /* not available on this OS / device          */
    FG_ERR_BUSY          = -8,   /* device mounted or in use                   */
    FG_ERR_VERIFY        = -9,   /* verification pass found residual data      */
    FG_ERR_ABORTED       = -10,  /* user cancelled                             */
    FG_ERR_REFUSED       = -11,  /* safety interlock refused the operation     */
    FG_ERR_CORRUPT       = -12,  /* on-disk structure failed sanity checks     */
    FG_ERR_RANGE         = -13,
    FG_ERR_TIMEOUT       = -14
} fg_status;

const char *fg_strerror(fg_status st);

/* ---- logging ------------------------------------------------------------- */
typedef enum {
    FG_LOG_TRACE = 0, FG_LOG_DEBUG, FG_LOG_INFO,
    FG_LOG_WARN, FG_LOG_ERROR, FG_LOG_SILENT
} fg_log_level;

void fg_log_set_level(fg_log_level lv);
fg_log_level fg_log_get_level(void);
void fg_log_set_stream(FILE *fp);
void fg_log(fg_log_level lv, const char *fmt, ...);

#define FG_TRACE(...) fg_log(FG_LOG_TRACE, __VA_ARGS__)
#define FG_DEBUG(...) fg_log(FG_LOG_DEBUG, __VA_ARGS__)
#define FG_INFO(...)  fg_log(FG_LOG_INFO,  __VA_ARGS__)
#define FG_WARN(...)  fg_log(FG_LOG_WARN,  __VA_ARGS__)
#define FG_ERROR(...) fg_log(FG_LOG_ERROR, __VA_ARGS__)

/* ---- progress callback --------------------------------------------------- */
/* Return non-zero from the callback to request cancellation of the job. */
typedef int (*fg_progress_fn)(void *user,
                              const char *phase,
                              uint64_t done,
                              uint64_t total,
                              const char *detail);

typedef struct {
    fg_progress_fn fn;
    void          *user;
} fg_progress;

int fg_progress_report(const fg_progress *p, const char *phase,
                       uint64_t done, uint64_t total, const char *detail);

/* ---- growable byte buffer ------------------------------------------------ */
typedef struct {
    char   *data;
    size_t  len;
    size_t  cap;
} fg_buf;

void       fg_buf_init(fg_buf *b);
fg_status  fg_buf_reserve(fg_buf *b, size_t need);
fg_status  fg_buf_append(fg_buf *b, const void *p, size_t n);
fg_status  fg_buf_puts(fg_buf *b, const char *s);
fg_status  fg_buf_printf(fg_buf *b, const char *fmt, ...);
void       fg_buf_free(fg_buf *b);

/* ---- misc helpers -------------------------------------------------------- */
void  fg_secure_zero(void *p, size_t n);
void *fg_xcalloc(size_t n, size_t sz);          /* NULL on failure, never aborts */
char *fg_strdup(const char *s);
int   fg_strcaseeq(const char *a, const char *b);
int   fg_str_endswith(const char *s, const char *suffix);
void  fg_hex_encode(const uint8_t *in, size_t n, char *out /* 2n+1 */);
int   fg_hex_decode(const char *hex, uint8_t *out, size_t outsz);
void  fg_human_size(uint64_t bytes, char *out, size_t outsz);
void  fg_human_duration(double seconds, char *out, size_t outsz);
uint64_t fg_now_ms(void);
void  fg_iso8601_utc(char *out, size_t outsz);   /* e.g. 2026-09-18T12:00:00Z */
void  fg_iso8601_from_unix(int64_t unix_sec, char *out, size_t outsz);
uint32_t fg_crc32(uint32_t seed, const void *data, size_t n);
double fg_shannon_entropy(const uint8_t *data, size_t n); /* bits/byte, 0..8 */

/* Little/big endian readers used everywhere by the on-disk parsers. */
static FG_INLINE uint16_t fg_rd16le(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
}
static FG_INLINE uint32_t fg_rd32le(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static FG_INLINE uint64_t fg_rd64le(const void *p) {
    return (uint64_t)fg_rd32le(p) | ((uint64_t)fg_rd32le((const uint8_t *)p + 4) << 32);
}
static FG_INLINE uint16_t fg_rd16be(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)(((uint16_t)b[0] << 8) | b[1]);
}
static FG_INLINE uint32_t fg_rd32be(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}
static FG_INLINE uint64_t fg_rd64be(const void *p) {
    return ((uint64_t)fg_rd32be(p) << 32) | fg_rd32be((const uint8_t *)p + 4);
}

#ifdef __cplusplus
}
#endif
#endif /* FG_COMMON_H */
