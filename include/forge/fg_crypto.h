/* fg_crypto.h - self-contained SHA-256, HMAC-SHA256, MD5 and a ChaCha20 CSPRNG.
 *
 * Nothing here links against OpenSSL: the tool must run from a forensic boot
 * medium with no package manager, so every primitive is in-tree and auditable.
 */
#ifndef FG_CRYPTO_H
#define FG_CRYPTO_H

#include "fg_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FG_SHA256_LEN 32
#define FG_MD5_LEN    16

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} fg_sha256;

void fg_sha256_init(fg_sha256 *c);
void fg_sha256_update(fg_sha256 *c, const void *data, size_t n);
void fg_sha256_final(fg_sha256 *c, uint8_t out[FG_SHA256_LEN]);
void fg_sha256_buf(const void *data, size_t n, uint8_t out[FG_SHA256_LEN]);
void fg_sha256_hex(const void *data, size_t n, char out[65]);

typedef struct {
    uint32_t state[4];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} fg_md5;

void fg_md5_init(fg_md5 *c);
void fg_md5_update(fg_md5 *c, const void *data, size_t n);
void fg_md5_final(fg_md5 *c, uint8_t out[FG_MD5_LEN]);

typedef struct {
    fg_sha256 inner;
    fg_sha256 outer;
} fg_hmac;

void fg_hmac_init(fg_hmac *h, const uint8_t *key, size_t keylen);
void fg_hmac_update(fg_hmac *h, const void *data, size_t n);
void fg_hmac_final(fg_hmac *h, uint8_t out[FG_SHA256_LEN]);
void fg_hmac_buf(const uint8_t *key, size_t keylen,
                 const void *data, size_t n, uint8_t out[FG_SHA256_LEN]);

/* Constant-time compare - used when checking audit-log seals. */
int fg_ct_equal(const void *a, const void *b, size_t n);

/* ---- CSPRNG -------------------------------------------------------------- */
/* ChaCha20 stream generator seeded from the OS entropy source
 * (BCryptGenRandom / getrandom(2) / arc4random_buf). Overwrite passes need
 * gigabytes of unpredictable bytes far faster than the OS source can supply
 * them, so the OS provides the 32-byte seed and ChaCha20 provides the volume. */
typedef struct {
    uint32_t state[16];
    uint8_t  block[64];
    size_t   used;
    int      seeded;
} fg_rng;

fg_status fg_rng_init(fg_rng *r);                       /* seeds from the OS  */
void      fg_rng_seed(fg_rng *r, const uint8_t key[32], const uint8_t nonce[12]);
void      fg_rng_fill(fg_rng *r, void *out, size_t n);
uint64_t  fg_rng_u64(fg_rng *r);
uint64_t  fg_rng_below(fg_rng *r, uint64_t bound);      /* unbiased           */

/* Pulls directly from the operating system CSPRNG. */
fg_status fg_os_random(void *out, size_t n);

#ifdef __cplusplus
}
#endif
#endif /* FG_CRYPTO_H */
