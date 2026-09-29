/* kv_crypto.h - self-contained SHA-256, HMAC-SHA256, MD5 and a ChaCha20 CSPRNG.
 *
 * Nothing here links against OpenSSL: the tool must run from a forensic boot
 * medium with no package manager, so every primitive is in-tree and auditable.
 */
#ifndef KV_CRYPTO_H
#define KV_CRYPTO_H

#include "kv_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KV_SHA256_LEN 32
#define KV_MD5_LEN    16

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} kv_sha256;

void kv_sha256_init(kv_sha256 *c);
void kv_sha256_update(kv_sha256 *c, const void *data, size_t n);
void kv_sha256_final(kv_sha256 *c, uint8_t out[KV_SHA256_LEN]);
void kv_sha256_buf(const void *data, size_t n, uint8_t out[KV_SHA256_LEN]);
void kv_sha256_hex(const void *data, size_t n, char out[65]);

typedef struct {
    uint32_t state[4];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} kv_md5;

void kv_md5_init(kv_md5 *c);
void kv_md5_update(kv_md5 *c, const void *data, size_t n);
void kv_md5_final(kv_md5 *c, uint8_t out[KV_MD5_LEN]);

typedef struct {
    kv_sha256 inner;
    kv_sha256 outer;
} kv_hmac;

void kv_hmac_init(kv_hmac *h, const uint8_t *key, size_t keylen);
void kv_hmac_update(kv_hmac *h, const void *data, size_t n);
void kv_hmac_final(kv_hmac *h, uint8_t out[KV_SHA256_LEN]);
void kv_hmac_buf(const uint8_t *key, size_t keylen,
                 const void *data, size_t n, uint8_t out[KV_SHA256_LEN]);

/* Constant-time compare - used when checking audit-log seals. */
int kv_ct_equal(const void *a, const void *b, size_t n);

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
} kv_rng;

kv_status kv_rng_init(kv_rng *r);                       /* seeds from the OS  */
void      kv_rng_seed(kv_rng *r, const uint8_t key[32], const uint8_t nonce[12]);
void      kv_rng_fill(kv_rng *r, void *out, size_t n);
uint64_t  kv_rng_u64(kv_rng *r);
uint64_t  kv_rng_below(kv_rng *r, uint64_t bound);      /* unbiased           */

/* Pulls directly from the operating system CSPRNG. */
kv_status kv_os_random(void *out, size_t n);

#ifdef __cplusplus
}
#endif
#endif /* KV_CRYPTO_H */
