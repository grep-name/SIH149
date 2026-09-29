#include "forge/fg_crypto.h"
#include <string.h>

#if FG_WINDOWS
#  include <windows.h>
#  include <bcrypt.h>
#  ifndef STATUS_SUCCESS
#    define STATUS_SUCCESS ((NTSTATUS)0)
#  endif
#else
#  include <stdlib.h>
#  include <unistd.h>
#  include <fcntl.h>
#  if FG_LINUX
#    include <sys/syscall.h>
#  endif
#endif

fg_status fg_os_random(void *out, size_t n)
{
#if FG_WINDOWS
    if (BCryptGenRandom(NULL, (PUCHAR)out, (ULONG)n,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) == STATUS_SUCCESS)
        return FG_OK;
    return FG_ERR_GENERIC;
#elif FG_MACOS
    arc4random_buf(out, n);
    return FG_OK;
#else
    {
        uint8_t *p = (uint8_t *)out;
        size_t left = n;
        int fd;
#  if defined(SYS_getrandom)
        while (left) {
            long r = syscall(SYS_getrandom, p, left, 0);
            if (r <= 0) break;
            p += r; left -= (size_t)r;
        }
        if (!left) return FG_OK;
#  endif
        fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) return FG_ERR_GENERIC;
        while (left) {
            ssize_t r = read(fd, p, left);
            if (r <= 0) { close(fd); return FG_ERR_GENERIC; }
            p += r; left -= (size_t)r;
        }
        close(fd);
        return FG_OK;
    }
#endif
}


#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a,b,c,d)                                \
    a += b; d ^= a; d = ROTL(d, 16);               \
    c += d; b ^= c; b = ROTL(b, 12);               \
    a += b; d ^= a; d = ROTL(d, 8);                \
    c += d; b ^= c; b = ROTL(b, 7)

static void chacha_block(const uint32_t in[16], uint8_t out[64])
{
    uint32_t x[16];
    int i;
    memcpy(x, in, sizeof x);
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }
    for (i = 0; i < 16; i++) {
        uint32_t v = x[i] + in[i];
        out[i*4]   = (uint8_t)v;
        out[i*4+1] = (uint8_t)(v >> 8);
        out[i*4+2] = (uint8_t)(v >> 16);
        out[i*4+3] = (uint8_t)(v >> 24);
    }
}

void fg_rng_seed(fg_rng *r, const uint8_t key[32], const uint8_t nonce[12])
{
    int i;
    r->state[0] = 0x61707865; r->state[1] = 0x3320646e;
    r->state[2] = 0x79622d32; r->state[3] = 0x6b206574;
    for (i = 0; i < 8; i++)  r->state[4 + i]  = fg_rd32le(key + i * 4);
    r->state[12] = 0;
    for (i = 0; i < 3; i++)  r->state[13 + i] = fg_rd32le(nonce + i * 4);
    r->used = 64;
    r->seeded = 1;
}

fg_status fg_rng_init(fg_rng *r)
{
    uint8_t seed[44];
    fg_status st = fg_os_random(seed, sizeof seed);
    if (st != FG_OK) return st;
    fg_rng_seed(r, seed, seed + 32);
    fg_secure_zero(seed, sizeof seed);
    return FG_OK;
}

void fg_rng_fill(fg_rng *r, void *out, size_t n)
{
    uint8_t *p = (uint8_t *)out;
    if (!r->seeded && fg_rng_init(r) != FG_OK) {
        
        uint8_t k[32], nn[12];
        size_t i;
        uint64_t t = fg_now_ms();
        for (i = 0; i < 32; i++) k[i]  = (uint8_t)(t >> ((i % 8) * 8)) ^ (uint8_t)i;
        for (i = 0; i < 12; i++) nn[i] = (uint8_t)(t * (i + 7));
        fg_rng_seed(r, k, nn);
    }
    while (n) {
        size_t take;
        if (r->used >= 64) {
            chacha_block(r->state, r->block);
            if (++r->state[12] == 0) r->state[13]++;
            r->used = 0;
        }
        take = FG_MIN(n, 64 - r->used);
        memcpy(p, r->block + r->used, take);
        r->used += take;
        p += take; n -= take;
    }
}

uint64_t fg_rng_u64(fg_rng *r)
{
    uint64_t v;
    fg_rng_fill(r, &v, sizeof v);
    return v;
}

uint64_t fg_rng_below(fg_rng *r, uint64_t bound)
{
    uint64_t lim, v;
    if (bound < 2) return 0;
    lim = (uint64_t)-1 - ((uint64_t)-1 % bound);
    do { v = fg_rng_u64(r); } while (v >= lim);
    return v % bound;
}
