#include "forge/fg_crypto.h"
#include <string.h>


static const uint32_t K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define ROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define S0(x) (ROR(x,2)  ^ ROR(x,13) ^ ROR(x,22))
#define S1(x) (ROR(x,6)  ^ ROR(x,11) ^ ROR(x,25))
#define s0(x) (ROR(x,7)  ^ ROR(x,18) ^ ((x) >> 3))
#define s1(x) (ROR(x,17) ^ ROR(x,19) ^ ((x) >> 10))

static void sha256_block(fg_sha256 *c, const uint8_t *p)
{
    uint32_t w[64], a, b, cc, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
    for (i = 16; i < 64; i++) w[i] = s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16];

    a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
    e = c->state[4]; f = c->state[5]; g  = c->state[6]; h = c->state[7];
    for (i = 0; i < 64; i++) {
        t1 = h + S1(e) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        t2 = S0(a) + ((a & b) ^ (a & cc) ^ (b & cc));
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=d;
    c->state[4]+=e; c->state[5]+=f; c->state[6]+=g;  c->state[7]+=h;
}

void fg_sha256_init(fg_sha256 *c)
{
    c->state[0]=0x6a09e667; c->state[1]=0xbb67ae85;
    c->state[2]=0x3c6ef372; c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f; c->state[5]=0x9b05688c;
    c->state[6]=0x1f83d9ab; c->state[7]=0x5be0cd19;
    c->bitlen = 0; c->buflen = 0;
}

void fg_sha256_update(fg_sha256 *c, const void *data, size_t n)
{
    const uint8_t *p = (const uint8_t *)data;
    c->bitlen += (uint64_t)n * 8;
    if (c->buflen) {
        size_t need = 64 - c->buflen;
        if (n < need) { memcpy(c->buf + c->buflen, p, n); c->buflen += n; return; }
        memcpy(c->buf + c->buflen, p, need);
        sha256_block(c, c->buf);
        p += need; n -= need; c->buflen = 0;
    }
    while (n >= 64) { sha256_block(c, p); p += 64; n -= 64; }
    if (n) { memcpy(c->buf, p, n); c->buflen = n; }
}

void fg_sha256_final(fg_sha256 *c, uint8_t out[32])
{
    uint64_t bl = c->bitlen;
    size_t i = c->buflen;
    c->buf[i++] = 0x80;
    if (i > 56) { while (i < 64) c->buf[i++] = 0; sha256_block(c, c->buf); i = 0; }
    while (i < 56) c->buf[i++] = 0;
    for (i = 0; i < 8; i++) c->buf[56 + i] = (uint8_t)(bl >> (56 - 8 * i));
    sha256_block(c, c->buf);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->state[i] >> 24);
        out[i*4+1] = (uint8_t)(c->state[i] >> 16);
        out[i*4+2] = (uint8_t)(c->state[i] >> 8);
        out[i*4+3] = (uint8_t)(c->state[i]);
    }
    fg_secure_zero(c->buf, sizeof c->buf);
}

void fg_sha256_buf(const void *data, size_t n, uint8_t out[32])
{
    fg_sha256 c;
    fg_sha256_init(&c);
    fg_sha256_update(&c, data, n);
    fg_sha256_final(&c, out);
}

void fg_sha256_hex(const void *data, size_t n, char out[65])
{
    uint8_t d[32];
    fg_sha256_buf(data, n, d);
    fg_hex_encode(d, 32, out);
}

static const uint32_t MD5K[64] = {
0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
static const uint8_t MD5S[64] = {
7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};

#define ROL(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

static void md5_block(fg_md5 *c, const uint8_t *p)
{
    uint32_t m[16], a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];
    uint32_t f, tmp;
    int i, g;
    for (i = 0; i < 16; i++) m[i] = fg_rd32le(p + i * 4);
    for (i = 0; i < 64; i++) {
        if (i < 16)      { f = (b & cc) | (~b & d);       g = i; }
        else if (i < 32) { f = (d & b) | (~d & cc);       g = (5 * i + 1) & 15; }
        else if (i < 48) { f = b ^ cc ^ d;                g = (3 * i + 5) & 15; }
        else             { f = cc ^ (b | ~d);             g = (7 * i) & 15; }
        tmp = d; d = cc; cc = b;
        b = b + ROL(a + f + MD5K[i] + m[g], MD5S[i]);
        a = tmp;
    }
    c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=d;
}

void fg_md5_init(fg_md5 *c)
{
    c->state[0]=0x67452301; c->state[1]=0xefcdab89;
    c->state[2]=0x98badcfe; c->state[3]=0x10325476;
    c->bitlen = 0; c->buflen = 0;
}

void fg_md5_update(fg_md5 *c, const void *data, size_t n)
{
    const uint8_t *p = (const uint8_t *)data;
    c->bitlen += (uint64_t)n * 8;
    if (c->buflen) {
        size_t need = 64 - c->buflen;
        if (n < need) { memcpy(c->buf + c->buflen, p, n); c->buflen += n; return; }
        memcpy(c->buf + c->buflen, p, need);
        md5_block(c, c->buf);
        p += need; n -= need; c->buflen = 0;
    }
    while (n >= 64) { md5_block(c, p); p += 64; n -= 64; }
    if (n) { memcpy(c->buf, p, n); c->buflen = n; }
}

void fg_md5_final(fg_md5 *c, uint8_t out[16])
{
    uint64_t bl = c->bitlen;
    size_t i = c->buflen;
    c->buf[i++] = 0x80;
    if (i > 56) { while (i < 64) c->buf[i++] = 0; md5_block(c, c->buf); i = 0; }
    while (i < 56) c->buf[i++] = 0;
    for (i = 0; i < 8; i++) c->buf[56 + i] = (uint8_t)(bl >> (8 * i));
    md5_block(c, c->buf);
    for (i = 0; i < 4; i++) {
        out[i*4]   = (uint8_t)(c->state[i]);
        out[i*4+1] = (uint8_t)(c->state[i] >> 8);
        out[i*4+2] = (uint8_t)(c->state[i] >> 16);
        out[i*4+3] = (uint8_t)(c->state[i] >> 24);
    }
}


void fg_hmac_init(fg_hmac *h, const uint8_t *key, size_t keylen)
{
    uint8_t k[64], pad[64];
    size_t i;
    memset(k, 0, sizeof k);
    if (keylen > 64) fg_sha256_buf(key, keylen, k);
    else             memcpy(k, key, keylen);

    for (i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    fg_sha256_init(&h->inner);
    fg_sha256_update(&h->inner, pad, 64);

    for (i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    fg_sha256_init(&h->outer);
    fg_sha256_update(&h->outer, pad, 64);

    fg_secure_zero(k, sizeof k);
    fg_secure_zero(pad, sizeof pad);
}

void fg_hmac_update(fg_hmac *h, const void *data, size_t n)
{
    fg_sha256_update(&h->inner, data, n);
}

void fg_hmac_final(fg_hmac *h, uint8_t out[32])
{
    uint8_t ih[32];
    fg_sha256_final(&h->inner, ih);
    fg_sha256_update(&h->outer, ih, 32);
    fg_sha256_final(&h->outer, out);
    fg_secure_zero(ih, sizeof ih);
}

void fg_hmac_buf(const uint8_t *key, size_t keylen,
                 const void *data, size_t n, uint8_t out[32])
{
    fg_hmac h;
    fg_hmac_init(&h, key, keylen);
    fg_hmac_update(&h, data, n);
    fg_hmac_final(&h, out);
}

int fg_ct_equal(const void *a, const void *b, size_t n)
{
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    uint8_t diff = 0;
    while (n--) diff |= (uint8_t)(*x++ ^ *y++);
    return diff == 0;
}
