
#include "forge/fg_erase.h"
#include <string.h>

#define F(b)  { FG_PAT_FIXED, { (b), 0, 0 }, 0 }
#define FV(b) { FG_PAT_FIXED, { (b), 0, 0 }, 1 }
#define R     { FG_PAT_RANDOM, { 0, 0, 0 }, 0 }
#define RV    { FG_PAT_RANDOM, { 0, 0, 0 }, 1 }
#define C     { FG_PAT_COMPLEMENT, { 0, 0, 0 }, 0 }
#define T(a,b,c) { FG_PAT_TRIPLE, { (a), (b), (c) }, 0 }

static const fg_pass P_ZERO[]   = { FV(0x00) };
static const fg_pass P_ONES[]   = { FV(0xFF) };
static const fg_pass P_RAND[]   = { R };
static const fg_pass P_CLEAR[]  = { RV };


static const fg_pass P_DOD3[]   = { F(0x00), C, RV };


static const fg_pass P_DOD7[]   = { F(0x00), C, R, R, F(0x00), C, RV };


static const fg_pass P_VSITR[]  = { F(0x00), F(0xFF), F(0x00),
                                    F(0xFF), F(0x00), F(0xFF), FV(0xAA) };


static const fg_pass P_HMG[]    = { F(0x00), F(0xFF), RV };


static const fg_pass P_GOST[]   = { F(0x00), RV };


static const fg_pass P_SCHN[]   = { F(0x00), F(0xFF), R, R, R, R, RV };


static const fg_pass P_GUTMANN[] = {
    R, R, R, R,
    T(0x55,0x55,0x55), T(0xAA,0xAA,0xAA), T(0x92,0x49,0x24),
    T(0x49,0x24,0x92), T(0x24,0x92,0x49), T(0x00,0x00,0x00),
    T(0x11,0x11,0x11), T(0x22,0x22,0x22), T(0x33,0x33,0x33),
    T(0x44,0x44,0x44), T(0x55,0x55,0x55), T(0x66,0x66,0x66),
    T(0x77,0x77,0x77), T(0x88,0x88,0x88), T(0x99,0x99,0x99),
    T(0xAA,0xAA,0xAA), T(0xBB,0xBB,0xBB), T(0xCC,0xCC,0xCC),
    T(0xDD,0xDD,0xDD), T(0xEE,0xEE,0xEE), T(0xFF,0xFF,0xFF),
    T(0x92,0x49,0x24), T(0x49,0x24,0x92), T(0x24,0x92,0x49),
    T(0x6D,0xB6,0xDB), T(0xB6,0xDB,0x6D), T(0xDB,0x6D,0xB6),
    R, R, R, RV
};


static const fg_pass P_NONE[]   = { RV };

static const fg_method_def g_methods[FG_M__COUNT] = {
/* name                     standard                                            cli          n  passes      fw final */
{ "Single pass zero",       "NIST SP 800-88 Rev.1 Clear (overwrite)",            "zero",      1, P_ZERO,     0, 1 },
{ "Single pass ones",       "Overwrite with 0xFF",                               "ones",      1, P_ONES,     0, 1 },
{ "Single pass random",     "NIST SP 800-88 Rev.1 Clear (pseudorandom)",         "random",    1, P_RAND,     0, 1 },
{ "NIST 800-88 Clear",      "NIST SP 800-88 Rev.1, Clear",                       "nist-clear",1, P_CLEAR,    0, 1 },
{ "NIST 800-88 Purge",      "NIST SP 800-88 Rev.1, Purge",                       "nist-purge",1, P_CLEAR,    1, 1 },
{ "DoD 5220.22-M (3 pass)", "US DoD 5220.22-M / NISPOM 8-306",                   "dod3",      3, P_DOD3,     0, 1 },
{ "DoD 5220.22-M ECE",      "US DoD 5220.22-M ECE (7 pass)",                     "dod7",      7, P_DOD7,     0, 1 },
{ "BSI-VSITR",              "German BSI Verschlusssachen-IT-Richtlinien",        "vsitr",     7, P_VSITR,    0, 1 },
{ "HMG IS5 Enhanced",       "UK HMG Infosec Standard 5, Enhanced",               "hmg",       3, P_HMG,      0, 1 },
{ "GOST R 50739-95",        "Russian State Standard GOST R 50739-95",            "gost",      2, P_GOST,     0, 1 },
{ "Schneier",               "Schneier, Applied Cryptography 2e",                 "schneier",  7, P_SCHN,     0, 1 },
{ "Gutmann",                "Gutmann 1996, 35-pass MFM/RLL",                     "gutmann",  35, P_GUTMANN,  0, 1 },
{ "Cryptographic erase",    "NIST SP 800-88 Rev.1 Purge, Cryptographic Erase",   "crypto",    1, P_NONE,     1, 1 }
};

const fg_method_def *fg_method_get(fg_method m)
{
    if (m < 0 || m >= FG_M__COUNT) return &g_methods[FG_M_NIST_CLEAR];
    return &g_methods[m];
}

fg_method fg_method_parse(const char *cli)
{
    int i;
    if (!cli) return (fg_method)-1;
    for (i = 0; i < FG_M__COUNT; i++)
        if (fg_strcaseeq(g_methods[i].cli_name, cli)) return (fg_method)i;

    if (fg_strcaseeq(cli, "dod"))      return FG_M_DOD_3;
    if (fg_strcaseeq(cli, "nist"))     return FG_M_NIST_CLEAR;
    if (fg_strcaseeq(cli, "purge"))    return FG_M_NIST_PURGE;
    if (fg_strcaseeq(cli, "bsi"))      return FG_M_VSITR;
    if (fg_strcaseeq(cli, "quick"))    return FG_M_ZERO;
    return (fg_method)-1;
}

void fg_method_list(void (*emit)(void *, const fg_method_def *), void *user)
{
    int i;
    for (i = 0; i < FG_M__COUNT; i++) emit(user, &g_methods[i]);
}

int fg_pattern_deterministic(const fg_method_def *def, int idx)
{
    if (!def || idx < 0 || idx >= def->pass_count) return 0;
    return def->passes[idx].kind != FG_PAT_RANDOM;
}


void fg_pattern_fill(const fg_method_def *def, int idx, fg_rng *rng,
                     uint8_t *buf, size_t n, uint64_t offset)
{
    const fg_pass *p;
    if (!def || idx < 0 || idx >= def->pass_count) { memset(buf, 0, n); return; }
    p = &def->passes[idx];

    switch (p->kind) {
    case FG_PAT_RANDOM:
        fg_rng_fill(rng, buf, n);
        break;
    case FG_PAT_FIXED:
        memset(buf, p->bytes[0], n);
        break;
    case FG_PAT_COMPLEMENT: {

        uint8_t prev = 0x00;
        if (idx > 0 && def->passes[idx-1].kind == FG_PAT_FIXED)
            prev = def->passes[idx-1].bytes[0];
        else if (idx > 0 && def->passes[idx-1].kind == FG_PAT_TRIPLE)
            prev = def->passes[idx-1].bytes[0];
        memset(buf, (uint8_t)~prev, n);
        break;
    }
    case FG_PAT_TRIPLE: {
        size_t i;
        unsigned phase = (unsigned)(offset % 3u);
        for (i = 0; i < n; i++) buf[i] = p->bytes[(phase + i) % 3u];
        break;
    }
    }
}
