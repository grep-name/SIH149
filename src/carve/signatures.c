#include "forge/fg_carve.h"
#include <string.h>

#define MB (1024ull * 1024ull)
#define GB (1024ull * MB)

const char *fg_category_name(fg_category c)
{
    switch (c) {
    case FG_CAT_IMAGE:      return "image";
    case FG_CAT_DOCUMENT:   return "document";
    case FG_CAT_ARCHIVE:    return "archive";
    case FG_CAT_AUDIO:      return "audio";
    case FG_CAT_VIDEO:      return "video";
    case FG_CAT_EXECUTABLE: return "executable";
    case FG_CAT_DATABASE:   return "database";
    case FG_CAT_EMAIL:      return "email";
    case FG_CAT_FORENSIC:   return "forensic-artifact";
    case FG_CAT_CRYPTO:     return "crypto-material";
    case FG_CAT_DISKIMAGE:  return "disk-image";
    default:                return "unknown";
    }
}


static uint64_t v_jpeg(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    size_t i = 2;
    FG_UNUSED(s);
    *q = 0;
    if (n < 4) return FG_LEN_UNKNOWN;
    while (i + 1 < n) {
        uint8_t marker;
        if (p[i] != 0xFF) { *q = 1; return FG_LEN_UNKNOWN; }
        marker = p[i + 1];
        if (marker == 0xFF) { i++; continue; }
        if (marker == 0xD9) { *q = 3; return i + 2; }
        if (marker >= 0xD0 && marker <= 0xD7) { i += 2; continue; }
        if (marker == 0x01) { i += 2; continue; }
        if (marker == 0x00) { *q = 1; return FG_LEN_UNKNOWN; }
        if (i + 3 >= n) break;
        {
            uint16_t seglen = fg_rd16be(p + i + 2);
            if (seglen < 2) return 0;
            if ((uint64_t)i + 2 + seglen > (uint64_t)n) break;
            if (marker == 0xDA) {

                i += 2 + seglen;
                while (i + 1 < n) {
                    if (p[i] == 0xFF && p[i+1] != 0x00 &&
                        !(p[i+1] >= 0xD0 && p[i+1] <= 0xD7)) break;
                    i++;
                }
                continue;
            }
            i += 2 + seglen;
        }
    }
    *q = 1;
    return FG_LEN_UNKNOWN;
}


static uint64_t v_png(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    size_t i = 8;
    int crc_ok = 1, chunks = 0;
    FG_UNUSED(s);
    *q = 0;
    while (i + 12 <= n) {
        uint32_t len = fg_rd32be(p + i);
        const uint8_t *type = p + i + 4;
        uint32_t stored, calc;
        if (len > 0x7FFFFFFFu || i + 12 + len > n) break;
        stored = fg_rd32be(p + i + 8 + len);
        calc = fg_crc32(0, p + i + 4, len + 4);
        if (stored != calc) crc_ok = 0;
        chunks++;
        if (!memcmp(type, "IEND", 4)) {
            *q = crc_ok ? 3 : 2;
            return i + 12 + len;
        }
        i += 12 + len;
    }
    *q = chunks > 1 ? 1 : 0;
    return chunks > 1 ? FG_LEN_UNKNOWN : 0;
}

static uint64_t v_gif(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    size_t i = 6;
    uint8_t flags;
    FG_UNUSED(s);
    *q = 0;
    if (n < 14) return FG_LEN_UNKNOWN;
    flags = p[10];
    i = 13;
    if (flags & 0x80) i += 3u << ((flags & 7) + 1);
    while (i < n) {
        uint8_t b = p[i];
        if (b == 0x3B) { *q = 3; return i + 1; }
        if (b == 0x21) {
            i += 2;
            while (i < n && p[i]) i += p[i] + 1;
            i++;
        } else if (b == 0x2C) {
            uint8_t lf;
            if (i + 10 > n) break;
            lf = p[i + 9];
            i += 10;
            if (lf & 0x80) i += 3u << ((lf & 7) + 1);
            if (i >= n) break;
            i++;
            while (i < n && p[i]) i += p[i] + 1;
            i++;
        } else break;
    }
    *q = 1;
    return FG_LEN_UNKNOWN;
}


static uint64_t v_bmp(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    uint32_t sz, dib, offbits;
    int32_t w, h;
    uint16_t planes, bpp;
    FG_UNUSED(s);
    *q = 0;
    if (n < 54) return 0;
    sz      = fg_rd32le(p + 2);
    offbits = fg_rd32le(p + 10);
    dib     = fg_rd32le(p + 14);
    if (sz < 54 || sz > 512 * MB) return 0;
    if (fg_rd32le(p + 6) != 0) return 0;
    if (dib != 12 && dib != 40 && dib != 52 && dib != 56 &&
        dib != 64 && dib != 108 && dib != 124) return 0;
    if (offbits < 14 + dib || offbits > sz) return 0;
    if (dib == 12) {
        w = (int32_t)(int16_t)fg_rd16le(p + 18);
        h = (int32_t)(int16_t)fg_rd16le(p + 20);
        planes = fg_rd16le(p + 22);
        bpp    = fg_rd16le(p + 24);
    } else {
        w = (int32_t)fg_rd32le(p + 18);
        h = (int32_t)fg_rd32le(p + 22);
        planes = fg_rd16le(p + 26);
        bpp    = fg_rd16le(p + 28);
    }
    if (w <= 0 || w > 262144 || h == 0 || h < -262144 || h > 262144) return 0;
    if (planes != 1) return 0;
    if (bpp != 1 && bpp != 4 && bpp != 8 && bpp != 16 && bpp != 24 && bpp != 32)
        return 0;
    *q = 3;
    return sz;
}


static uint64_t v_riff(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    uint32_t sz;
    FG_UNUSED(s);
    *q = 0;
    if (n < 12) return 0;
    sz = fg_rd32le(p + 4);
    if (sz < 4 || (uint64_t)sz > 4ull * GB - 8) return 0;
    if (memcmp(p + 8, "WAVE", 4) && memcmp(p + 8, "AVI ", 4) &&
        memcmp(p + 8, "WEBP", 4) && memcmp(p + 8, "RMID", 4)) return 0;
    *q = 3;
    return (uint64_t)sz + 8;
}


static uint64_t v_mp4(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    uint64_t off = 0;
    int boxes = 0;
    FG_UNUSED(s);
    *q = 0;
    while (off + 8 <= (uint64_t)n) {
        uint64_t bs = fg_rd32be(p + off);
        const uint8_t *type = p + off + 4;
        int printable = 1, k;
        for (k = 0; k < 4; k++)
            if (type[k] < 0x20 || type[k] > 0x7E) printable = 0;
        if (!printable) break;
        if (bs == 1) {
            if (off + 16 > (uint64_t)n) break;
            bs = fg_rd64be(p + off + 8);
        } else if (bs == 0) {
            
            *q = 2;
            return FG_LEN_UNKNOWN;
        }
        if (bs < 8) break;
        boxes++;
        off += bs;
        if (off > 16ull * GB) break;
    }
    if (boxes >= 2) { *q = 3; return off; }
    return boxes ? FG_LEN_UNKNOWN : 0;
}


static uint64_t v_zip(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    size_t i;
    uint64_t best = 0;
    FG_UNUSED(s);
    *q = 0;
    if (n < 22) return FG_LEN_UNKNOWN;
    for (i = 0; i + 22 <= n; i++) {
        if (p[i] != 0x50 || p[i+1] != 0x4B || p[i+2] != 0x05 || p[i+3] != 0x06) continue;
        {
            uint32_t cd_size = fg_rd32le(p + i + 12);
            uint32_t cd_off  = fg_rd32le(p + i + 16);
            uint16_t comment = fg_rd16le(p + i + 20);
            if ((uint64_t)cd_off + cd_size != (uint64_t)i) continue;  /* must add up */
            if ((uint64_t)i + 22 + comment > (uint64_t)n) continue;
            best = (uint64_t)i + 22 + comment;
        }
    }
    if (best) { *q = 3; return best; }
    return FG_LEN_UNKNOWN;
}

static uint64_t v_pdf(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    uint64_t end = 0, pos = 0;
    FG_UNUSED(s);
    *q = 0;
    for (;;) {
        uint64_t i, eof = 0;
        int found = 0;
        for (i = pos; i + 5 <= (uint64_t)n; i++) {
            if (p[i] == '%' && p[i+1] == '%' && !memcmp(p + i + 2, "EOF", 3)) {
                eof = i; found = 1; break;
            }
        }
        if (!found) return end ? end : FG_LEN_UNKNOWN;
        end = eof + 5;
        if (end < (uint64_t)n && (p[end] == '\r' || p[end] == '\n')) end++;
        if (end < (uint64_t)n && p[end] == '\n') end++;

        {
            uint64_t look = FG_MIN((uint64_t)n, end + 4096), k;
            int has_obj = 0, has_xref = 0;
            for (k = end; k + 9 <= look; k++) {
                if (!memcmp(p + k, "startxref", 9)) has_xref = 1;
                if (k + 3 <= look && !memcmp(p + k, "obj", 3)) has_obj = 1;
                if (has_obj && has_xref) break;
            }
            if (!(has_obj && has_xref)) break;
        }
        pos = end;
    }
    *q = 3;
    return end;
}


static uint64_t v_sqlite(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    uint32_t pgsz, pages;
    FG_UNUSED(s);
    *q = 0;
    if (n < 100) return 0;
    pgsz = fg_rd16be(p + 16);
    if (pgsz == 1) pgsz = 65536;
    if (pgsz < 512 || (pgsz & (pgsz - 1))) return 0;
    pages = fg_rd32be(p + 28);
    if (!pages || pages > 0x3FFFFFFFu) return 0;
    *q = 3;
    return (uint64_t)pgsz * pages;
}


static uint64_t v_elf(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    int is64, le;
    uint64_t shoff, end;
    uint16_t shentsize, shnum;
    FG_UNUSED(s);
    *q = 0;
    if (n < 64) return 0;
    if (p[4] != 1 && p[4] != 2) return 0;
    if (p[5] != 1 && p[5] != 2) return 0;
    if (p[6] != 1) return 0;
    is64 = (p[4] == 2);
    le   = (p[5] == 1);
    if (!le) return FG_LEN_UNKNOWN;
    if (is64) {
        shoff     = fg_rd64le(p + 0x28);
        shentsize = fg_rd16le(p + 0x3A);
        shnum     = fg_rd16le(p + 0x3C);
    } else {
        shoff     = fg_rd32le(p + 0x20);
        shentsize = fg_rd16le(p + 0x2E);
        shnum     = fg_rd16le(p + 0x30);
    }
    if (!shoff || !shnum || shentsize < 32 || shentsize > 256) return 0;
    end = shoff + (uint64_t)shentsize * shnum;
    if (end < 64 || end > 2ull * GB) return 0;
    *q = 3;
    return end;
}


static uint64_t v_pe(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    uint32_t e_lfanew, i;
    uint16_t nsec, optsz;
    uint64_t end = 0, sect;
    FG_UNUSED(s);
    *q = 0;
    if (n < 0x40) return 0;
    e_lfanew = fg_rd32le(p + 0x3C);

    if (e_lfanew < 0x40 || e_lfanew > 0x1000) return 0;
    if ((uint64_t)e_lfanew + 24 > n) return 0;
    if (memcmp(p + e_lfanew, "PE\0\0", 4)) return 0;
    nsec  = fg_rd16le(p + e_lfanew + 6);
    optsz = fg_rd16le(p + e_lfanew + 20);
    sect  = (uint64_t)e_lfanew + 24 + optsz;
    if (!nsec || nsec > 96) return 0;
    if (sect + (uint64_t)nsec * 40 > n) return FG_LEN_UNKNOWN;
    for (i = 0; i < nsec; i++) {
        const uint8_t *sh = p + sect + (uint64_t)i * 40;
        uint64_t raw = fg_rd32le(sh + 20) + (uint64_t)fg_rd32le(sh + 16);
        if (raw > end) end = raw;
    }
    if (!end || end > 2ull * GB) return FG_LEN_UNKNOWN;

    {
        uint16_t magic = fg_rd16le(p + e_lfanew + 24);
        uint64_t dd = (magic == 0x20B) ? e_lfanew + 24 + 112 + 4 * 8
                                       : e_lfanew + 24 + 96  + 4 * 8;
        if (dd + 8 <= n) {
            uint64_t certoff = fg_rd32le(p + dd), certsz = fg_rd32le(p + dd + 4);
            if (certoff && certsz && certoff + certsz > end && certoff + certsz < 2ull * GB)
                end = certoff + certsz;
        }
    }
    *q = 3;
    return end;
}


static uint64_t v_7z(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    uint64_t off, sz;
    FG_UNUSED(s);
    *q = 0;
    if (n < 32) return 0;
    off = fg_rd64le(p + 12);
    sz  = fg_rd64le(p + 20);
    if (off > 64ull * GB || sz > 64ull * GB) return 0;
    *q = 3;
    return 32 + off + sz;
}


static uint64_t v_cab(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    uint32_t sz;
    FG_UNUSED(s);
    *q = 0;
    if (n < 36) return 0;
    sz = fg_rd32le(p + 8);
    if (sz < 36 || sz > 2u * 1024u * 1024u * 1024u - 1) return 0;
    *q = 3;
    return sz;
}


static uint64_t v_evtx(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    uint64_t chunks;
    FG_UNUSED(s);
    *q = 0;
    if (n < 0x80) return 0;
    chunks = fg_rd64le(p + 0x28);
    if (!chunks || chunks > 1000000ull) return 0;
    *q = 3;
    return 4096 + chunks * 65536;
}


static uint64_t v_tiff(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    int le = (p[0] == 'I');
    uint64_t ifd, end = 8;
    int guard = 0;
    FG_UNUSED(s);
    *q = 0;
    if (n < 8) return 0;
    ifd = le ? fg_rd32le(p + 4) : fg_rd32be(p + 4);
    while (ifd && ifd + 2 <= (uint64_t)n && guard++ < 64) {
        uint16_t cnt = le ? fg_rd16le(p + ifd) : fg_rd16be(p + ifd);
        uint64_t i;
        if (ifd + 2 + (uint64_t)cnt * 12 + 4 > (uint64_t)n) break;
        for (i = 0; i < cnt; i++) {
            const uint8_t *e = p + ifd + 2 + i * 12;
            uint16_t tag  = le ? fg_rd16le(e)     : fg_rd16be(e);
            uint16_t type = le ? fg_rd16le(e + 2) : fg_rd16be(e + 2);
            uint32_t num  = le ? fg_rd32le(e + 4) : fg_rd32be(e + 4);
            uint32_t val  = le ? fg_rd32le(e + 8) : fg_rd32be(e + 8);
            static const uint8_t tsz[13] = {0,1,1,2,4,8,1,1,2,4,8,4,8};
            uint64_t bytes = (type < 13 ? tsz[type] : 1) * (uint64_t)num;
            if (bytes > 4 && val + bytes > end) end = val + bytes;

            if ((tag == 273 || tag == 324) && num == 1 && val + 1 > end) end = val + 1;
            if ((tag == 279 || tag == 325) && num == 1) {

            }
        }
        ifd = le ? fg_rd32le(p + ifd + 2 + (uint64_t)cnt * 12)
                 : fg_rd32be(p + ifd + 2 + (uint64_t)cnt * 12);
        if (ifd + 2 > end) end = ifd + 2;
    }
    if (end > 8 && end < 512 * MB) { *q = 2; return end; }
    return FG_LEN_UNKNOWN;
}


static uint64_t v_dex(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    uint32_t sz;
    FG_UNUSED(s);
    *q = 0;
    if (n < 112) return 0;
    sz = fg_rd32le(p + 32);
    if (sz < 112 || sz > 512 * MB) return 0;
    *q = 3;
    return sz;
}


static uint64_t v_mp3(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    uint64_t i = 0;
    int frames = 0;
    FG_UNUSED(s);
    *q = 0;
    if (n > 10 && !memcmp(p, "ID3", 3)) {
        uint32_t tag = ((uint32_t)(p[6] & 0x7F) << 21) | ((uint32_t)(p[7] & 0x7F) << 14) |
                       ((uint32_t)(p[8] & 0x7F) << 7)  |  (uint32_t)(p[9] & 0x7F);
        i = 10 + tag;
    }
    while (i + 4 <= (uint64_t)n) {
        static const int br_v1l3[16] = {0,32,40,48,56,64,80,96,112,128,160,192,224,256,320,0};
        static const int sr_v1[4]    = {44100,48000,32000,0};
        int bri, sri, pad, bitrate, srate, flen;
        if (p[i] != 0xFF || (p[i+1] & 0xE0) != 0xE0) break;

        if (frames >= 4 && frames < 8 && i > (uint64_t)n / 2) break;
        bri = (p[i+2] >> 4) & 15;
        sri = (p[i+2] >> 2) & 3;
        pad = (p[i+2] >> 1) & 1;
        bitrate = br_v1l3[bri];
        srate   = sr_v1[sri];
        if (!bitrate || !srate) break;
        flen = 144 * bitrate * 1000 / srate + pad;
        if (flen < 24) break;
        i += (uint64_t)flen;
        frames++;
        if (frames > 200000) break;
    }
    if (frames > 8) {

        if (i + 128 <= (uint64_t)n && !memcmp(p + i, "TAG", 3)) i += 128;
        *q = 3;
        return i;
    }

    return 0;
}


static uint64_t v_ogg(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    uint64_t i = 0;
    int pages = 0;
    FG_UNUSED(s);
    *q = 0;
    while (i + 27 <= (uint64_t)n && !memcmp(p + i, "OggS", 4)) {
        uint8_t nseg = p[i + 26];
        uint64_t body = 0;
        int k;
        if (i + 27 + nseg > (uint64_t)n) break;
        for (k = 0; k < nseg; k++) body += p[i + 27 + k];
        pages++;
        {
            uint8_t hdr_type = p[i + 5];
            i += 27 + nseg + body;
            if (hdr_type & 0x04) { *q = 3; return i; }
        }
        if (pages > 500000) break;
    }
    return pages ? FG_LEN_UNKNOWN : 0;
}


static uint64_t v_iso(const uint8_t *p, size_t n, const fg_sig *s, int *q)
{
    uint32_t blocks;
    FG_UNUSED(s);
    *q = 0;
    if (n < 32768 + 88) return FG_LEN_UNKNOWN;
    blocks = fg_rd32le(p + 32768 + 80);   /* both-endian field, LE half first */
    if (!blocks || blocks > 0x20000000u) return FG_LEN_UNKNOWN;
    *q = 3;
    return (uint64_t)blocks * 2048ull;
}


#define H(name, ...) static const uint8_t name[] = { __VA_ARGS__ }

H(h_jpg,  0xFF,0xD8,0xFF);            H(f_jpg,  0xFF,0xD9);
H(h_png,  0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A);
H(f_png,  'I','E','N','D',0xAE,0x42,0x60,0x82);
H(h_gif87,'G','I','F','8','7','a');   H(h_gif89,'G','I','F','8','9','a');
H(f_gif,  0x00,0x3B);
H(h_bmp,  'B','M');
H(h_tiff1,'I','I',0x2A,0x00);         H(h_tiff2,'M','M',0x00,0x2A);
H(h_webp, 'R','I','F','F');
H(h_psd,  '8','B','P','S');
H(h_ico,  0x00,0x00,0x01,0x00);
H(h_heic, 'f','t','y','p','h','e','i','c');
H(h_pdf,  '%','P','D','F','-');
H(h_rtf,  '{','\\','r','t','f');
H(h_ole,  0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1);
H(h_zip,  'P','K',0x03,0x04);
H(h_rar4, 'R','a','r','!',0x1A,0x07,0x00);
H(h_rar5, 'R','a','r','!',0x1A,0x07,0x01,0x00);
H(h_7z,   '7','z',0xBC,0xAF,0x27,0x1C);
H(h_gz,   0x1F,0x8B,0x08);
H(h_bz2,  'B','Z','h');
H(h_xz,   0xFD,'7','z','X','Z',0x00);
H(h_cab,  'M','S','C','F',0x00,0x00,0x00,0x00);
H(h_mp3id,'I','D','3');
H(h_mp3fr,0xFF,0xFB);
H(h_wav,  'R','I','F','F');
H(h_flac, 'f','L','a','C');
H(h_ogg,  'O','g','g','S');
H(h_mid,  'M','T','h','d');
H(h_mp4,  'f','t','y','p');
H(h_mkv,  0x1A,0x45,0xDF,0xA3);
H(h_flv,  'F','L','V',0x01);
H(h_asf,  0x30,0x26,0xB2,0x75,0x8E,0x66,0xCF,0x11);
H(h_mz,   'M','Z');
H(h_elf,  0x7F,'E','L','F');
H(h_macho,0xCF,0xFA,0xED,0xFE);
H(h_dex,  'd','e','x',0x0A);
H(h_class,0xCA,0xFE,0xBA,0xBE);
H(h_sqlite,'S','Q','L','i','t','e',' ','f','o','r','m','a','t',' ','3',0x00);
H(h_evtx, 'E','l','f','F','i','l','e',0x00);
H(h_pst,  '!','B','D','N');
H(h_reg,  'r','e','g','f');
H(h_lnk,  0x4C,0x00,0x00,0x00,0x01,0x14,0x02,0x00);
H(h_pcap, 0xD4,0xC3,0xB2,0xA1);
H(h_pcapng,0x0A,0x0D,0x0D,0x0A);
H(h_eml,  'R','e','c','e','i','v','e','d',':',' ');
H(h_pem,  '-','-','-','-','-','B','E','G','I','N',' ');
H(h_pfx,  0x30,0x82);
H(h_iso,  'C','D','0','0','1');
H(h_vhd,  'c','o','n','e','c','t','i','x');
H(h_vmdk, 'K','D','M','V');
H(h_qcow, 'Q','F','I',0xFB);
H(h_sh,   '#','!','/');
H(h_xml,  '<','?','x','m','l');
H(h_html, '<','!','D','O','C','T','Y','P','E',' ','h','t','m','l');

#define SIG(ext, desc, cat, hdr, hoff, ftr, finc, maxs, mins, val) \
    { ext, desc, cat, hdr, sizeof hdr, hoff, ftr, sizeof ftr, finc, maxs, mins, val }
#define SIGN(ext, desc, cat, hdr, hoff, maxs, mins, val) \
    { ext, desc, cat, hdr, sizeof hdr, hoff, NULL, 0, 0, maxs, mins, val }

static const fg_sig g_sigs[] = {

SIG ("jpg",  "JPEG image",                  FG_CAT_IMAGE,   h_jpg,   0, f_jpg, 1, 200*MB, 128, v_jpeg),
SIG ("png",  "PNG image",                   FG_CAT_IMAGE,   h_png,   0, f_png, 1, 200*MB,  64, v_png),
SIG ("gif",  "GIF image (87a)",             FG_CAT_IMAGE,   h_gif87, 0, f_gif, 1,  64*MB,  32, v_gif),
SIG ("gif",  "GIF image (89a)",             FG_CAT_IMAGE,   h_gif89, 0, f_gif, 1,  64*MB,  32, v_gif),
SIGN("bmp",  "Windows bitmap",              FG_CAT_IMAGE,   h_bmp,   0,        512*MB,  54, v_bmp),
SIGN("tif",  "TIFF image (little endian)",  FG_CAT_IMAGE,   h_tiff1, 0,        512*MB,   8, v_tiff),
SIGN("tif",  "TIFF image (big endian)",     FG_CAT_IMAGE,   h_tiff2, 0,        512*MB,   8, v_tiff),
SIGN("webp", "WebP image",                  FG_CAT_IMAGE,   h_webp,  0,         64*MB,  20, v_riff),
SIGN("psd",  "Adobe Photoshop document",    FG_CAT_IMAGE,   h_psd,   0,          2*GB,  26, NULL),
SIGN("ico",  "Windows icon",                FG_CAT_IMAGE,   h_ico,   0,          2*MB,  22, NULL),
SIGN("heic", "HEIF/HEIC image",             FG_CAT_IMAGE,   h_heic,  4,        200*MB,  32, v_mp4),
SIGN("pdf",  "PDF document",                FG_CAT_DOCUMENT,h_pdf,   0,        512*MB, 300, v_pdf),
SIGN("rtf",  "Rich Text Format document",   FG_CAT_DOCUMENT,h_rtf,   0,        128*MB,  32, NULL),
SIGN("doc",  "OLE compound document (doc/xls/ppt/msg)", FG_CAT_DOCUMENT, h_ole, 0, 512*MB, 512, NULL),
SIGN("xml",  "XML document",                FG_CAT_DOCUMENT,h_xml,   0,         64*MB,  32, NULL),
SIGN("html", "HTML document",               FG_CAT_DOCUMENT,h_html,  0,         64*MB,  32, NULL),

SIGN("zip",  "ZIP archive (also docx/xlsx/pptx/jar/apk)", FG_CAT_ARCHIVE, h_zip, 0, 4*GB, 22, v_zip),
SIGN("rar",  "RAR archive (v4)",            FG_CAT_ARCHIVE, h_rar4,  0,          4*GB,  64, NULL),
SIGN("rar",  "RAR archive (v5)",            FG_CAT_ARCHIVE, h_rar5,  0,          4*GB,  64, NULL),
SIGN("7z",   "7-Zip archive",               FG_CAT_ARCHIVE, h_7z,    0,          8*GB,  32, v_7z),
SIGN("gz",   "gzip stream",                 FG_CAT_ARCHIVE, h_gz,    0,          4*GB,  20, NULL),
SIGN("bz2",  "bzip2 archive",               FG_CAT_ARCHIVE, h_bz2,   0,          4*GB,  14, NULL),
SIGN("xz",   "XZ archive",                  FG_CAT_ARCHIVE, h_xz,    0,          4*GB,  32, NULL),
SIGN("cab",  "Microsoft cabinet",           FG_CAT_ARCHIVE, h_cab,   0,          2*GB,  36, v_cab),

SIGN("mp3",  "MPEG audio (ID3v2)",          FG_CAT_AUDIO,   h_mp3id, 0,        512*MB, 128, v_mp3),
SIGN("mp3",  "MPEG audio (raw frame)",      FG_CAT_AUDIO,   h_mp3fr, 0,        512*MB, 128, v_mp3),
SIGN("wav",  "WAVE audio",                  FG_CAT_AUDIO,   h_wav,   0,          4*GB,  44, v_riff),
SIGN("flac", "FLAC audio",                  FG_CAT_AUDIO,   h_flac,  0,          2*GB,  42, NULL),
SIGN("ogg",  "Ogg container",               FG_CAT_AUDIO,   h_ogg,   0,          2*GB,  58, v_ogg),
SIGN("mid",  "MIDI sequence",               FG_CAT_AUDIO,   h_mid,   0,          8*MB,  22, NULL),
SIGN("mp4",  "ISO base media (mp4/mov/3gp)",FG_CAT_VIDEO,   h_mp4,   4,         16*GB, 128, v_mp4),
SIGN("mkv",  "Matroska / WebM",             FG_CAT_VIDEO,   h_mkv,   0,         16*GB, 128, NULL),
SIGN("flv",  "Flash video",                 FG_CAT_VIDEO,   h_flv,   0,          2*GB,  64, NULL),
SIGN("wmv",  "ASF / WMV container",         FG_CAT_VIDEO,   h_asf,   0,          8*GB, 128, NULL),

SIGN("exe",  "PE executable (exe/dll/sys)", FG_CAT_EXECUTABLE, h_mz, 0,          1*GB,  64, v_pe),
SIGN("elf",  "ELF binary",                  FG_CAT_EXECUTABLE, h_elf,0,          1*GB,  64, v_elf),
SIGN("macho","Mach-O binary",               FG_CAT_EXECUTABLE, h_macho,0,        1*GB,  64, NULL),
SIGN("dex",  "Android DEX bytecode",        FG_CAT_EXECUTABLE, h_dex, 0,       256*MB, 112, v_dex),
SIGN("class","Java class file",             FG_CAT_EXECUTABLE, h_class,0,        32*MB,  32, NULL),
SIGN("sh",   "Shell script",                FG_CAT_EXECUTABLE, h_sh,  0,          4*MB,   8, NULL),

SIGN("sqlite","SQLite 3 database",          FG_CAT_DATABASE,h_sqlite,0,          8*GB, 512, v_sqlite),
SIGN("evtx", "Windows event log",           FG_CAT_FORENSIC,h_evtx,  0,          2*GB,4096, v_evtx),
SIGN("pst",  "Outlook personal store",      FG_CAT_EMAIL,   h_pst,   0,         48*GB, 512, NULL),
SIGN("reg",  "Windows registry hive",       FG_CAT_FORENSIC,h_reg,   0,          2*GB,4096, NULL),
SIGN("lnk",  "Windows shortcut",            FG_CAT_FORENSIC,h_lnk,   0,          1*MB,  76, NULL),
SIGN("pcap", "libpcap capture",             FG_CAT_FORENSIC,h_pcap,  0,          8*GB,  24, NULL),
SIGN("pcapng","pcapng capture",             FG_CAT_FORENSIC,h_pcapng,0,          8*GB,  32, NULL),
SIGN("eml",  "RFC 822 e-mail message",      FG_CAT_EMAIL,   h_eml,   0,        128*MB, 128, NULL),

SIGN("pem",  "PEM key or certificate",      FG_CAT_CRYPTO,  h_pem,   0,          1*MB,  64, NULL),
SIGN("p12",  "DER/PKCS#12 container",       FG_CAT_CRYPTO,  h_pfx,   0,          1*MB,  64, NULL),

SIGN("iso",  "ISO 9660 optical image",      FG_CAT_DISKIMAGE,h_iso, 32769,      32*GB,2048, v_iso),
SIGN("vhd",  "Virtual hard disk",           FG_CAT_DISKIMAGE,h_vhd,   0,        64*GB, 512, NULL),
SIGN("vmdk", "VMware disk image",           FG_CAT_DISKIMAGE,h_vmdk,  0,        64*GB, 512, NULL),
SIGN("qcow2","QEMU copy-on-write image",    FG_CAT_DISKIMAGE,h_qcow,  0,        64*GB, 512, NULL)
};

const fg_sig *fg_sig_table(int *count)
{
    if (count) *count = (int)FG_ARRAY_LEN(g_sigs);
    return g_sigs;
}

const fg_sig *fg_sig_by_ext(const char *ext)
{
    size_t i;
    for (i = 0; i < FG_ARRAY_LEN(g_sigs); i++)
        if (fg_strcaseeq(g_sigs[i].ext, ext)) return &g_sigs[i];
    return NULL;
}


const fg_sig *fg_sig_match(const uint8_t *data, size_t n, const char *ext_hint)
{
    size_t i;
    const fg_sig *ext_fallback = NULL;
    for (i = 0; i < FG_ARRAY_LEN(g_sigs); i++) {
        const fg_sig *s = &g_sigs[i];
        if (ext_hint && !fg_strcaseeq(s->ext, ext_hint)) continue;
        if (!ext_fallback) ext_fallback = s;
        if (n >= s->header_off + s->header_len &&
            !memcmp(data + s->header_off, s->header, s->header_len))
            return s;
    }
    if (ext_hint) return ext_fallback;

    for (i = 0; i < FG_ARRAY_LEN(g_sigs); i++) {
        const fg_sig *s = &g_sigs[i];
        if (s->header_off) continue;
        if (n >= s->header_len && !memcmp(data, s->header, s->header_len)) return s;
    }
    return NULL;
}
