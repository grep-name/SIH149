#include "forge/fg_carve.h"
#include <string.h>
#include <stdio.h>


fg_category fg_classify(const uint8_t *data, size_t n, const fg_sig *sig)
{
    size_t i, printable = 0, nulls = 0, look;
    double h;

    if (sig && sig->category != FG_CAT_UNKNOWN) {

        if (sig->category == FG_CAT_ARCHIVE && n > 64 && !memcmp(data, "PK\3\4", 4)) {
            const char *hay = (const char *)data;
            size_t lim = FG_MIN(n, (size_t)4096);
            for (i = 0; i + 19 < lim; i++) {
                if (!memcmp(hay + i, "[Content_Types].xml", 19)) return FG_CAT_DOCUMENT;
                if (!memcmp(hay + i, "AndroidManifest.xml", 19)) return FG_CAT_EXECUTABLE;
                if (!memcmp(hay + i, "mimetypeapplication", 19)) return FG_CAT_DOCUMENT;
            }
        }
        return sig->category;
    }

    if (!n) return FG_CAT_UNKNOWN;
    look = FG_MIN(n, (size_t)8192);
    for (i = 0; i < look; i++) {
        uint8_t c = data[i];
        if (c == 0) nulls++;
        else if ((c >= 0x20 && c < 0x7F) || c == '\t' || c == '\n' || c == '\r') printable++;
    }
    h = fg_shannon_entropy(data, look);

    if (printable * 100 / look > 92 && nulls == 0) {

        const char *t = (const char *)data;
        if (look > 16 && (!memcmp(t, "From: ", 6) || !memcmp(t, "Received:", 9) ||
                          !memcmp(t, "Return-Path:", 12)))
            return FG_CAT_EMAIL;
        if (look > 16 && !memcmp(t, "-----BEGIN ", 11)) return FG_CAT_CRYPTO;
        return FG_CAT_DOCUMENT;
    }
    if (h > 7.95) return FG_CAT_ARCHIVE;
    return FG_CAT_UNKNOWN;
}


int fg_confidence_score(fg_recovered *r, const uint8_t *data, size_t n,
                        const fg_sig *sig)
{
    int score;
    char why[192];
    size_t used = 0;
    double h;

    switch (r->method) {
    case FG_REC_METADATA:  score = 70; break;
    case FG_REC_STRUCTURE: score = 60; break;
    case FG_REC_FRAGMENT:  score = 35; break;
    case FG_REC_SLACK:     score = 25; break;
    default:               score = 30; break;
    }
    why[0] = '\0';
#define ADD(fmt, ...) do { \
        int _w = snprintf(why + used, sizeof why - used, \
                          used ? "; " fmt : fmt, ##__VA_ARGS__); \
        if (_w > 0 && used + (size_t)_w < sizeof why) used += (size_t)_w; \
    } while (0)

    ADD("%s recovery", fg_rec_method_name(r->method));

    if (r->header_ok)    { score += 8;  ADD("header valid"); }
    if (r->structure_ok) { score += 15; ADD("structure parsed to exact length"); }
    if (r->footer_ok)    { score += 10; ADD("footer present"); }
    if (r->checksum_ok)  { score += 15; ADD("internal checksum verified"); }


    if (sig) {
        if (r->size < sig->min_size)      { score -= 25; ADD("smaller than the format allows"); }
        else if (r->size > sig->max_size) { score -= 15; ADD("exceeds the expected maximum size"); }
    }
    if (r->size == 0) return 0;

    h = n ? fg_shannon_entropy(data, FG_MIN(n, (size_t)65536)) : 0.0;
    r->entropy = h;
    if (sig) {
        int compressed = (sig->category == FG_CAT_ARCHIVE ||
                          sig->category == FG_CAT_VIDEO ||
                          sig->category == FG_CAT_AUDIO ||
                          !strcmp(sig->ext, "jpg") || !strcmp(sig->ext, "png"));
        if (compressed && h < 4.0)      { score -= 30; ADD("content entropy too low for this format"); }
        else if (compressed && h > 7.0) { score += 5;  ADD("entropy consistent with the format"); }
        if (!compressed && h > 7.95 && sig->category == FG_CAT_DOCUMENT) {
            score -= 10; ADD("entropy suggests the body was overwritten with random data");
        }
    }

    if (h < 0.5 && r->size > 4096 && !r->structure_ok) {
        score -= 40;
        ADD("body is almost entirely one repeated byte");
    }

    if (r->fragments > 1) { score -= 10; ADD("reassembled from %d fragments", r->fragments); }
    if (r->overwritten_risk > 50) {
        score -= r->overwritten_risk / 5;
        ADD("clusters show %d%% risk of reallocation", r->overwritten_risk);
    }

    if (r->method != FG_REC_METADATA &&
        !r->structure_ok && !r->footer_ok && !r->checksum_ok) {
        if (score > 25) score = 25;
        ADD("no corroborating structure, footer or checksum");
    }

    if (score < 0) score = 0;
    if (score > 100) score = 100;
    r->confidence = score;
    snprintf(r->confidence_why, sizeof r->confidence_why, "%s", why);
#undef ADD
    return score;
}

const char *fg_rec_method_name(fg_rec_method m)
{
    switch (m) {
    case FG_REC_METADATA:  return "filesystem metadata";
    case FG_REC_STRUCTURE: return "structure-based carving";
    case FG_REC_SIGNATURE: return "signature carving";
    case FG_REC_FRAGMENT:  return "fragment reassembly";
    case FG_REC_SLACK:     return "slack-space";
    }
    return "unknown";
}
