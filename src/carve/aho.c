#include "forge/fg_carve.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    int32_t  next[256];
    int32_t  fail;
    int32_t  out;
    int32_t  out_link;
    uint16_t depth;
} ac_node;

struct fg_ac {
    ac_node  *nodes;
    int       count;
    int       cap;
    int       state;
    const fg_sig *sigs;
    int       nsigs;
};

static int ac_new_node(fg_ac *ac)
{
    if (ac->count == ac->cap) {
        int ncap = ac->cap ? ac->cap * 2 : 256;
        ac_node *n = (ac_node *)realloc(ac->nodes, (size_t)ncap * sizeof *n);
        if (!n) return -1;
        ac->nodes = n;
        ac->cap = ncap;
    }
    {
        ac_node *n = &ac->nodes[ac->count];
        int i;
        for (i = 0; i < 256; i++) n->next[i] = -1;
        n->fail = 0;
        n->out = -1;
        n->out_link = -1;
        n->depth = 0;
    }
    return ac->count++;
}

fg_status fg_ac_build(fg_ac **out, const fg_sig *sigs, int nsigs, const int *enabled)
{
    fg_ac *ac;
    int i, *queue, qh = 0, qt = 0;

    if (!out || !sigs || nsigs <= 0) return FG_ERR_INVALID;
    ac = (fg_ac *)fg_xcalloc(1, sizeof *ac);
    if (!ac) return FG_ERR_NOMEM;
    ac->sigs = sigs;
    ac->nsigs = nsigs;
    if (ac_new_node(ac) < 0) { free(ac); return FG_ERR_NOMEM; }   /* root */

    for (i = 0; i < nsigs; i++) {
        const fg_sig *s = &sigs[i];
        int cur = 0;
        size_t k;
        if (enabled && !enabled[i]) continue;
        for (k = 0; k < s->header_len; k++) {
            uint8_t c = s->header[k];
            if (ac->nodes[cur].next[c] < 0) {
                int nn = ac_new_node(ac);
                if (nn < 0) { fg_ac_free(ac); return FG_ERR_NOMEM; }
                ac->nodes[cur].next[c] = nn;
                ac->nodes[nn].depth = (uint16_t)(k + 1);
            }
            cur = ac->nodes[cur].next[c];
        }

        if (ac->nodes[cur].out < 0) {
            ac->nodes[cur].out = i;
        } else {
            int nn = ac_new_node(ac);
            if (nn < 0) { fg_ac_free(ac); return FG_ERR_NOMEM; }
            ac->nodes[nn].out = i;
            ac->nodes[nn].out_link = ac->nodes[cur].out_link;
            ac->nodes[nn].depth = ac->nodes[cur].depth;
            ac->nodes[cur].out_link = nn;
        }
    }

    
    queue = (int *)fg_xcalloc((size_t)ac->count, sizeof *queue);
    if (!queue) { fg_ac_free(ac); return FG_ERR_NOMEM; }
    for (i = 0; i < 256; i++) {
        int t = ac->nodes[0].next[i];
        if (t < 0) ac->nodes[0].next[i] = 0;
        else { ac->nodes[t].fail = 0; queue[qt++] = t; }
    }
    while (qh < qt) {
        int u = queue[qh++];
        int c;
        for (c = 0; c < 256; c++) {
            int v = ac->nodes[u].next[c];
            if (v < 0) {
                ac->nodes[u].next[c] = ac->nodes[ac->nodes[u].fail].next[c];
            } else {
                ac->nodes[v].fail = ac->nodes[ac->nodes[u].fail].next[c];
                queue[qt++] = v;
            }
        }
    }
    free(queue);

    *out = ac;
    return FG_OK;
}

void fg_ac_reset(fg_ac *ac) { if (ac) ac->state = 0; }

void fg_ac_scan(fg_ac *ac, const uint8_t *chunk, size_t n,
                uint64_t abs_base, fg_ac_hit_fn cb, void *user)
{
    int st = ac->state;
    const ac_node *nodes = ac->nodes;
    size_t i;

    for (i = 0; i < n; i++) {
        int node;
        st = nodes[st].next[chunk[i]];
        
        node = st;
        while (node > 0) {
            int o = nodes[node].out;
            int chain = nodes[node].out_link;
            if (o >= 0) {
                const fg_sig *s = &ac->sigs[o];
                uint64_t match_end = abs_base + i + 1;
                uint64_t hdr_start = match_end - s->header_len;
                if (hdr_start >= s->header_off)
                    cb(user, hdr_start - s->header_off, o);
            }
            while (chain >= 0) {
                int o2 = nodes[chain].out;
                if (o2 >= 0) {
                    const fg_sig *s2 = &ac->sigs[o2];
                    uint64_t match_end = abs_base + i + 1;
                    uint64_t hdr_start = match_end - s2->header_len;
                    if (hdr_start >= s2->header_off)
                        cb(user, hdr_start - s2->header_off, o2);
                }
                chain = nodes[chain].out_link;
            }
            node = nodes[node].fail;
            if (node == 0) break;
        }
    }
    ac->state = st;
}

void fg_ac_free(fg_ac *ac)
{
    if (!ac) return;
    free(ac->nodes);
    free(ac);
}
