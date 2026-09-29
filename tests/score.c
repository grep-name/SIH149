#include "forge/fg_common.h"
#include "forge/fg_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[64];
    char state[16];
    char sha[80];
    uint64_t size;
    int found;
    char found_as[128];
    char method[40];
    int confidence;
} row;

static char *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    char *b;
    long n;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    b = (char *)malloc((size_t)n + 1);
    if (!b) { fclose(f); return NULL; }
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { /* short read is fine */ }
    b[n] = '\0';
    fclose(f);
    if (len) *len = (size_t)n;
    return b;
}

int main(int argc, char **argv)
{
    char *csv, *json;
    row rows[128];
    int nrows = 0, i;
    fg_jval *doc, *files;
    int expected = 0, recovered = 0, live_seen = 0;

    if (argc != 3) {
        fprintf(stderr, "usage: forge_score <manifest.csv> <report.json>\n");
        return 2;
    }
    csv  = slurp(argv[1], NULL);
    json = slurp(argv[2], NULL);
    if (!csv)  { fprintf(stderr, "cannot read %s\n", argv[1]); return 1; }
    if (!json) { fprintf(stderr, "cannot read %s\n", argv[2]); return 1; }

    {
        char *line = strtok(csv, "\r\n");
        line = strtok(NULL, "\r\n");
        while (line && nrows < 128) {
            char *f[5];
            int k = 0;
            char *p = line;
            while (k < 5 && p) {
                f[k++] = p;
                p = strchr(p, ',');
                if (p) *p++ = '\0';
            }
            if (k == 5) {
                row *r = &rows[nrows++];
                memset(r, 0, sizeof *r);
                snprintf(r->name,  sizeof r->name,  "%s", f[0]);
                snprintf(r->state, sizeof r->state, "%s", f[1]);
                r->size = strtoull(f[3], NULL, 10);
                snprintf(r->sha, sizeof r->sha, "%s", f[4]);
            }
            line = strtok(NULL, "\r\n");
        }
    }

    doc = fg_json_parse(json);
    if (!doc) { fprintf(stderr, "could not parse %s as JSON\n", argv[2]); return 1; }
    files = fg_json_get(doc, "recovered_files");
    if (!files || files->type != FG_JS_ARR) {
        fprintf(stderr, "report has no recovered_files array\n");
        return 1;
    }
    {
        fg_jval *e;
        for (e = files->child; e; e = e->next) {
            const char *sha = fg_json_gets(e, "sha256", "");
            for (i = 0; i < nrows; i++) {
                if (rows[i].found) continue;
                if (!fg_strcaseeq(rows[i].sha, sha)) continue;
                rows[i].found = 1;
                snprintf(rows[i].found_as, sizeof rows[i].found_as, "%s",
                         fg_json_gets(e, "name", "?"));
                snprintf(rows[i].method, sizeof rows[i].method, "%s",
                         fg_json_gets(e, "recovery_method", "?"));
                rows[i].confidence = (int)fg_json_getn(e, "confidence", 0);
                break;
            }
        }
    }

    printf("\nRECOVERY SCORECARD\n");
    printf("manifest : %s\nreport   : %s\n\n", argv[1], argv[2]);
    printf("  %-14s %-11s %9s  %-8s %-24s %s\n",
           "ARTEFACT", "PLANTED AS", "SIZE", "RESULT", "RECOVERY METHOD", "RECOVERED AS");
    printf("  %.*s\n", 104,
           "--------------------------------------------------------------"
           "--------------------------------------------------------------");
    for (i = 0; i < nrows; i++) {
        int must = strcmp(rows[i].state, "live") != 0;
        const char *verdict;
        if (must) {
            expected++;
            if (rows[i].found) recovered++;
            verdict = rows[i].found ? "PASS" : "MISS";
        } else {
            if (rows[i].found) live_seen++;
            verdict = rows[i].found ? "(live)" : "(live)";
        }
        printf("  %-14s %-11s %9llu  %-8s %-24s %s%s\n",
               rows[i].name, rows[i].state, (unsigned long long)rows[i].size,
               verdict, rows[i].found ? rows[i].method : "-",
               rows[i].found ? rows[i].found_as : "-",
               rows[i].found && must ? "" : "");
    }

    printf("\n  Target artefacts       : %d\n", expected);
    printf("  Recovered byte-exact   : %d\n", recovered);
    printf("  Recovery rate          : %.1f%%\n",
           expected ? recovered * 100.0 / expected : 0.0);
    printf("  Live files also carved : %d (expected: content carving cannot\n"
           "                           tell allocated from unallocated data\n"
           "                           unless --unallocated-only is used)\n\n",
           live_seen);

    free(csv);
    free(json);
    fg_json_free(doc);
    return recovered == expected ? 0 : 1;
}
