#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>

/*
 * Fuzzing harness targeting CVE-2016-10087.
 *
 * The harness hardcodes the vulnerable API sequence after png_read_info:
 *   png_free_data(PNG_FREE_TEXT, -1)  -- leaves max_text stale, zeroes text
 *   png_set_text(1 entry)             -- skips realloc if max_text > 0,
 *                                        dereferences NULL text ptr -> crash
 *
 * AFL only needs to find an input that makes libpng process at least one
 * tEXt/zTXt/iTXt chunk (so that max_text > 0 after png_read_info).
 * The content of the chunk is irrelevant; any value triggers the crash.
 *
 * Seed: poc_cve_2016_10087.png (valid PNG with one tEXt chunk).
 * CRC patch must be applied so AFL mutations don't die on bad CRCs.
 */

#define MAX_DIM 4096

int main(int argc, char **argv) {
    if (argc < 2) return 1;

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) return 0;

    png_structp png = png_create_read_struct(
        PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) { fclose(fp); return 0; }

    png_infop info = png_create_info_struct(png);
    if (!info) {
        png_destroy_read_struct(&png, NULL, NULL);
        fclose(fp);
        return 0;
    }

    /* Catch all libpng errors so malformed inputs don't look like crashes. */
    if (setjmp(png_jmpbuf(png))) {
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return 0;
    }

    png_init_io(png, fp);

    /* Processes all pre-IDAT chunks, including tEXt/zTXt/iTXt.
     * If a text chunk is present: max_text=9, num_text>=1, text=<allocated>. */
    png_read_info(png, info);

    png_uint_32 w = png_get_image_width(png, info);
    png_uint_32 h = png_get_image_height(png, info);
    if (w == 0 || h == 0 || w > MAX_DIM || h > MAX_DIM)
        png_error(png, "dimension out of bounds");

    /* --- CVE-2016-10087 trigger sequence --- */

    /* Step 1: free text — sets text=NULL, num_text=0, leaves max_text stale */
    png_free_data(png, info, PNG_FREE_TEXT, -1);

    /* Step 2: add text — if max_text > 0: skips realloc, deref NULL -> crash.
     *                     if max_text == 0: fresh allocation, no crash.
     * AFL needs to generate inputs where max_text > 0, i.e. inputs that
     * contain at least one tEXt/zTXt/iTXt chunk. */
    png_text t;
    memset(&t, 0, sizeof(t));
    t.compression = PNG_TEXT_COMPRESSION_NONE;
    t.key         = "Key";
    t.text        = "Value";
    t.text_length = 5;
    png_set_text(png, info, &t, 1);

    png_destroy_read_struct(&png, &info, NULL);
    fclose(fp);
    return 0;
}
