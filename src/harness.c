#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <png.h>  /* must come before any setjmp.h include — see libpng pngconf.h */

/* Reject implausibly large headers up front so libpng doesn't try to
 * malloc several GB and abort before we ever exercise the parser. */
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

    /* Pointers that may be allocated past setjmp must be volatile, otherwise
     * the longjmp-driven cleanup may see register-cached stale values. */
    png_bytepp  volatile rows       = NULL;
    png_uint_32 volatile rows_alloc = 0;

    /* libpng signals all parser errors through longjmp. Without this catch
     * every malformed input would abort the process and AFL would record it
     * as a crash. */
    if (setjmp(png_jmpbuf(png))) {
        if (rows) {
            for (png_uint_32 i = 0; i < rows_alloc; i++) free(rows[i]);
            free((void *)rows);
        }
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return 0;
    }

    png_init_io(png, fp);
    png_read_info(png, info);

    png_uint_32 w = png_get_image_width(png, info);
    png_uint_32 h = png_get_image_height(png, info);
    if (w == 0 || h == 0 || w > MAX_DIM || h > MAX_DIM)
        png_error(png, "dimension out of bounds");

    /* Three transformations widen the reachable surface considerably.
     * png_set_expand pulls in palette/tRNS/low-bit-grayscale expansion,
     * which is where CVE-2015-8126 (PLTE overflow) historically lived. */
    png_set_expand(png);
    png_set_strip_16(png);
    png_set_gray_to_rgb(png);

    png_read_update_info(png, info);

    size_t rowbytes = png_get_rowbytes(png, info);
    rows = (png_bytepp)malloc(h * sizeof(png_bytep));
    if (!rows) png_error(png, "row pointer array alloc");
    for (png_uint_32 i = 0; i < h; i++) {
        rows[i] = (png_bytep)malloc(rowbytes);
        if (!rows[i]) png_error(png, "row alloc");
        rows_alloc = i + 1;
    }

    png_read_image(png, (png_bytepp)rows);
    png_read_end(png, info);

    for (png_uint_32 i = 0; i < rows_alloc; i++) free(rows[i]);
    free((void *)rows);
    png_destroy_read_struct(&png, &info, NULL);
    fclose(fp);
    return 0;
}
