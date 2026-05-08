#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <setjmp.h>
#include <png.h>

#define MAX_DIM 4096

__AFL_FUZZ_INIT();

typedef struct {
    const unsigned char *data;
    size_t len;
    size_t pos;
} buf_t;

static void buf_read(png_structp png, png_bytep dst, png_size_t n) {
    buf_t *b = (buf_t *)png_get_io_ptr(png);
    if (b->pos + n > b->len)
        png_error(png, "short read");
    memcpy(dst, b->data + b->pos, n);
    b->pos += n;
}

int main(void) {
    /* Deferred fork-server: AFL forks here, after libc/dlopen overhead
     * but before the per-input loop body. */
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < 8) continue;  /* shorter than the PNG signature */

        buf_t b = { buf, (size_t)len, 0 };

        png_structp png = png_create_read_struct(
            PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
        if (!png) continue;
        png_infop info = png_create_info_struct(png);
        if (!info) { png_destroy_read_struct(&png, NULL, NULL); continue; }

        png_bytepp  volatile rows       = NULL;
        png_uint_32 volatile rows_alloc = 0;

        if (setjmp(png_jmpbuf(png))) {
            if (rows) {
                for (png_uint_32 i = 0; i < rows_alloc; i++) free(rows[i]);
                free((void *)rows);
            }
            png_destroy_read_struct(&png, &info, NULL);
            continue;
        }

        png_set_read_fn(png, &b, buf_read);
        png_read_info(png, info);

        png_uint_32 w = png_get_image_width(png, info);
        png_uint_32 h = png_get_image_height(png, info);
        if (w == 0 || h == 0 || w > MAX_DIM || h > MAX_DIM)
            png_error(png, "dimension out of bounds");

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
    }
    return 0;
}
