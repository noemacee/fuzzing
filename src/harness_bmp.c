#include "SDL.h"
#include <stdio.h>
#include <stdlib.h>

/* Entry point for SDL BMP fuzzing.
 *
 * Target surface: SDL_LoadBMP_RW → BMP header parsing + pixel-format
 *                                  conversion (SDL_bmp.c, SDL_pixels.c)
 * Known CVEs potentially reachable:
 *   CVE-2019-7635  heap over-read  Blit1to4 (SDL_blit_1.c)
 *   CVE-2019-7636  heap over-read  SDL_GetRGB (SDL_pixel.c)
 *   CVE-2019-7637  heap overflow   SDL_FillRect (SDL_surface.c)
 *   CVE-2019-7638  heap over-read  Map1toN (SDL_pixels.c)
 *
 * SDL_VIDEODRIVER=dummy (set in Dockerfile ENV) allows SDL_Init(SDL_INIT_VIDEO)
 * to succeed in the headless container, which is required by
 * SDL_CreateRGBSurface and SDL_BlitSurface.
 *
 * The blit step (SDL_CreateRGBSurface + SDL_BlitSurface) is included because
 * several BMP CVEs live in the pixel-format conversion path that runs during
 * a surface-to-surface blit, not during the initial load.  Without it,
 * coverage of the pixel-conversion code is minimal.
 */

int main(int argc, char **argv) {
    if (argc < 2) return 1;

    /* SDL_VIDEODRIVER=dummy is set in the container environment; this call
     * will succeed even without a physical display. */
    SDL_Init(SDL_INIT_VIDEO);

    SDL_RWops *rw = SDL_RWFromFile(argv[1], "rb");
    if (!rw) {
        SDL_Quit();
        return 0;
    }

    /* freesrc=1 — SDL frees the RWops on return (success or error). */
    SDL_Surface *src = SDL_LoadBMP_RW(rw, 1);
    if (src) {
        /* Convert to 32-bit ARGB: exercises Blit1to4, Map1toN, SDL_GetRGB
         * across whatever colour depth the fuzz input claims. */
        SDL_Surface *dst = SDL_CreateRGBSurface(
            SDL_SWSURFACE, src->w, src->h, 32,
            0x00FF0000u, 0x0000FF00u, 0x000000FFu, 0xFF000000u);
        if (dst) {
            SDL_BlitSurface(src, NULL, dst, NULL);
            SDL_FreeSurface(dst);
        }
        SDL_FreeSurface(src);
    }

    SDL_Quit();
    return 0;
}
