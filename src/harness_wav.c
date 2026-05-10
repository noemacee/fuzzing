#include "SDL.h"
#include <stdio.h>
#include <stdlib.h>

/* Entry point for SDL WAV fuzzing.
 *
 * Target surface: SDL_LoadWAV_RW → InitMS_ADPCM / MS_ADPCM_decode
 *                                → InitIMA_ADPCM / IMA_ADPCM_decode
 * Known CVEs reachable from this call:
 *   CVE-2019-7572  heap over-read  InitIMA_ADPCM (SDL_wave.c)
 *   CVE-2019-7573  heap over-read  InitMS_ADPCM  (SDL_wave.c)
 *   CVE-2019-7574  heap over-read  IMA_ADPCM_decode (SDL_wave.c)
 *   CVE-2019-7575  heap overflow   MS_ADPCM_decode  (SDL_wave.c)
 *   CVE-2019-7576  heap over-read  InitMS_ADPCM  (SDL_wave.c)
 *   CVE-2019-7578  heap over-read  InitIMA_ADPCM (SDL_wave.c)
 *
 * Design choices:
 * - SDL_Init(0): initialises SDL internals without starting video or audio
 *   output subsystems.  SDL_LoadWAV_RW is a pure file-parsing function that
 *   does not require either subsystem.
 * - No setjmp needed: SDL signals errors via return value (NULL / 0), not
 *   longjmp.  Malformed inputs are silently rejected; only real memory bugs
 *   (caught by ASan) cause a non-zero exit.
 * - freesrc=1: SDL closes and frees the SDL_RWops after reading, so we do
 *   not double-free.
 */

int main(int argc, char **argv) {
    if (argc < 2) return 1;

    SDL_Init(0);

    SDL_RWops *rw = SDL_RWFromFile(argv[1], "rb");
    if (!rw) {
        SDL_Quit();
        return 0;
    }

    SDL_AudioSpec spec;
    Uint8 *buf = NULL;
    Uint32 len = 0;

    /* freesrc=1: SDL_RWclose is called on rw whether loading succeeds or not. */
    SDL_LoadWAV_RW(rw, 1, &spec, &buf, &len);
    if (buf)
        SDL_FreeWAV(buf);

    SDL_Quit();
    return 0;
}
