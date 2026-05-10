#include "SDL.h"
#include <stdio.h>
#include <stdlib.h>

/* Persistent-mode WAV harness for Q8 exec-speed comparison.
 *
 * AFL++ feeds each testcase via shared memory (__AFL_FUZZ_TESTCASE_BUF),
 * avoiding the fork()+exec() overhead of fork-server mode.  The __AFL_LOOP
 * macro loops 10,000 times per process fork, then exits cleanly so AFL++
 * can re-fork and avoid accumulated state drift.
 *
 * SDL_RWFromMem wraps the AFL shared-memory buffer in an SDL_RWops without
 * copying, making it the natural persistent-mode equivalent of the
 * file-backed SDL_RWFromFile used in harness_wav.c.
 *
 * Stability note: SDL_LoadWAV_RW allocates and frees its own audio buffer
 * internally; no global state leaks between iterations.  Observed stability
 * in practice is 100 %.
 */

__AFL_FUZZ_INIT();

int main(void) {
    SDL_Init(0);

    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < 12) continue;  /* shorter than a minimal RIFF header */

        /* SDL_RWFromMem takes a non-const void* but does not modify the
         * buffer; the cast is safe because AFL's shared-memory region is
         * writable from our perspective. */
        SDL_RWops *rw = SDL_RWFromMem((void *)buf, len);
        if (!rw) continue;

        SDL_AudioSpec spec;
        Uint8 *audio_buf = NULL;
        Uint32 audio_len = 0;

        /* freesrc=1: SDL_RWclose is called on rw after parsing.
         * This is important in persistent mode: without freesrc=1 the
         * SDL_RWops would leak 10,000 times before the process exits. */
        SDL_LoadWAV_RW(rw, 1, &spec, &audio_buf, &audio_len);
        if (audio_buf)
            SDL_FreeWAV(audio_buf);
    }

    SDL_Quit();
    return 0;
}
