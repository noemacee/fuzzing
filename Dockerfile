FROM aflplusplus/aflplusplus:latest

WORKDIR /work

# SDL 1.2.15 needs standard build tools only; no X11 or system audio required.
RUN apt-get update && apt-get install -y --no-install-recommends \
        wget \
    && rm -rf /var/lib/apt/lists/*

# SDL 1.2.15 — last stable 1.2.x release; contains CVE-2019-7572 … CVE-2019-7578
# (ADPCM heap overflows in SDL_wave.c) and CVE-2019-7635 … CVE-2019-7638
# (heap over-read/overflow in pixel-format conversion).
RUN wget -q https://www.libsdl.org/release/SDL-1.2.15.tar.gz \
    && tar xzf SDL-1.2.15.tar.gz \
    && rm SDL-1.2.15.tar.gz

# No CRC / checksum patch needed — WAV (RIFF) and BMP have no integrity check
# that would cause the parser to reject mutated inputs early.

# Shared configure options: disable all platform display/audio backends so the
# build requires no system headers (X11, ALSA, OSS, …).  The null/dummy
# backends are compiled automatically when every platform backend is disabled.
# We only need SDL_LoadWAV_RW (audio/SDL_wave.c) and SDL_LoadBMP_RW
# (video/SDL_bmp.c) — both are pure file-I/O functions that compile regardless
# of which backend is chosen.
ENV SDL_CFG="--disable-shared \
    --without-x \
    --disable-video-x11 --disable-video-dga --disable-video-fbcon \
    --disable-video-directfb --disable-video-opengl --disable-video-aalib \
    --disable-alsa --disable-oss --disable-esd --disable-arts --disable-nas \
    --disable-joystick --disable-cdrom"

# SDL 1.2.15 ships a very old config.guess that does not recognise the
# aarch64-linux kernel triple used inside Docker on Apple Silicon.
# --build=$(gcc -dumpmachine) bypasses config.guess entirely and tells
# autoconf the exact host triple directly.

# 1. Instrumented + ASan: main campaign target.
RUN cd SDL-1.2.15 && \
    CC=afl-clang-fast CXX=afl-clang-fast++ \
    CFLAGS="-fsanitize=address -g -O1" \
    LDFLAGS="-fsanitize=address" \
    ./configure --build=$(gcc -dumpmachine) $SDL_CFG --prefix=/work/install && \
    make -j"$(nproc)" && make install

# 2. Instrumented, no ASan: Q8 "no-sanitizer + fork" comparison config.
RUN cd SDL-1.2.15 && make distclean && \
    CC=afl-clang-fast CXX=afl-clang-fast++ \
    CFLAGS="-g -O1" \
    ./configure --build=$(gcc -dumpmachine) $SDL_CFG --prefix=/work/install_no_san && \
    make -j"$(nproc)" && make install

# 3. Vanilla gcc, no instrumentation: black-box target for QEMU mode.
RUN cd SDL-1.2.15 && make distclean && \
    CC=gcc CFLAGS="-g -O1" \
    ./configure --build=$(gcc -dumpmachine) $SDL_CFG --prefix=/work/install_vanilla && \
    make -j"$(nproc)" && make install

# ---- harness binaries ----
COPY src/ /work/src/

# Main campaign: WAV/ADPCM harness, instrumented + ASan, fork-server mode.
# Targets CVE-2019-7572 … CVE-2019-7578 in SDL_wave.c ADPCM decoders.
RUN afl-clang-fast /work/src/harness_wav.c \
        -I/work/install/include/SDL -L/work/install/lib \
        -fsanitize=address -g -O1 \
        -lSDL -lm \
        -o /work/sdl_wav_fuzz

# BMP harness, instrumented + ASan, fork-server mode.
# Targets CVE-2019-7635 … CVE-2019-7638 in SDL pixel-format conversion.
RUN afl-clang-fast /work/src/harness_bmp.c \
        -I/work/install/include/SDL -L/work/install/lib \
        -fsanitize=address -g -O1 \
        -lSDL -lm \
        -o /work/sdl_bmp_fuzz

# Q8 config (1): instrumented, no ASan, fork mode.
RUN afl-clang-fast /work/src/harness_wav.c \
        -I/work/install_no_san/include/SDL -L/work/install_no_san/lib \
        -g -O1 -lSDL -lm \
        -o /work/sdl_wav_fuzz_no_san

# Q8 config (3): instrumented + ASan, persistent loop.
RUN afl-clang-fast /work/src/harness_wav_persistent.c \
        -I/work/install/include/SDL -L/work/install/lib \
        -fsanitize=address -g -O1 \
        -lSDL -lm \
        -o /work/sdl_wav_fuzz_persistent

# QEMU-mode targets: vanilla gcc, no instrumentation.
RUN gcc /work/src/harness_wav.c \
        -I/work/install_vanilla/include/SDL -L/work/install_vanilla/lib \
        -g -O1 -lSDL -lm \
        -o /work/sdl_wav_fuzz_qemu

RUN gcc /work/src/harness_bmp.c \
        -I/work/install_vanilla/include/SDL -L/work/install_vanilla/lib \
        -g -O1 -lSDL -lm \
        -o /work/sdl_bmp_fuzz_qemu

# Seeds (WAV and BMP) + custom dictionary.
COPY seeds/ /work/seeds/
COPY sdl.dict /work/sdl.dict

RUN mkdir -p /work/findings /work/findings-qemu

# SDL_VIDEODRIVER=dummy prevents SDL_Init from trying to open a real display
# in the headless container (needed for SDL_LoadBMP_RW surface operations).
ENV AFL_SKIP_CPUFREQ=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_NO_AFFINITY=1 \
    AFL_AUTORESUME=1 \
    SDL_VIDEODRIVER=dummy \
    SDL_AUDIODRIVER=dummy

CMD ["/bin/bash"]
