# Pin to amd64 — AFL++ QEMU mode and ASan are flaky under arm64 emulation
# of an arm64 image. Going amd64 throughout keeps host/grader symmetric.
FROM --platform=linux/amd64 aflplusplus/aflplusplus:latest

WORKDIR /work

# Most build deps come with the AFL++ image; keep this list small but explicit.
RUN apt-get update && apt-get install -y --no-install-recommends \
        wget patch zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# libpng 1.2.56 — see NOTES.md / report Q1 for rationale.
RUN wget -q https://download.sourceforge.net/libpng/libpng-1.2.56.tar.gz \
    && tar xzf libpng-1.2.56.tar.gz \
    && rm libpng-1.2.56.tar.gz

# CRC removal patch (shipped by AFL++). Without it, every mutated chunk fails
# CRC validation and we never reach the deeper parser.
COPY patches/ /work/patches/
RUN cd libpng-1.2.56 && patch -p0 < /work/patches/libpng-nocrc.patch

# ---- three library builds, all installed side-by-side ----
# 1. Instrumented + ASan: the main campaign target.
RUN cd libpng-1.2.56 && \
    make distclean 2>/dev/null || true; \
    CC=afl-clang-fast CXX=afl-clang-fast++ \
    CFLAGS="-fsanitize=address -g -O1" \
    LDFLAGS="-fsanitize=address" \
    ./configure --disable-shared --prefix=/work/install && \
    make -j"$(nproc)" && make install

# 2. Instrumented, NO sanitizer: needed for the Q8 "no-sanitizer + fork" config.
RUN cd libpng-1.2.56 && make distclean && \
    CC=afl-clang-fast CXX=afl-clang-fast++ \
    CFLAGS="-g -O1" \
    ./configure --disable-shared --prefix=/work/install_no_san && \
    make -j"$(nproc)" && make install

# 3. Vanilla gcc, no instrumentation, no sanitizer: the "closed-source" target
#    fed to AFL++ in QEMU mode. Keeps the CRC patch applied on purpose
#    (see libpng guide page 8 box "Why keep the CRC patch for QEMU mode?").
RUN cd libpng-1.2.56 && make distclean && \
    CC=gcc CFLAGS="-g -O1" \
    ./configure --disable-shared --prefix=/work/install_vanilla && \
    make -j"$(nproc)" && make install

# ---- harness binaries ----
COPY src/ /work/src/

# Main campaign harness: instrumented + ASan, fork-server mode.
RUN afl-clang-fast /work/src/harness.c \
        -I/work/install/include -L/work/install/lib \
        -fsanitize=address -g -O1 \
        -lpng12 -lz -lm \
        -o /work/png_fuzz

# Q8 config (1): instrumented, no sanitizer, fork-server mode.
RUN afl-clang-fast /work/src/harness.c \
        -I/work/install_no_san/include -L/work/install_no_san/lib \
        -g -O1 \
        -lpng12 -lz -lm \
        -o /work/png_fuzz_no_san

# Q8 config (3): instrumented + ASan, persistent loop.
RUN afl-clang-fast /work/src/harness_persistent.c \
        -I/work/install/include -L/work/install/lib \
        -fsanitize=address -g -O1 \
        -lpng12 -lz -lm \
        -o /work/png_fuzz_persistent

# QEMU-mode target: vanilla gcc, no instrumentation, no sanitizer.
RUN gcc /work/src/harness.c \
        -I/work/install_vanilla/include -L/work/install_vanilla/lib \
        -g -O1 \
        -lpng12 -lz -lm \
        -o /work/png_fuzz_qemu

# Seeds + dictionary.
COPY seeds/ /work/seeds/
RUN cp /AFLplusplus/dictionaries/png.dict /work/png.dict

# Findings dirs are bind-mounted at runtime, but pre-create them so afl-fuzz
# doesn't fail if someone runs the image without mounts.
RUN mkdir -p /work/findings /work/findings-qemu

# Knobs that smooth over Mac/Docker quirks (no host /proc/sys access etc.).
ENV AFL_SKIP_CPUFREQ=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_NO_AFFINITY=1 \
    AFL_AUTORESUME=1

CMD ["/bin/bash"]
