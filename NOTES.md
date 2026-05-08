# NOTES — decision log

Records the key choices made in this project (target version, architecture,
harness shape, patches) and the issues encountered and resolved during setup.

---

## Target choice

**libpng 1.2.56**, downloaded from sourceforge:
`https://download.sourceforge.net/libpng/libpng-1.2.56.tar.gz`

Why this version:
- AFL++ ships `utils/libpng_no_checksum/libpng-nocrc.patch` written for the 1.2.x series — applies cleanly with `patch -p0`.
- Has known unfixed memory-safety bugs reachable from public API (e.g., CVE-2016-10087 NULL-deref in `png_set_text_2`). Increases probability of a real crash within a 30-min run → easier Q5.
- The lab PDF (Section 2) explicitly endorses targeting older versions: *"Using an older version with known CVEs is acceptable and even encouraged."*
- The libpng walkthrough in the PDF uses 1.2.56 — staying on this path keeps everything we do defensible against the canonical reference.

Counter-options considered: 1.6.37 (manual one-line patch to `png_crc_finish` in `pngrutil.c`; Q5 weaker), latest 1.6.x (likely no real crashes → forced down synthetic-bug path).

## Architecture

Host is **Apple Silicon (arm64)**. The `aflplusplus/aflplusplus` image is
multi-arch (amd64 + arm64), so the build runs natively on the host architecture
rather than under emulation. The Dockerfile does **not** pin a platform — see
Issue 1 below for why pinning was tried first and removed.

Implications for the recorded numbers:
- Fuzzing exec speed will be lower than what's quoted in AFL++ docs (expect a
  few hundred exec/sec instead of >1k) because of arm64 + ASan overhead.
- Numbers in Q4/Q7/Q8 reflect arm64-native execution. On amd64 hosts the grader
  may see different absolute speeds; the *relative* shape (persistent ≫ no-san
  fork > ASan fork) holds across architectures.

## Harness design

**Decoder, full pipeline, all transforms enabled.**

Entry-point sequence:
```
png_create_read_struct → png_create_info_struct → setjmp(png_jmpbuf)
  → png_set_read_fn (callback over fuzzer-provided buffer)
  → png_read_info
  → png_set_expand / png_set_strip_16 / png_set_gray_to_rgb / png_set_palette_to_rgb
  → png_read_update_info
  → allocate row pointers
  → png_read_image
  → png_read_end
  → png_destroy_read_struct
```

Justification for Q1:
- **Why decoder, not encoder?** Attackers rarely control encode input; the threat model is "user opens malicious PNG."
- **Why all transforms?** Each `png_set_*` opens a code path that the parser otherwise skips. CVE-2015-8126 lives in palette expansion (`png_set_expand`). Without these calls the relevant code is dead-coverage.
- **Why setjmp?** libpng signals errors via `png_error → longjmp`. Without a `setjmp` site, every malformed input → unhandled longjmp → process aborts → AFL++ records a crash. False-positive flood.
- **Why dimension/depth guards?** A mutated IHDR claiming `65535×65535` makes libpng `malloc` ~16 GB; that's a libc abort, not a parser bug. Caps avoid this false positive without hiding real issues (real images are <16k×16k).

Alternatives rejected:
- `png_image_begin_read_from_memory` (simplified API): only in 1.6+. N/A on 1.2.56.
- Low-level chunk reader (`png_read_chunk_header` etc.): smaller surface, less interesting for security fuzzing.
- Encoder path: less attacker-relevant.

## Patches applied

`patches/libpng-nocrc.patch` — the AFL++ shipped CRC-removal patch. Without this, every byte mutated inside a chunk's data invalidates the CRC-32 → libpng calls `png_error` (critical chunks) or silently discards data (ancillary chunks). Either way the deeper parsing code never runs and coverage plateaus immediately. The lab box on page 4 of the libpng guide is explicit about this.

We keep the CRC patch applied even in the QEMU/black-box build. Rationale: in a real closed-source scenario you couldn't patch out the checksum, but the *comparison* between instrumented and QEMU campaigns is only meaningful if both explore comparable code paths. The lab's QEMU box on page 8 of the libpng guide explicitly endorses this choice.

## Deliverable mapping

| Repo artifact | Lab section | Graded question |
|---|---|---|
| `Dockerfile` | 3.1 | Q2 |
| `Makefile` | 3.1, 3.2 | — |
| `src/harness.c` | 3.1 | Q1 |
| `src/harness_persistent.c` | 3.1 | Q8 |
| `patches/libpng-nocrc.patch` | 3.1 | Q2 |
| `seeds/` | — | Q3 |
| `findings/` (gitignored, in tarball) | 3.4 | Q4, Q5 |
| `findings-qemu/` (gitignored, in tarball) | 3.2, 3.4 | Q7 |
| `plot_output/`, `plot_output_qemu/` | 3.4 | Q4, Q7 |
| `report.pdf` | 3.3 | all |

---

## Issues encountered (and how they were fixed)

### 1. ASan refuses to initialize under Docker amd64 emulation on arm64
First Dockerfile pinned `--platform=linux/amd64`. On Apple Silicon this means amd64 binaries run via QEMU user-mode. autoconf's link-test (`./a.out`) segfaulted in ASan's shadow-memory init, so `./configure` aborted with *"cannot run C compiled programs"*.

**Fix**: dropped the platform pin from both Dockerfile and Makefile. The `aflplusplus/aflplusplus` image is multi-arch (amd64 + arm64); native arch makes ASan happy. The grader's machine will pick whichever arch is native to them — also native, also works.

If you need to re-pin to amd64 (e.g., grader insists on amd64-only), you can drop the ASan flag for the `--build` test by passing `--host=x86_64-linux-gnu` to configure, but that's a no-op fix because the actual fuzzing harness will then ALSO segfault under emulation. Stay native.

### 2. libpng 1.2.x refuses to compile if `<setjmp.h>` is included before `<png.h>`
First harness had:
```c
#include <setjmp.h>
#include <png.h>
```
`pngconf.h` checks `#ifdef _SETJMP_H` and aborts with the cryptic `__pngconf.h__ ... __dont__ include it again` message. Fix: don't include `<setjmp.h>` ourselves; let `<png.h>` pull it in.

### 3. `make_seeds.py` was being copied into the image as a "seed"
First build did `COPY seeds/ /work/seeds/` which dragged the generator script along. AFL++ happily picked it up as a seed; map size for it was only 84 bits (vs 260+ for valid PNGs) → wasted exec budget on a non-PNG dry run.

**Fix**: `.dockerignore` excludes `seeds/make_seeds.py`. Container ends up with only the 6 PNGs.

---

## Numbers from sanity check (record in report)

### Edge counts (`AFL_DEBUG=1`)
| Binary | Edges | Notes |
|---|---|---|
| `png_fuzz` (instr + ASan, fork) | **3085** | The main campaign target |
| `png_fuzz_no_san` (instr, no ASan, fork) | **3082** | Q8 config (1) |
| `png_fuzz_persistent` (instr + ASan, persistent) | **3099** | Q8 config (3) — slightly higher due to __AFL_LOOP macros |
| library-only (whole-archive) | **4449** | What libpng *would* contribute if all of it were linked |

The library-only count (4449) is **higher** than the harness count (3085) because the static linker only pulls in object files our harness actually references — encoder, writers, and helpers are dropped. This is the exact "Sanity Checking Edge Counts" point from the libsixel guide. Use it for Q8.

### 30-second smoke test of `afl-fuzz`
- 6 seeds + 27 dictionary tokens loaded (one per chunk type + signature)
- Dry run passed for all 6 seeds (map sizes 260–280 bits, exec ~4–5ms each)
- After 30 sec: **93 new corpus items**, **18.41% coverage**, 0 crashes
- Stability not yet measured — needs longer run

These are arm64-native numbers. On amd64 (grader) you may see 2–3× faster exec speeds.

---

## Command log

```bash
# environment
git clone git@github.com:noemacee/fuzzing.git
cd fuzzing

# scaffold (in order)
# .gitignore — exclude build outputs
# patches/libpng-nocrc.patch — fetched from AFL++ stable branch
# Dockerfile — multi-arch base, libpng 1.2.56, three lib builds
# Makefile — host-driven targets
# src/harness.c — file-input, full decode, setjmp catch
# src/harness_persistent.c — __AFL_LOOP version for Q8
# seeds/make_seeds.py — generator + 6 generated PNGs
# .dockerignore — keep make_seeds.py out of the image

# build
make build                              # ~3 min on arm64 native

# sanity
make sanity                             # exit=0 expected
docker run --rm cs412-fuzz sh -c 'for f in seeds/*.png; do ./png_fuzz "$f"; echo "$f -> $?"; done'
                                        # all six exit 0
echo "garbage" | docker run -i --rm cs412-fuzz sh -c 'cat > /tmp/x; ./png_fuzz /tmp/x; echo $?'
                                        # exits 0 (libpng prints error, setjmp catches)

# Edge counts
docker run --rm -e AFL_DEBUG=1 cs412-fuzz ./png_fuzz seeds/grayscale.png 2>&1 | grep edges
docker run --rm cs412-fuzz bash -c '
  echo "int main(){return 0;}" > /tmp/e.c;
  afl-clang-fast /tmp/e.c -Wl,--whole-archive /work/install/lib/libpng12.a \
    -Wl,--no-whole-archive -lz -lm -fsanitize=address -o /tmp/L;
  AFL_DEBUG=1 /tmp/L 2>&1 | grep edges
'

# Smoke test (30 sec)
rm -rf findings && mkdir findings
docker run --rm -v $PWD/findings:/work/findings cs412-fuzz \
  afl-fuzz -i seeds -o findings -x png.dict -V 30 -- ./png_fuzz @@
```

