# cs412 fuzzing lab — SDL 1.2.15 WAV/BMP driver targets.
# Host-side wrapper around docker; all builds and afl-fuzz runs happen inside.

IMAGE      := cs412-fuzz-sdl
TIME       ?= 1800          # default campaign duration: 30 min
SEEDS_WAV  := seeds/wav
SEEDS_BMP  := seeds/bmp
DICT       := sdl.dict

DOCKER_RUN := docker run --rm \
    -v $(PWD)/findings:/work/findings \
    -v $(PWD)/findings-qemu:/work/findings-qemu

.PHONY: build shell sanity-wav sanity-bmp \
        fuzz fuzz-bmp fuzz-qemu fuzz-qemu-bmp \
        fuzz-persistent fuzz-no-san \
        plot plot-qemu clean distclean help

help:
	@echo "make build             build the docker image"
	@echo "make sanity-wav        smoke-test WAV harness on a known-good seed"
	@echo "make sanity-bmp        smoke-test BMP harness on a known-good seed"
	@echo "make fuzz              WAV campaign, instrumented + ASan (TIME=$(TIME)s)"
	@echo "make fuzz-bmp          BMP campaign, instrumented + ASan (TIME=$(TIME)s)"
	@echo "make fuzz-qemu         WAV QEMU-mode campaign"
	@echo "make fuzz-qemu-bmp     BMP QEMU-mode campaign"
	@echo "make fuzz-persistent   WAV persistent-mode variant for Q8"
	@echo "make fuzz-no-san       WAV no-sanitizer + fork variant for Q8"
	@echo "make plot              afl-plot of findings/"
	@echo "make plot-qemu         afl-plot of findings-qemu/"
	@echo "make shell             drop into the container"
	@echo "make clean             remove findings/, plots"
	@echo "make distclean         also remove docker image"

build:
	docker build -t $(IMAGE) .

shell:
	$(DOCKER_RUN) -it $(IMAGE)

# Sanity check: feed a known-good seed, expect exit 0.
sanity-wav:
	$(DOCKER_RUN) $(IMAGE) sh -c './sdl_wav_fuzz seeds/wav/pcm_s16le.wav; echo exit=$$?'

sanity-bmp:
	$(DOCKER_RUN) $(IMAGE) sh -c './sdl_bmp_fuzz seeds/bmp/rgb24.bmp; echo exit=$$?'

# Main WAV campaign (instrumented + ASan).
fuzz:
	mkdir -p findings
	$(DOCKER_RUN) -it $(IMAGE) \
	    afl-fuzz -i $(SEEDS_WAV) -o findings -x $(DICT) -V $(TIME) \
	    -- ./sdl_wav_fuzz @@

# Secondary BMP campaign (instrumented + ASan).
fuzz-bmp:
	mkdir -p findings-bmp
	$(DOCKER_RUN) -it -v $(PWD)/findings-bmp:/work/findings-bmp $(IMAGE) \
	    afl-fuzz -i $(SEEDS_BMP) -o findings-bmp -x $(DICT) -V $(TIME) \
	    -- ./sdl_bmp_fuzz @@

# QEMU-mode campaigns (black-box, vanilla gcc binaries).
fuzz-qemu:
	mkdir -p findings-qemu
	$(DOCKER_RUN) -it $(IMAGE) \
	    afl-fuzz -Q -i $(SEEDS_WAV) -o findings-qemu -x $(DICT) -V $(TIME) \
	    -- ./sdl_wav_fuzz_qemu @@

fuzz-qemu-bmp:
	mkdir -p findings-qemu-bmp
	$(DOCKER_RUN) -it -v $(PWD)/findings-qemu-bmp:/work/findings-qemu-bmp $(IMAGE) \
	    afl-fuzz -Q -i $(SEEDS_BMP) -o findings-qemu-bmp -x $(DICT) -V $(TIME) \
	    -- ./sdl_bmp_fuzz_qemu @@

# Q8: persistent-mode WAV, its own findings dir.
fuzz-persistent:
	mkdir -p findings-persistent
	$(DOCKER_RUN) -it -v $(PWD)/findings-persistent:/work/findings-persistent $(IMAGE) \
	    afl-fuzz -i $(SEEDS_WAV) -o findings-persistent -x $(DICT) -V $(TIME) \
	    -- ./sdl_wav_fuzz_persistent

# Q8: no-sanitizer + fork WAV.
fuzz-no-san:
	mkdir -p findings-no-san
	$(DOCKER_RUN) -it -v $(PWD)/findings-no-san:/work/findings-no-san $(IMAGE) \
	    afl-fuzz -i $(SEEDS_WAV) -o findings-no-san -x $(DICT) -V $(TIME) \
	    -- ./sdl_wav_fuzz_no_san @@

plot:
	mkdir -p plot_output
	$(DOCKER_RUN) -v $(PWD)/plot_output:/work/plot_output $(IMAGE) \
	    afl-plot findings/default plot_output

plot-qemu:
	mkdir -p plot_output_qemu
	$(DOCKER_RUN) -v $(PWD)/plot_output_qemu:/work/plot_output_qemu $(IMAGE) \
	    afl-plot findings-qemu/default plot_output_qemu

clean:
	rm -rf findings findings-bmp findings-qemu findings-qemu-bmp \
	       findings-persistent findings-no-san \
	       plot_output plot_output_qemu

distclean: clean
	-docker image rm $(IMAGE)
