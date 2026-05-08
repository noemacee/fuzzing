# cs412 fuzzing lab — driver targets.
# Host-side wrapper around docker; the actual builds and afl-fuzz runs
# happen inside the container.

IMAGE      := cs412-fuzz
TIME       ?= 1800              # default campaign duration: 30 min
SEEDS_DIR  := seeds
DICT       := png.dict

DOCKER_RUN := docker run --rm \
    -v $(PWD)/findings:/work/findings \
    -v $(PWD)/findings-qemu:/work/findings-qemu

.PHONY: build build-synthetic shell fuzz fuzz-qemu fuzz-persistent fuzz-no-san \
        fuzz-synthetic plot plot-qemu sanity clean distclean help

help:
	@echo "make build           build the docker image"
	@echo "make sanity          run harness on a known-good seed (exit 0)"
	@echo "make fuzz            instrumented + ASan campaign (TIME=$(TIME)s)"
	@echo "make fuzz-qemu       QEMU-mode campaign on vanilla binary"
	@echo "make fuzz-persistent persistent-mode variant for Q8"
	@echo "make fuzz-no-san     no-sanitizer + fork variant for Q8"
	@echo "make plot            afl-plot of findings/"
	@echo "make plot-qemu       afl-plot of findings-qemu/"
	@echo "make shell           drop into the container"
	@echo "make clean           remove findings/, plots"
	@echo "make distclean       also remove docker image"

build:
	docker build -t $(IMAGE) .

# Q5 fallback build: layered image with synthetic_bug.patch applied.
build-synthetic: build
	docker build -f Dockerfile.synthetic -t $(IMAGE)-synthetic .

# Q5 fallback fuzz: 60 seconds is enough for AFL++ to splice in tEXt and crash.
fuzz-synthetic:
	mkdir -p findings-synthetic
	docker run --rm -it \
	    -v $(PWD)/findings-synthetic:/work/findings \
	    $(IMAGE)-synthetic \
	    afl-fuzz -i seeds -o findings -x $(DICT) -V 60 -- ./png_fuzz @@

shell:
	$(DOCKER_RUN) -it $(IMAGE)

# Sanity check: feed a known-good seed to the harness, expect exit 0.
# If this fails the harness has a bug — fix before fuzzing.
sanity:
	$(DOCKER_RUN) $(IMAGE) sh -c './png_fuzz seeds/grayscale.png; echo exit=$$?'

# Instrumented campaign (white-box).
# -V $(TIME) auto-stops after N seconds — needed for reproducibility.
fuzz:
	mkdir -p findings
	$(DOCKER_RUN) -it $(IMAGE) \
	    afl-fuzz -i $(SEEDS_DIR) -o findings -x $(DICT) -V $(TIME) \
	    -- ./png_fuzz @@

# Black-box / QEMU-mode campaign.
fuzz-qemu:
	mkdir -p findings-qemu
	$(DOCKER_RUN) -it $(IMAGE) \
	    afl-fuzz -Q -i $(SEEDS_DIR) -o findings-qemu -x $(DICT) -V $(TIME) \
	    -- ./png_fuzz_qemu @@

# Q8: persistent-mode binary, in its own findings dir to keep numbers clean.
fuzz-persistent:
	mkdir -p findings-persistent
	$(DOCKER_RUN) -it -v $(PWD)/findings-persistent:/work/findings-persistent $(IMAGE) \
	    afl-fuzz -i $(SEEDS_DIR) -o findings-persistent -x $(DICT) -V $(TIME) \
	    -- ./png_fuzz_persistent

# Q8: no-sanitizer build, fork mode.
fuzz-no-san:
	mkdir -p findings-no-san
	$(DOCKER_RUN) -it -v $(PWD)/findings-no-san:/work/findings-no-san $(IMAGE) \
	    afl-fuzz -i $(SEEDS_DIR) -o findings-no-san -x $(DICT) -V $(TIME) \
	    -- ./png_fuzz_no_san @@

plot:
	mkdir -p plot_output
	$(DOCKER_RUN) -v $(PWD)/plot_output:/work/plot_output $(IMAGE) \
	    afl-plot findings/default plot_output

plot-qemu:
	mkdir -p plot_output_qemu
	$(DOCKER_RUN) -v $(PWD)/plot_output_qemu:/work/plot_output_qemu $(IMAGE) \
	    afl-plot findings-qemu/default plot_output_qemu

clean:
	rm -rf findings findings-qemu findings-persistent findings-no-san \
	       findings-synthetic plot_output plot_output_qemu

distclean: clean
	-docker image rm $(IMAGE) $(IMAGE)-synthetic
