#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "[*] Waiting for cs412-fuzz-sdl image to be ready..."
until docker image inspect cs412-fuzz-sdl &>/dev/null; do
    sleep 5
done
echo "[+] Image ready."

echo "[*] Running sanity checks..."
make sanity-wav
make sanity-bmp
echo "[+] Sanity checks passed."

echo "[*] Starting 2-hour WAV instrumented campaign..."
make fuzz TIME=7200
echo "[+] Instrumented campaign done."

echo "[*] Starting 2-hour QEMU campaign..."
make fuzz-qemu TIME=7200
echo "[+] QEMU campaign done."

echo "[*] Starting Q8 perf runs (30s each)..."
make fuzz-no-san TIME=30
make fuzz-persistent TIME=30
echo "[+] Q8 perf runs done."

echo "[*] Generating plots..."
make plot
make plot-qemu
echo "[+] All done."
