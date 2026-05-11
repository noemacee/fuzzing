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

echo "[*] Starting 2-hour WAV fuzz campaign..."
make fuzz TIME=7200
