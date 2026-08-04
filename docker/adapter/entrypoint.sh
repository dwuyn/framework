#!/bin/sh
set -eu

if [ "$(id -u)" -eq 0 ]; then
    echo "baseline entrypoint refuses root" >&2
    exit 73
fi

unset GOOGLE_APPLICATION_CREDENTIALS GOOGLE_ADC GOOGLE_CLOUD_PROJECT
run_dir="${VERIPLANPT_RUN_DIR:-/run/veriplanpt}"
mkdir -p "$run_dir"
cd "${VERIPLANPT_SOURCE_DIR:-/opt/upstream}"

if [ "$#" -eq 0 ]; then
    exec python /opt/adapter/provider_shim.py --contract-smoke
fi
exec "$@"
