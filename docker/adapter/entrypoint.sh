#!/bin/sh
set -eu

if [ "$(id -u)" -eq 0 ]; then
    echo "baseline entrypoint refuses root" >&2
    exit 73
fi

unset GOOGLE_APPLICATION_CREDENTIALS GOOGLE_ADC GOOGLE_CLOUD_PROJECT
run_dir="${VERIPLANPT_RUN_DIR:-/run/veriplanpt}"
mkdir -p "$run_dir"
export HOME="$run_dir/home"
export XDG_CACHE_HOME="$run_dir/xdg-cache"
export XDG_CONFIG_HOME="$run_dir/xdg-config"
export TMPDIR="$run_dir/tmp"
mkdir -p "$HOME" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$TMPDIR"
cd "$run_dir"

if [ "$#" -eq 0 ]; then
    exec python /opt/adapter/provider_shim.py --contract-smoke
fi
exec "$@"
