#!/usr/bin/env sh
set -eu

cargo build --release

release_dir="target/release"
tools_dir="$release_dir/tools"

mkdir -p "$tools_dir/cupola" "$tools_dir/aegis" "$tools_dir/epi"
: > "$tools_dir/cupola/cupola-cli.exe"
: > "$tools_dir/aegis/aegis.exe"
: > "$tools_dir/epi/epi-cli.exe"

"$release_dir/leo" doctor > /dev/null
"$release_dir/leo" --help > /dev/null
