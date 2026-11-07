#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 3 ]] || { printf 'Usage: %s shelly-source aurlens-binary new-evidence-directory\n' "$0" >&2; exit 2; }
integration_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source_dir="$(realpath -- "$1")"
binary="$(realpath -- "$2")"
zig_bin="${ZIG:-zig}"
[[ -x "$binary" ]]
[[ "$("$zig_bin" version)" == 0.17.0 ]]
"$binary" verify --help > /dev/null
mkdir -- "$3"
evidence="$(realpath -- "$3")"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/aurlens-shelly.XXXXXXXX")"
trap 'rm -rf -- "$scratch"; printf "Evidence retained at %s\n" "$evidence" >&2' EXIT
(
    cd -- "$source_dir"
    sha256sum --check --strict "$integration_dir/base-sha256.txt"
) > "$evidence/source-check.txt"
tar -C "$source_dir" --exclude=.git --exclude=.zig-cache --exclude=zig-pkg --exclude=zig-out -cf "$scratch/source.tar" .
mkdir -- "$scratch/source"
tar -C "$scratch/source" -xf "$scratch/source.tar"
cd -- "$scratch/source"
git apply --check "$integration_dir/shelly-3.2.0.patch"
git apply "$integration_dir/shelly-3.2.0.patch"
cp -- "$integration_dir/aurlens.zig" Shelly.PackageManager/src/aur/aurlens.zig
"$zig_bin" fmt --check Shelly.PackageManager/src/aur/aurlens.zig Shelly.PackageManager/src/aur/manager.zig Shelly.PackageManager/build.zig
"$zig_bin" test Shelly.PackageManager/src/aur/aurlens.zig > "$evidence/protocol.log" 2>&1
sha256sum "$binary" "$integration_dir/shelly-3.2.0.patch" "$integration_dir/aurlens.zig" > "$evidence/artifacts.sha256"
cd Shelly.PackageManager
AURLENS_TEST_BIN="$binary" "$zig_bin" build aurlens-test -Dlibalpm=true --summary all > "$evidence/gates.log" 2>&1
AURLENS_TEST_BIN="$binary" "$zig_bin" build aur-test -Dlibalpm=true --summary all > "$evidence/native.log" 2>&1
printf '{"passed":true,"installed_shelly_changed":false,"real_aurlens":true}\n' > "$evidence/summary.json"
