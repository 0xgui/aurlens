#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 3 ]] || { printf 'Usage: %s shelly-source aurlens-binary new-evidence-directory\n' "$0" >&2; exit 2; }
integration_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source_dir="$(realpath -- "$1")"
binary="$(realpath -- "$2")"
zig_bin="${ZIG:-zig}"
[[ -x "$binary" ]]
makepkg_bin="${MAKEPKG:-$(command -v makepkg)}"
[[ -x "$makepkg_bin" ]]
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
cp -- "$integration_dir/aurlens.zig" "$integration_dir/reviewed_outputs.zig" "$integration_dir/build_destinations.zig" "$integration_dir/aurlens_settings.zig" Shelly.PackageManager/src/aur/
"$zig_bin" fmt --check Shelly.PackageManager/src/aur/aurlens_settings.zig Shelly.Cli.Zig/src/runtime/proxy_environment.zig Shelly.Ui.Gtk/src/services/shelly_operation.zig Shelly.PackageManager/src/aur/aurlens.zig Shelly.PackageManager/src/aur/reviewed_outputs.zig Shelly.PackageManager/src/aur/build_destinations.zig Shelly.PackageManager/src/aur/manager.zig Shelly.PackageManager/src/aur/builder.zig Shelly.PackageManager/src/aur/builder/builder.zig Shelly.PackageManager/build.zig Shelly.Cli.Zig/src/commands/builder.zig Shelly.Cli.Zig/src/cli/catalog/builder.zig
"$zig_bin" test Shelly.PackageManager/src/aur/aurlens.zig > "$evidence/protocol.log" 2>&1
sha256sum "$binary" "$makepkg_bin" "$integration_dir/shelly-3.2.0.patch" "$integration_dir/aurlens.zig" "$integration_dir/reviewed_outputs.zig" "$integration_dir/build_destinations.zig" "$integration_dir/aurlens_settings.zig" > "$evidence/artifacts.sha256"
cd Shelly.Cli.Zig
"$zig_bin" build builder-command-test isolated-config-test -Dlibalpm=true --summary all > "$evidence/cli-tests.log" 2>&1
"$zig_bin" build --prefix "$evidence/cli" -Dlibalpm=true --summary all > "$evidence/cli-build.log" 2>&1
child="$evidence/cli/bin/shelly"
[[ -x "$child" ]]
sha256sum "$child" >> "$evidence/artifacts.sha256"
cd ../Shelly.PackageManager
AURLENS_TEST_BIN="$binary" AURLENS_TEST_SHELLY_BIN="$child" AURLENS_TEST_MAKEPKG_BIN="$makepkg_bin" "$zig_bin" build aurlens-test -Dlibalpm=true --summary all > "$evidence/gates.log" 2>&1
AURLENS_TEST_BIN="$binary" AURLENS_TEST_SHELLY_BIN="$child" AURLENS_TEST_MAKEPKG_BIN="$makepkg_bin" "$zig_bin" build aur-test -Dlibalpm=true --summary all > "$evidence/native.log" 2>&1
printf '{"passed":true,"installed_shelly_changed":false,"real_aurlens":true,"real_shelly_child":true,"real_makepkg":true}\n' > "$evidence/summary.json"
