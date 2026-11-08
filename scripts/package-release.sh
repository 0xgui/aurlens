#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 3 ]] || { printf 'Usage: %s binary target new-output-directory\n' "$0" >&2; exit 2; }
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
binary="$(realpath -- "$1")"
target="$2"
[[ "$target" == x86_64-unknown-linux-gnu ]]
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]]
[[ -x "$binary" ]]
cd -- "$repo_root"
git diff --quiet HEAD --
cargo_bin="${CARGO:-cargo}"
version="$("$cargo_bin" metadata --locked --offline --no-deps --format-version 1 | jq -er '.packages[] | select(.name == "aurlens") | .version')"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$ ]]
[[ "$("$binary" --version)" == "aurlens $version" ]]
commit="$(git rev-parse HEAD)"
epoch="$(git show -s --format=%ct HEAD)"
mkdir -- "$3"
output="$(realpath -- "$3")"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/aurlens-release.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT
prefix="aurlens-v$version-$target"
git archive --format=tar --prefix="$prefix/" HEAD > "$scratch/source.tar"
tar -xf "$scratch/source.tar" -C "$scratch"
mkdir -- "$scratch/$prefix/bin"
install -m 755 -- "$binary" "$scratch/$prefix/bin/aurlens"
binary_digest="$(sha256sum "$binary" | cut -d ' ' -f1)"
jq -n --arg version "$version" --arg target "$target" --arg commit "$commit" --arg binary_sha256 "$binary_digest" \
    '{version:$version,target:$target,source_commit:$commit,binary_sha256:$binary_sha256}' > "$scratch/$prefix/release.json"
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    --format=posix --pax-option=delete=atime,delete=ctime -cf - -C "$scratch" "$prefix" \
    | gzip -n > "$output/$prefix.tar.gz"
git archive --format=tar --prefix="aurlens-v$version/" HEAD \
    | gzip -n > "$output/aurlens-v$version-source.tar.gz"
(
    cd -- "$output"
    sha256sum --binary -- "$prefix.tar.gz" "aurlens-v$version-source.tar.gz" > SHA256SUMS
)
printf 'Packaged AURLens %s (%s) from %s\n' "$version" "$target" "$commit"
