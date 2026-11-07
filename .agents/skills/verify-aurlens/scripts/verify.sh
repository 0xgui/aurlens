#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd -- "$repo_root"
cargo_bin="${CARGO:-cargo}"
cargo_flags=(--locked)
if [[ "${AURLENS_VERIFY_OFFLINE:-0}" == 1 ]]; then
    cargo_flags+=(--offline)
fi

metadata="$("$cargo_bin" metadata --no-deps --format-version 1 "${cargo_flags[@]}")"
target_dir="$(jq -er '.target_directory' <<< "$metadata")"
expected_version="$(jq -er '.packages[] | select(.name == "aurlens") | .version' <<< "$metadata")"
binary="$target_dir/release/aurlens"

doctor() {
    [[ -f Cargo.lock && -x "$binary" ]]
    local actual_version
    actual_version="$("$binary" --version)"
    [[ "$actual_version" == "aurlens $expected_version" ]]
    printf '%s\n' "$actual_version"
    "$binary" scan --help
    "$binary" verify --help
    sha256sum "$binary" Cargo.lock
    git status --short
}

case "${1:-run}" in
    doctor)
        [[ $# -eq 1 ]]
        doctor
        ;;
    run)
        [[ $# -le 2 ]]
        if [[ $# -eq 2 ]]; then
            mkdir -- "$2"
            evidence="$(cd -- "$2" && pwd)"
        else
            evidence="$(mktemp -d "${TMPDIR:-/tmp}/aurlens-evidence.XXXXXXXX")"
        fi
        trap 'printf "Evidence retained at %s\n" "$evidence" >&2' EXIT
        "$cargo_bin" build "${cargo_flags[@]}" --release > "$evidence/build.log" 2>&1
        doctor > "$evidence/doctor.txt" 2>&1
        AURLENS_VERIFY_BIN="$binary" AURLENS_VERIFY_EVIDENCE_DIR="$evidence" \
            "$cargo_bin" test "${cargo_flags[@]}" --test review user_journey_evidence \
            -- --exact --nocapture > "$evidence/drive.log" 2>&1
        jq -e '.passed == true and .scratch_removed == true and (.journeys | length) == 8' \
            "$evidence/summary.json" > /dev/null
        python3 .agents/skills/verify-aurlens/scripts/verify-snapshot.py "$binary" "$evidence/verification"
        jq -e '.passed == true and .scratch_removed == true and (.journeys | length) == 5' \
            "$evidence/verification/summary.json" > /dev/null
        printf 'All eight scan journeys and five snapshot journeys passed.\n'
        ;;
    *)
        printf 'Usage: %s doctor | run [new-evidence-directory]\n' "$0" >&2
        exit 2
        ;;
esac
