import array
import fcntl
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time


for interruption in (None, signal.SIGINT, signal.SIGTERM, signal.SIGHUP, "after_entry"):
    with tempfile.TemporaryDirectory(prefix="aurlens-terminal-") as scratch:
        directory = Path(scratch) / "aurlens"
        directory.mkdir(mode=0o700)
        saved = directory / "config.toml"
        saved.write_text("previous connection")
        master, slave = pty.openpty()
        original = termios.tcgetattr(slave)
        child = subprocess.Popen(
            [sys.argv[1], "setup"], stdin=slave, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env={**os.environ, "XDG_CONFIG_HOME": scratch},
        )
        output = bytearray()

        def until(marker):
            deadline = time.monotonic() + 10
            while marker not in output:
                assert time.monotonic() < deadline, "Setup prompt did not arrive"
                if select.select([child.stdout], [], [], 0.1)[0]:
                    data = os.read(child.stdout.fileno(), 4096)
                    assert data, "Setup exited before its prompt"
                    output.extend(data)

        try:
            until(b"Connection [1]:")
            os.write(master, b"2\n")
            until(b"Replace your saved AURLens connection?")
            os.write(master, b"y\n")
            until(b"Chat Completions endpoint:")
            os.write(master, b"https://example.invalid/v1/chat/completions\n")
            until(b"Model name:")
            os.write(master, b"fixture-model\n")
            until(b"API key (hidden; Enter for none)")
            assert not termios.tcgetattr(slave)[3] & termios.ECHO
            if interruption in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                os.kill(child.pid, signal.SIGSTOP)
                os.waitpid(child.pid, os.WUNTRACED)
            if interruption == "after_entry":
                os.write(master, b"\n")
                until(b"Enable this connection?")
                assert termios.tcgetattr(slave) == original
                os.kill(child.pid, signal.SIGINT)
            elif interruption is None:
                os.write(master, b"fixture-entry-value")
                os.write(master, b"\x03")
            else:
                os.write(master, b"fixture-entry-value")
                deadline = time.monotonic() + 2
                while True:
                    queued = array.array("i", [0])
                    fcntl.ioctl(slave, termios.FIONREAD, queued, True)
                    if queued[0] == len(b"fixture-entry-value"):
                        break
                    assert time.monotonic() < deadline, "PTY input did not arrive"
                    time.sleep(0.001)
                os.kill(child.pid, interruption)
                if interruption in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                    os.kill(child.pid, signal.SIGCONT)
            stdout, stderr = child.communicate(timeout=10)
            expected = -signal.SIGINT if interruption == "after_entry" else 3
            assert child.returncode == expected, (interruption, child.returncode)
            assert termios.tcgetattr(slave) == original, "Terminal settings were not restored"
            os.write(master, b"\n")
            assert select.select([slave], [], [], 1)[0], "Terminal stopped accepting input"
            assert os.read(slave, 4096) == b"\n", "Partial key remained in terminal input"
            assert saved.read_text() == "previous connection"
            assert list(directory.iterdir()) == [saved], "Partial credential file remained"
            assert b"fixture-entry-value" not in output + stdout + stderr
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)
            termios.tcsetattr(slave, termios.TCSANOW, original)
            os.close(master)
            os.close(slave)
