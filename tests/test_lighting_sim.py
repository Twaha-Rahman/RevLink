"""Offline integration test of the lighting code path (no hardware needed).

`run_lighting()` is exercised against a datagram socketpair standing in for
``/dev/hidraw*``: one 64-byte report per read/write, like hidraw.  The fake
device records cmd-0x03 writes and answers cmd-0x04 single-key reads for the
lighting registers, so write-frame generation, channel handling and status
parsing are covered end to end.
"""

import contextlib
import io
import json
import os
import socket
import struct
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import revlink as rl

REGISTER_VALUES = {0x2089: 1, 0x208A: 50, 0x208B: 2, 0x208C: 1, 0x208E: 2}


class FakeDevice:
    """Answers lighting read probes and records writes on a socketpair."""

    def __init__(self):
        self.fd, self.peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.writes = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        buffer = b""
        self.peer.settimeout(0.1)
        while not self._stop.is_set():
            try:
                chunk = self.peer.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if not chunk:
                return
            buffer += chunk
            while len(buffer) >= rl.REPORT_LEN:
                record, buffer = buffer[: rl.REPORT_LEN], buffer[rl.REPORT_LEN:]
                parsed = rl.parse_frame(rl.strip_report_id(record))
                if not parsed:
                    continue
                cmd, payload = parsed
                if cmd == rl.CMD_WRITE:
                    self.writes.append(struct.unpack("<HH", payload))
                elif cmd == rl.CMD_READ:
                    key = struct.unpack("<H", payload)[0]
                    if key in REGISTER_VALUES:
                        reply = rl.build_frame(
                            rl.CMD_READ, struct.pack("<HH", key, REGISTER_VALUES[key])
                        ).ljust(rl.REPORT_LEN, b"\x00")
                        self.peer.sendall(reply)

    def open_device(self, args):
        return os.dup(self.fd.fileno()), {"dev": "/dev/fake"}, False

    def wait_for_writes(self, count, timeout=2.0):
        deadline = time.monotonic() + timeout
        while len(self.writes) < count and time.monotonic() < deadline:
            time.sleep(0.01)

    def close(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self.fd.close()
        self.peer.close()


class LightingSimulationTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeDevice()
        self._open_device = rl.open_device
        self._describe = rl.describe
        rl.open_device = self.fake.open_device
        rl.describe = lambda device: "fake device"

    def tearDown(self):
        rl.open_device = self._open_device
        rl.describe = self._describe
        self.fake.close()

    def test_writes_led_and_custom_color_both_channels(self):
        args = rl.parse_args(
            ["--light", "on", "--light-color", "#00ff00", "--light-slot", "2", "--channel", "both"]
        )
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(rl.run_lighting(args), 0)
        self.fake.wait_for_writes(10)
        self.assertEqual(
            self.fake.writes,
            [
                (0x2089, 1), (0x2889, 1),
                (0x2092, 12000), (0x2892, 12000),
                (0x2093, 100), (0x2893, 100),
                (0x2094, 100), (0x2894, 100),
                (0x208C, 9), (0x288C, 9),
            ],
        )

    def test_status_read_back_text(self):
        args = rl.parse_args(["--light-status", "--wait", "2"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(rl.run_lighting(args), 0)
        self.assertIn(
            "TX1  led=on  brightness=50  mode=breathe  color=red(1)  custom_count=2",
            out.getvalue(),
        )

    def test_status_read_back_json(self):
        args = rl.parse_args(["--light-status", "--json", "--wait", "2"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(rl.run_lighting(args), 0)
        payload = json.loads(out.getvalue().strip().splitlines()[-1])
        self.assertEqual(payload["tx1"]["led"], 1)
        self.assertEqual(payload["tx1"]["mode"], 2)
        self.assertEqual(payload["tx1"]["mode_name"], "breathe")
        self.assertEqual(payload["tx1"]["color_name"], "red(1)")
        self.assertEqual(payload["tx1"]["custom_count"], 2)


if __name__ == "__main__":
    unittest.main()
