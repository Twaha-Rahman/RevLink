"""Offline integration test of the scene/PEQ code path (no hardware needed).

`run_eq()` is exercised against a datagram socketpair standing in for
``/dev/hidraw*``: one 64-byte report per read/write, like hidraw.  The fake
device records every cmd-0x03 write frame, answers cmd-0x04 single reads for
the mode/mix registers and answers the cmd-0x06 band block read in pieces, so
scene application, band edits, status decoding and profile import are covered
end to end.
"""

import contextlib
import io
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import revlink as rl

# Mode register of TX1: podcast scene, preset 1 (Podcast2), preset flag.
MODE_TX1 = 0x0101
MODE_TX2 = 0x0200


def curve_registers(curve):
    """The 35 register values of one curve, keyed by offset from EQ_BAND_OFF."""
    tables = {}
    for slot, freq, gain, q, ftype in rl.curve_slots(curve):
        base = rl.EQ_BAND_OFF + slot * rl.EQ_REGS_PER_SLOT
        for index, value in enumerate(rl.eq_slot_values(freq, gain, q, ftype)):
            tables[base + index] = value
    return tables


class FakeDevice:
    """Answers EQ read probes and records EQ writes on a socketpair."""

    def __init__(self):
        self.fd, self.peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.writes = []  # flat [(key, value), ...] in send order
        self.frames = []  # one [(key, value), ...] list per cmd-0x03 frame
        self.registers = {}
        for offset, value in curve_registers(rl.EQ_PRESETS["original"]).items():
            self.registers[0x2000 + offset] = value
        self.registers[0x2000 + rl.EQ_MODE_OFF] = MODE_TX1
        self.registers[0x2000 + rl.EQ_MIXTURE_OFF] = 0
        self.registers[0x2000 + rl.EQ_LEVEL_OFF] = 0
        self.registers[0x2800 + rl.EQ_MODE_OFF] = MODE_TX2
        self.registers[0x2800 + rl.EQ_MIXTURE_OFF] = 1
        self.registers[0x2800 + rl.EQ_LEVEL_OFF] = 5
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
                    values = struct.unpack("<" + "HH" * (len(payload) // 4), payload)
                    pairs = list(zip(values[0::2], values[1::2]))
                    self.frames.append(pairs)
                    self.writes.extend(pairs)
                elif cmd == rl.CMD_READ:
                    key = struct.unpack("<H", payload)[0]
                    if key in self.registers:
                        self.peer.sendall(
                            rl.build_frame(
                                rl.CMD_READ, struct.pack("<HH", key, self.registers[key])
                            ).ljust(rl.REPORT_LEN, b"\x00")
                        )
                elif cmd == rl.CMD_READ_BLOCK:
                    key, count = struct.unpack("<HH", payload[:4])
                    # Type-6 answers: key, count, then the values; each answer
                    # must fit one 64-byte report, so it is chunked like the app.
                    values = [self.registers.get(key + i, 0) for i in range(count)]
                    for start in range(0, count, 12):
                        chunk = values[start : start + 12]
                        body = struct.pack("<HH", key + start, len(chunk))
                        body += b"".join(struct.pack("<H", value) for value in chunk)
                        self.peer.sendall(
                            rl.build_frame(rl.CMD_READ_BLOCK, body).ljust(rl.REPORT_LEN, b"\x00")
                        )

    def open_device(self, args):
        return os.dup(self.fd.fileno()), {"dev": "/dev/fake"}, False

    def wait_for_frames(self, count, timeout=2.0):
        deadline = time.monotonic() + timeout
        while len(self.frames) < count and time.monotonic() < deadline:
            time.sleep(0.01)

    def close(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self.fd.close()
        self.peer.close()


class EqSimulationTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeDevice()
        self._open_device = rl.open_device
        self._describe = rl.describe
        self._spacing = rl.EQ_WRITE_SPACING
        rl.open_device = self.fake.open_device
        rl.describe = lambda device: "fake device"
        rl.EQ_WRITE_SPACING = 0.0

    def tearDown(self):
        rl.open_device = self._open_device
        rl.describe = self._describe
        rl.EQ_WRITE_SPACING = self._spacing
        self.fake.close()

    def _run(self, argv):
        args = rl.parse_args(argv)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = rl.run_eq(args)
        return code, out.getvalue()

    def test_scene_apply_writes_bands_mix_and_mode(self):
        code, _ = self._run(["--scene", "sing:1", "--channel", "both", "--wait", "2"])
        self.assertEqual(code, 0)
        self.fake.wait_for_frames(20)
        self.assertEqual(len(self.fake.frames), 20)
        # One frame per band slot: enable, type, frequency, gain, Q.
        self.assertEqual(
            self.fake.frames[0],
            [(0x2023, 1), (0x2024, 1), (0x2025, 171), (0x2026, 1980), (0x2027, 100)],
        )
        self.assertEqual(self.fake.frames[7], [(0x2082, 1)])  # Folk mixture
        self.assertEqual(self.fake.frames[8], [(0x2083, 1)])  # Folk level
        self.assertEqual(self.fake.frames[9], [(0x2022, 0x0301)])
        self.assertEqual(
            self.fake.frames[10],
            [(0x2823, 1), (0x2824, 1), (0x2825, 171), (0x2826, 1980), (0x2827, 100)],
        )
        self.assertEqual(self.fake.frames[17], [(0x2882, 1)])
        self.assertEqual(self.fake.frames[18], [(0x2883, 1)])
        self.assertEqual(self.fake.frames[19], [(0x2822, 0x0301)])

    def test_band_edit_and_raw_register(self):
        code, _ = self._run(
            ["--eq-band", "2", "800", "-3", "1.5", "--eq-reg", "0x2082=1", "--wait", "2"]
        )
        self.assertEqual(code, 0)
        self.fake.wait_for_frames(2)
        self.assertEqual(
            self.fake.frames[0],
            [(0x2028, 1), (0x2029, 1), (0x202A, 800), (0x202B, 1970), (0x202C, 150)],
        )
        self.assertEqual(self.fake.frames[1], [(0x2082, 1)])

    def test_dry_run_writes_nothing(self):
        code, out = self._run(["--scene", "game", "--dry-run", "--wait", "1"])
        self.assertEqual(code, 0)
        time.sleep(0.2)
        self.assertEqual(self.fake.writes, [])
        self.assertIn("dry-run 0x2022 <= 512", out)  # game(2) << 8 | preset 0

    def test_eq_status_text(self):
        code, out = self._run(["--eq-status", "--wait", "2"])
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertEqual(
            lines[0],
            "TX1  mode=0x0101  scene=podcast(1)  preset=podcast2(1)  preset  mixture=0  level=0",
        )
        self.assertEqual(lines[1], "TX1  band1 freq=125  gain=+0.0dB  Q=1.00  type=peak")
        self.assertEqual(lines[6], "TX1  hpf   freq=20  gain=-  Q=1.00  type=hpf")
        self.assertEqual(lines[7], "TX1  lpf   freq=20000  gain=-  Q=1.00  type=lpf")

    def test_eq_status_json(self):
        code, out = self._run(["--eq-status", "--json", "--channel", "both", "--wait", "2"])
        self.assertEqual(code, 0)
        payload = json.loads(out.strip().splitlines()[-1])
        self.assertEqual(payload["tx1"]["scene_name"], "podcast")
        self.assertEqual(payload["tx1"]["preset"], "podcast2")
        self.assertFalse(payload["tx1"]["custom"])
        self.assertEqual(payload["tx1"]["bands"][0]["freq"], 125)
        self.assertEqual(payload["tx2"]["mode"], MODE_TX2)
        self.assertEqual(payload["tx2"]["scene_name"], "game")
        self.assertEqual(payload["tx2"]["preset"], "game1")
        self.assertEqual(payload["tx2"]["mixture"], 1)
        self.assertEqual(payload["tx2"]["level"], 5)

    def test_eq_import_applies_profile(self):
        args = rl.parse_args(
            [
                "--eq-export",
                "unused.cfg",
                "--eq-band",
                "4",
                "4000",
                "5",
                "3",
                "--eq-mixture",
                "1",
                "--eq-level",
                "2",
            ]
        )
        curve, name, mixture, level, default = rl.curve_from_args(args)
        with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as handle:
            handle.write(rl.cfg_text(name, curve, mixture, level, default))
            path = handle.name
        self.addCleanup(os.unlink, path)
        code, _ = self._run(["--eq-import", path, "--wait", "2"])
        self.assertEqual(code, 0)
        self.fake.wait_for_frames(9)
        self.assertEqual(
            self.fake.frames[3],
            [(0x2032, 1), (0x2033, 1), (0x2034, 4000), (0x2035, 2050), (0x2036, 300)],
        )
        self.assertEqual(self.fake.frames[7], [(0x2082, 1)])
        self.assertEqual(self.fake.frames[8], [(0x2083, 2)])

    def test_eq_import_rejects_foreign_profile(self):
        doc = {
            "device_name": "PD100X",
            "blnMixture": False,
            "level": 0,
            "InfoName": "Weird",
            "curve_contains": rl.curve_json_text(rl.EQ_PRESETS["original"]),
            "blnDefault": False,
        }
        with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as handle:
            json.dump(doc, handle)
            path = handle.name
        self.addCleanup(os.unlink, path)
        args = rl.parse_args(["--eq-import", path])
        with self.assertRaises(rl.ConfigError):
            with contextlib.redirect_stderr(io.StringIO()):
                rl.run_eq(args)
        # --force accepts the profile; --dry-run keeps the device untouched
        args = rl.parse_args(["--eq-import", path, "--force", "--dry-run", "--wait", "1"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(rl.run_eq(args), 0)
        self.assertIn("dry-run 0x2023", out.getvalue())

    def test_eq_export_writes_cfg_without_device(self):
        path = tempfile.mktemp(suffix=".cfg")
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        args = rl.parse_args(["--eq-export", path, "--eq-preset", "pop"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(rl.run_eq_export(args), 0)
        self.assertIn("exported 'Pop'", out.getvalue())
        item = rl.load_cfg(path)
        self.assertEqual(item["name"], "Pop")
        self.assertEqual((item["mixture"], item["level"]), (1, 5))


if __name__ == "__main__":
    unittest.main()
