"""Unit tests for maono_battery.py — protocol frame building/parsing.

The expected byte vectors match the builders in PD200XW.dll
(`FUN_180064940` single read, `FUN_180064f70` write pair); see docs/protocol.md.
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import maono_battery as mb


class FrameBuilderTests(unittest.TestCase):
    def test_single_read_battery_0x42(self):
        self.assertEqual(mb.single_read(0x42), bytes.fromhex("c4090000044200edfe"))

    def test_single_read_charge_0x49(self):
        self.assertEqual(mb.single_read(0x49), bytes.fromhex("c4090000044900e6fe"))

    def test_write_pair_0x1e_0x10(self):
        self.assertEqual(mb.write_value(0x1E, 0x10), bytes.fromhex("c40b0000061e001000fdfe"))

    def test_ack_shape(self):
        frame = mb.build_frame(mb.CMD_ACK, struct.pack("<HH", 0x2084, 0))
        self.assertEqual(frame[0], mb.MAGIC)
        self.assertEqual(frame[4], mb.CMD_ACK)
        self.assertEqual(frame[1] | (frame[2] << 8), 0x0B)

    def test_checksum_roundtrip(self):
        cases = [
            (mb.CMD_READ, struct.pack("<H", 0x42)),
            (mb.CMD_WRITE, struct.pack("<HH", 0x2E, 0x10)),
            (mb.CMD_ACK, struct.pack("<HHHH", 0x2084, 1, 0x49, 0x2000)),
        ]
        for cmd, payload in cases:
            frame = mb.build_frame(cmd, payload)
            length = frame[1] | (frame[2] << 8)
            self.assertEqual(length, len(frame))
            expected = (-sum(frame[: length - 2])) & 0xFFFF
            stored = frame[length - 2] | (frame[length - 1] << 8)
            self.assertEqual(expected, stored)


class ParserTests(unittest.TestCase):
    def test_parse_frame_roundtrip(self):
        frame = mb.write_value(0x2E, 0x10)
        self.assertEqual(mb.parse_frame(frame), (mb.CMD_WRITE, struct.pack("<HH", 0x2E, 0x10)))

    def test_parse_frame_allows_zero_padding(self):
        frame = mb.single_read(0x42) + b"\x00" * 20
        cmd, payload = mb.parse_frame(frame)
        self.assertEqual(cmd, mb.CMD_READ)
        self.assertEqual(payload, b"\x42\x00")

    def test_rejects_bad_checksum(self):
        frame = bytearray(mb.single_read(0x42))
        frame[-1] ^= 0xFF
        self.assertIsNone(mb.parse_frame(bytes(frame)))

    def test_rejects_short_frame(self):
        self.assertIsNone(mb.parse_frame(b"\xc4\x09\x00"))

    def test_rejects_wrong_magic(self):
        frame = bytearray(mb.single_read(0x42))
        frame[0] = 0x00
        self.assertIsNone(mb.parse_frame(bytes(frame)))

    def test_strip_report_id(self):
        frame = mb.single_read(0x42)
        self.assertEqual(mb.strip_report_id(b"\x00" + frame), frame)
        self.assertEqual(mb.strip_report_id(frame), frame)


class StateTests(unittest.TestCase):
    def test_battery_and_charge_pairs(self):
        state = mb.State()
        battery = 85 | (76 << 8)   # TX1 85 %, TX2 76 %
        charge = 0 | (1 << 8)      # TX1 not charging, TX2 charging
        payload = struct.pack("<HHHH", 0x42, battery, 0x49, charge)
        pairs = mb.parse_pairs(payload)
        self.assertEqual(pairs, {0x42: battery, 0x49: charge})
        state.update_from_pairs(pairs)
        self.assertEqual((state.tx1_batt, state.tx2_batt), (85, 76))
        self.assertEqual((state.tx1_chg, state.tx2_chg), (0, 1))
        self.assertTrue(state.has_data())

    def test_ignores_unrelated_keys(self):
        state = mb.State()
        state.update_from_pairs({0x41: 0x1234, 0x47: 0x0001})
        self.assertFalse(state.has_data())


if __name__ == "__main__":
    unittest.main()
