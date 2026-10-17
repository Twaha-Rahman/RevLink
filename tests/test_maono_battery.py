"""Unit tests for maono_battery.py — frame building/parsing and lighting.

The expected byte vectors match the builders in PD200XW.dll
(`FUN_180064940` single read, `FUN_180064a30` cmd-3 write pair,
`FUN_180064f70` cmd-6 block read); see docs/protocol.md.
"""

import contextlib
import io
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

    def test_write_pair_cmd3_led_on(self):
        # host -> device writes are cmd-0x03 pairs (the app's UI write path)
        self.assertEqual(mb.write_value(0x2089, 1), bytes.fromhex("c40b0000038920010084fe"))

    def test_write_pair_cmd3_color_red(self):
        self.assertEqual(mb.write_value(0x208C, 1), bytes.fromhex("c40b0000038c20010081fe"))

    def test_block_read_cmd6_sn(self):
        # the DLL's cmd-6 frame for a 16-value serial-number block read
        self.assertEqual(mb.block_read(0x1E, 0x10), bytes.fromhex("c40b0000061e001000fdfe"))

    def test_block_read_cmd6_custom_colors(self):
        # 5 custom colors x (H, S, V) values
        self.assertEqual(mb.block_read(0x208F, 15), bytes.fromhex("c40b0000068f200f006dfe"))

    def test_ack_shape(self):
        frame = mb.build_frame(mb.CMD_ACK, struct.pack("<HH", 0x2084, 0))
        self.assertEqual(frame[0], mb.MAGIC)
        self.assertEqual(frame[4], mb.CMD_ACK)
        self.assertEqual(frame[1] | (frame[2] << 8), 0x0B)

    def test_checksum_roundtrip(self):
        cases = [
            (mb.CMD_READ, struct.pack("<H", 0x42)),
            (mb.CMD_WRITE, struct.pack("<HH", 0x2E, 0x10)),
            (mb.CMD_READ_BLOCK, struct.pack("<HH", 0x208F, 15)),
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


class LightingTests(unittest.TestCase):
    def test_channel_key_spaces(self):
        self.assertEqual(mb.light_key(1, mb.LIGHT_LED_OFF), 0x2089)
        self.assertEqual(mb.light_key(2, mb.LIGHT_LED_OFF), 0x2889)
        self.assertEqual(mb.light_key(1, mb.LIGHT_CUSTOM_OFF), 0x208F)
        self.assertEqual(mb.light_key(2, mb.LIGHT_CUSTOM_OFF + 0x0C), 0x289B)

    def test_parse_color_presets(self):
        self.assertEqual(mb.parse_color("white"), ("preset", 0))
        self.assertEqual(mb.parse_color("Magenta"), ("preset", 7))
        self.assertEqual(mb.parse_color("3"), ("preset", 3))
        self.assertIsNone(mb.parse_color("8"))
        self.assertIsNone(mb.parse_color("purple"))

    def test_parse_color_custom(self):
        self.assertEqual(mb.parse_color("#FF0000"), ("custom", (255, 0, 0)))
        self.assertEqual(mb.parse_color("#f00"), ("custom", (255, 0, 0)))
        self.assertEqual(mb.parse_color("00ff00"), ("custom", (0, 255, 0)))
        self.assertIsNone(mb.parse_color("#12345"))

    def test_rgb_to_light_hsv(self):
        # H is hue in degrees x100 (the app's double x100 encoder), S/V percent
        self.assertEqual(mb.rgb_to_light_hsv(255, 0, 0), (0, 100, 100))
        self.assertEqual(mb.rgb_to_light_hsv(0, 255, 0), (12000, 100, 100))
        self.assertEqual(mb.rgb_to_light_hsv(0, 0, 255), (24000, 100, 100))
        self.assertEqual(mb.rgb_to_light_hsv(255, 255, 255), (0, 0, 100))

    def test_plan_lighting_basic(self):
        args = mb.parse_args(["--light", "on", "--light-mode", "breathe", "--light-brightness", "50"])
        writes = mb.plan_lighting(args)
        self.assertEqual(
            [(key, value) for key, value, _ in writes],
            [(0x2089, 1), (0x208A, 50), (0x208B, 2)],
        )

    def test_plan_lighting_preset_color_channel2(self):
        args = mb.parse_args(["--light-color", "red", "--channel", "2"])
        self.assertEqual(mb.plan_lighting(args), [(0x288C, 1, "color=red(1)")])

    def test_plan_lighting_custom_color(self):
        args = mb.parse_args(["--light-color", "#00ff00", "--light-slot", "2"])
        writes = mb.plan_lighting(args)
        self.assertEqual(
            [(key, value) for key, value, _ in writes],
            [(0x2092, 12000), (0x2093, 100), (0x2094, 100), (0x208C, 9)],
        )

    def test_plan_lighting_raw_hsv_does_not_select(self):
        args = mb.parse_args(["--light-hsv", "100,20,30"])
        self.assertEqual(
            mb.plan_lighting(args),
            [
                (0x208F, 100, "custom1.h=100"),
                (0x2090, 20, "custom1.s=20"),
                (0x2091, 30, "custom1.v=30"),
            ],
        )

    def test_plan_lighting_both_channels(self):
        args = mb.parse_args(["--light", "off", "--channel", "both"])
        self.assertEqual(
            mb.plan_lighting(args),
            [(0x2089, 0, "led=off"), (0x2889, 0, "led=off")],
        )

    def test_light_value_names(self):
        self.assertEqual(mb.light_value_names(mb.LIGHT_LED_OFF, 1), "on")
        self.assertEqual(mb.light_value_names(mb.LIGHT_LED_OFF, 0), "off")
        self.assertEqual(mb.light_value_names(mb.LIGHT_MODE_OFF, 1), "loop")
        self.assertEqual(mb.light_value_names(mb.LIGHT_MODE_OFF, 2), "breathe")
        self.assertEqual(mb.light_value_names(mb.LIGHT_COLOR_OFF, 7), "magenta(7)")
        self.assertEqual(mb.light_value_names(mb.LIGHT_COLOR_OFF, 8), "custom1(8)")
        self.assertEqual(mb.light_value_names(mb.LIGHT_BRIGHTNESS_OFF, 42), "42")

    def test_light_status_record(self):
        record = mb.light_status_record(
            {mb.LIGHT_LED_OFF: 1, mb.LIGHT_MODE_OFF: 2, mb.LIGHT_COLOR_OFF: 5}
        )
        self.assertEqual(record["led"], 1)
        self.assertEqual(record["led_name"], "on")
        self.assertEqual(record["mode_name"], "breathe")
        self.assertEqual(record["color_name"], "cyan(5)")
        self.assertIsNone(record["brightness"])
        self.assertIsNone(record["custom_count"])

    def test_lighting_validation_errors(self):
        bad_argv = (
            ["--light-mode", "flash"],
            ["--light-brightness", "0"],
            ["--light-brightness", "101"],
            ["--light-color", "purple"],
            ["--light-slot", "0"],
            ["--light-hsv", "1,2"],
            ["--light-hsv", "1,2,65536"],
            ["--light-count", "6"],
            ["--light", "on", "--watch"],
        )
        with contextlib.redirect_stderr(io.StringIO()):
            for argv in bad_argv:
                with self.assertRaises(SystemExit, msg=repr(argv)):
                    mb.parse_args(argv)


class InterfacePathTests(unittest.TestCase):
    def test_usb_interface_component(self):
        path = (
            "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-3/1-3:1.3/"
            "0003:352F:040E.0003/hidraw/hidraw6"
        )
        self.assertEqual(mb.interface_from_path(path), 3)

    def test_hid_instance_dir_is_not_an_interface(self):
        # ".../0411.0051" must not be read as interface 51.
        path = (
            "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.5/"
            "0003:352F:0411.0051/hidraw/hidraw6"
        )
        self.assertEqual(mb.interface_from_path(path), 5)

    def test_no_interface_component(self):
        path = "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/0003:352F:0411.0051/hidraw/hidraw6"
        self.assertIsNone(mb.interface_from_path(path))

    def test_multidigit_port_path(self):
        self.assertEqual(
            mb.interface_from_path("/sys/devices/x/3-2.1/3-2.1:1.51/hidraw/hidraw9"),
            51,
        )


if __name__ == "__main__":
    unittest.main()
