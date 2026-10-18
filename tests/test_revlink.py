"""Unit tests for revlink.py — frame building/parsing and lighting.

The expected byte vectors match the builders in PD200XW.dll
(`FUN_180064940` single read, `FUN_180064a30` cmd-3 write pair,
`FUN_180064f70` cmd-6 block read); see docs/protocol.md.
"""

import contextlib
import io
import json
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import revlink as rl


class FrameBuilderTests(unittest.TestCase):
    def test_single_read_battery_0x42(self):
        self.assertEqual(rl.single_read(0x42), bytes.fromhex("c4090000044200edfe"))

    def test_single_read_charge_0x49(self):
        self.assertEqual(rl.single_read(0x49), bytes.fromhex("c4090000044900e6fe"))

    def test_write_pair_cmd3_led_on(self):
        # host -> device writes are cmd-0x03 pairs (the app's UI write path)
        self.assertEqual(rl.write_value(0x2089, 1), bytes.fromhex("c40b0000038920010084fe"))

    def test_write_pair_cmd3_color_red(self):
        self.assertEqual(rl.write_value(0x208C, 1), bytes.fromhex("c40b0000038c20010081fe"))

    def test_block_read_cmd6_sn(self):
        # the DLL's cmd-6 frame for a 16-value serial-number block read
        self.assertEqual(rl.block_read(0x1E, 0x10), bytes.fromhex("c40b0000061e001000fdfe"))

    def test_block_read_cmd6_custom_colors(self):
        # 5 custom colors x (H, S, V) values
        self.assertEqual(rl.block_read(0x208F, 15), bytes.fromhex("c40b0000068f200f006dfe"))

    def test_ack_shape(self):
        frame = rl.build_frame(rl.CMD_ACK, struct.pack("<HH", 0x2084, 0))
        self.assertEqual(frame[0], rl.MAGIC)
        self.assertEqual(frame[4], rl.CMD_ACK)
        self.assertEqual(frame[1] | (frame[2] << 8), 0x0B)

    def test_checksum_roundtrip(self):
        cases = [
            (rl.CMD_READ, struct.pack("<H", 0x42)),
            (rl.CMD_WRITE, struct.pack("<HH", 0x2E, 0x10)),
            (rl.CMD_READ_BLOCK, struct.pack("<HH", 0x208F, 15)),
            (rl.CMD_ACK, struct.pack("<HHHH", 0x2084, 1, 0x49, 0x2000)),
        ]
        for cmd, payload in cases:
            frame = rl.build_frame(cmd, payload)
            length = frame[1] | (frame[2] << 8)
            self.assertEqual(length, len(frame))
            expected = (-sum(frame[: length - 2])) & 0xFFFF
            stored = frame[length - 2] | (frame[length - 1] << 8)
            self.assertEqual(expected, stored)


class ParserTests(unittest.TestCase):
    def test_parse_frame_roundtrip(self):
        frame = rl.write_value(0x2E, 0x10)
        self.assertEqual(rl.parse_frame(frame), (rl.CMD_WRITE, struct.pack("<HH", 0x2E, 0x10)))

    def test_parse_frame_allows_zero_padding(self):
        frame = rl.single_read(0x42) + b"\x00" * 20
        cmd, payload = rl.parse_frame(frame)
        self.assertEqual(cmd, rl.CMD_READ)
        self.assertEqual(payload, b"\x42\x00")

    def test_rejects_bad_checksum(self):
        frame = bytearray(rl.single_read(0x42))
        frame[-1] ^= 0xFF
        self.assertIsNone(rl.parse_frame(bytes(frame)))

    def test_rejects_short_frame(self):
        self.assertIsNone(rl.parse_frame(b"\xc4\x09\x00"))

    def test_rejects_wrong_magic(self):
        frame = bytearray(rl.single_read(0x42))
        frame[0] = 0x00
        self.assertIsNone(rl.parse_frame(bytes(frame)))

    def test_strip_report_id(self):
        frame = rl.single_read(0x42)
        self.assertEqual(rl.strip_report_id(b"\x00" + frame), frame)
        self.assertEqual(rl.strip_report_id(frame), frame)


class StateTests(unittest.TestCase):
    def test_battery_and_charge_pairs(self):
        state = rl.State()
        battery = 85 | (76 << 8)   # TX1 85 %, TX2 76 %
        charge = 0 | (1 << 8)      # TX1 not charging, TX2 charging
        payload = struct.pack("<HHHH", 0x42, battery, 0x49, charge)
        pairs = rl.parse_pairs(payload)
        self.assertEqual(pairs, {0x42: battery, 0x49: charge})
        state.update_from_pairs(pairs)
        self.assertEqual((state.tx1_batt, state.tx2_batt), (85, 76))
        self.assertEqual((state.tx1_chg, state.tx2_chg), (0, 1))
        self.assertTrue(state.has_data())

    def test_ignores_unrelated_keys(self):
        state = rl.State()
        state.update_from_pairs({0x41: 0x1234, 0x47: 0x0001})
        self.assertFalse(state.has_data())


class LightingTests(unittest.TestCase):
    def test_channel_key_spaces(self):
        self.assertEqual(rl.light_key(1, rl.LIGHT_LED_OFF), 0x2089)
        self.assertEqual(rl.light_key(2, rl.LIGHT_LED_OFF), 0x2889)
        self.assertEqual(rl.light_key(1, rl.LIGHT_CUSTOM_OFF), 0x208F)
        self.assertEqual(rl.light_key(2, rl.LIGHT_CUSTOM_OFF + 0x0C), 0x289B)

    def test_parse_color_presets(self):
        self.assertEqual(rl.parse_color("white"), ("preset", 0))
        self.assertEqual(rl.parse_color("Magenta"), ("preset", 7))
        self.assertEqual(rl.parse_color("3"), ("preset", 3))
        self.assertIsNone(rl.parse_color("8"))
        self.assertIsNone(rl.parse_color("purple"))

    def test_parse_color_custom(self):
        self.assertEqual(rl.parse_color("#FF0000"), ("custom", (255, 0, 0)))
        self.assertEqual(rl.parse_color("#f00"), ("custom", (255, 0, 0)))
        self.assertEqual(rl.parse_color("00ff00"), ("custom", (0, 255, 0)))
        self.assertIsNone(rl.parse_color("#12345"))

    def test_rgb_to_light_hsv(self):
        # H is hue in degrees x100 (the app's double x100 encoder), S/V percent
        self.assertEqual(rl.rgb_to_light_hsv(255, 0, 0), (0, 100, 100))
        self.assertEqual(rl.rgb_to_light_hsv(0, 255, 0), (12000, 100, 100))
        self.assertEqual(rl.rgb_to_light_hsv(0, 0, 255), (24000, 100, 100))
        self.assertEqual(rl.rgb_to_light_hsv(255, 255, 255), (0, 0, 100))

    def test_plan_lighting_basic(self):
        args = rl.parse_args(["--light", "on", "--light-mode", "breathe", "--light-brightness", "50"])
        writes = rl.plan_lighting(args)
        self.assertEqual(
            [(key, value) for key, value, _ in writes],
            [(0x2089, 1), (0x208A, 50), (0x208B, 2)],
        )

    def test_plan_lighting_preset_color_channel2(self):
        args = rl.parse_args(["--light-color", "red", "--channel", "2"])
        self.assertEqual(rl.plan_lighting(args), [(0x288C, 1, "color=red(1)")])

    def test_plan_lighting_custom_color(self):
        args = rl.parse_args(["--light-color", "#00ff00", "--light-slot", "2"])
        writes = rl.plan_lighting(args)
        self.assertEqual(
            [(key, value) for key, value, _ in writes],
            [(0x2092, 12000), (0x2093, 100), (0x2094, 100), (0x208C, 9)],
        )

    def test_plan_lighting_raw_hsv_does_not_select(self):
        args = rl.parse_args(["--light-hsv", "100,20,30"])
        self.assertEqual(
            rl.plan_lighting(args),
            [
                (0x208F, 100, "custom1.h=100"),
                (0x2090, 20, "custom1.s=20"),
                (0x2091, 30, "custom1.v=30"),
            ],
        )

    def test_plan_lighting_both_channels(self):
        args = rl.parse_args(["--light", "off", "--channel", "both"])
        self.assertEqual(
            rl.plan_lighting(args),
            [(0x2089, 0, "led=off"), (0x2889, 0, "led=off")],
        )

    def test_light_value_names(self):
        self.assertEqual(rl.light_value_names(rl.LIGHT_LED_OFF, 1), "on")
        self.assertEqual(rl.light_value_names(rl.LIGHT_LED_OFF, 0), "off")
        self.assertEqual(rl.light_value_names(rl.LIGHT_MODE_OFF, 1), "loop")
        self.assertEqual(rl.light_value_names(rl.LIGHT_MODE_OFF, 2), "breathe")
        self.assertEqual(rl.light_value_names(rl.LIGHT_COLOR_OFF, 7), "magenta(7)")
        self.assertEqual(rl.light_value_names(rl.LIGHT_COLOR_OFF, 8), "custom1(8)")
        self.assertEqual(rl.light_value_names(rl.LIGHT_BRIGHTNESS_OFF, 42), "42")

    def test_light_status_record(self):
        record = rl.light_status_record(
            {rl.LIGHT_LED_OFF: 1, rl.LIGHT_MODE_OFF: 2, rl.LIGHT_COLOR_OFF: 5}
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
                    rl.parse_args(argv)


class NoiseTests(unittest.TestCase):
    def test_noise_key_spaces(self):
        self.assertEqual(rl.noise_key(1, rl.NOISE_STATE_OFF), 0x2084)
        self.assertEqual(rl.noise_key(1, rl.NOISE_LEVEL_OFF), 0x2085)
        self.assertEqual(rl.noise_key(2, rl.NOISE_LEVEL_OFF), 0x2885)

    def test_noise_write_frames(self):
        # cmd-3 pairs as the app's "NR" widget sends them (docs/protocol.md §11)
        self.assertEqual(rl.write_value(0x2084, 1), bytes.fromhex("c40b0000038420010089fe"))
        self.assertEqual(rl.write_value(0x2085, 0), bytes.fromhex("c40b0000038520000089fe"))
        self.assertEqual(rl.single_read(0x2084), bytes.fromhex("c40900000484208bfe"))

    def test_plan_noise_basic(self):
        args = rl.parse_args(["--noise", "on", "--noise-level", "aggressive"])
        self.assertEqual(
            rl.plan_noise(args),
            [(0x2084, 1, "noise=on"), (0x2085, 2, "noise-level=aggressive(2)")],
        )
        self.assertEqual(rl.plan_noise(rl.parse_args([])), [])
        self.assertEqual(
            rl.plan_noise(rl.parse_args(["--noise", "off"])),
            [(0x2084, 0, "noise=off")],
        )

    def test_plan_noise_channels(self):
        self.assertEqual(
            rl.plan_noise(rl.parse_args(["--noise-level", "gentle", "--channel", "2"])),
            [(0x2885, 0, "noise-level=gentle(0)")],
        )
        self.assertEqual(
            rl.plan_noise(rl.parse_args(["--noise", "on", "--channel", "both"])),
            [(0x2084, 1, "noise=on"), (0x2884, 1, "noise=on")],
        )

    def test_parse_noise_level(self):
        self.assertEqual(rl.parse_noise_level("gentle"), 0)
        self.assertEqual(rl.parse_noise_level("Soft"), 0)
        self.assertEqual(rl.parse_noise_level("MID"), 1)
        self.assertEqual(rl.parse_noise_level("balanced"), 1)
        self.assertEqual(rl.parse_noise_level("strong"), 2)
        self.assertEqual(rl.parse_noise_level("0"), 0)
        self.assertEqual(rl.parse_noise_level("2"), 2)
        self.assertIsNone(rl.parse_noise_level("3"))
        self.assertIsNone(rl.parse_noise_level("-1"))
        self.assertIsNone(rl.parse_noise_level("loud"))

    def test_noise_value_names(self):
        self.assertEqual(rl.noise_value_names(rl.NOISE_STATE_OFF, 1), "on")
        self.assertEqual(rl.noise_value_names(rl.NOISE_STATE_OFF, 0), "off")
        self.assertEqual(rl.noise_value_names(rl.NOISE_LEVEL_OFF, 2), "aggressive")
        self.assertEqual(rl.noise_value_names(rl.NOISE_LEVEL_OFF, 7), "?(7)")

    def test_noise_status_record(self):
        record = rl.noise_status_record({rl.NOISE_STATE_OFF: 1, rl.NOISE_LEVEL_OFF: 0})
        self.assertEqual(record["noise"], 1)
        self.assertEqual(record["noise_name"], "on")
        self.assertEqual(record["level"], 0)
        self.assertEqual(record["level_name"], "gentle")
        self.assertIsNone(rl.noise_status_record({})["noise"])
        self.assertIsNone(rl.noise_status_record({}).get("noise_name"))

    def test_noise_validation_errors(self):
        bad_argv = (
            ["--noise-level", "3"],
            ["--noise-level", "loud"],
            ["--noise", "on", "--watch"],
            ["--noise-status", "--watch"],
            ["--noise", "on", "--light", "off"],
            ["--noise-status", "--light-status"],
            ["--noise", "on", "--scene", "game"],
            ["--noise-level", "gentle", "--eq-status"],
        )
        with contextlib.redirect_stderr(io.StringIO()):
            for argv in bad_argv:
                with self.assertRaises(SystemExit, msg=repr(argv)):
                    rl.parse_args(argv)

    def test_noise_dry_run_needs_no_device(self):
        def fail(_args):
            raise AssertionError("--dry-run must not open the device")

        original = rl.open_device
        rl.open_device = fail
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = rl.main(["--noise", "on", "--noise-level", "gentle", "--dry-run"])
            self.assertEqual(code, 0)
            self.assertEqual(
                out.getvalue().splitlines(),
                ["dry-run 0x2084 <= 1   noise=on", "dry-run 0x2085 <= 0   noise-level=gentle(0)"],
            )
        finally:
            rl.open_device = original


class EqEncodingTests(unittest.TestCase):
    def test_gain_encoding_matches_app(self):
        # FUN_18006d840: (int)(gain * 10 + 2000), truncating toward zero
        self.assertEqual(rl.encode_eq_gain(0), 2000)
        self.assertEqual(rl.encode_eq_gain(2.5), 2025)
        self.assertEqual(rl.encode_eq_gain(-4.5), 1955)
        self.assertEqual(rl.encode_eq_gain(-4.045714285714286), 1959)
        self.assertEqual(rl.encode_eq_gain(-12), 1880)
        self.assertEqual(rl.encode_eq_gain(-12.5), 2000)  # below -12 dB the app writes 0 dB
        self.assertEqual(rl.encode_eq_gain(-30), 2000)

    def test_q_encoding_matches_app(self):
        # FUN_18006d860: (int)(Q * 100)
        self.assertEqual(rl.encode_eq_q(0.7), 70)
        self.assertEqual(rl.encode_eq_q(2.5), 250)
        self.assertEqual(rl.encode_eq_q(8), 800)

    def test_slot_values_map_filter_types(self):
        # FUN_180045c40: JSON type 0 -> device 1, 1 -> 0, 2 -> 2, 3 -> 3, 4 -> 5;
        # HPF/LPF gains are forced to the 0 dB marker (2000)
        self.assertEqual(rl.eq_slot_values(1000, -3, 2, 0), [1, 1, 1000, 1970, 200])
        self.assertEqual(rl.eq_slot_values(60, -4.5, 0.5, 1), [1, 0, 60, 1955, 50])
        self.assertEqual(rl.eq_slot_values(10000, -7.062857142857143, 0.7, 2), [1, 2, 10000, 1929, 70])
        self.assertEqual(rl.eq_slot_values(20000, -1, 1, 3), [1, 3, 20000, 2000, 100])
        self.assertEqual(rl.eq_slot_values(63.26942754238026, -1, 1, 4), [1, 5, 63, 2000, 100])

    def test_eq_key_spaces(self):
        self.assertEqual(rl.eq_key(1, rl.EQ_MODE_OFF), 0x2022)
        self.assertEqual(rl.eq_key(2, rl.EQ_MODE_OFF), 0x2822)
        self.assertEqual(rl.eq_key(1, rl.EQ_BAND_OFF), 0x2023)
        self.assertEqual(rl.eq_key(2, rl.EQ_LEVEL_OFF), 0x2883)


class EqPlanTests(unittest.TestCase):
    def test_write_pairs_multiple(self):
        frame = rl.write_pairs([(0x2023, 1), (0x2024, 1), (0x2025, 125)])
        self.assertEqual(frame[:5], bytes.fromhex("c413000003"))  # len = 7 + 4*3
        parsed = rl.parse_frame(frame)
        self.assertIsNotNone(parsed)
        cmd, payload = parsed
        self.assertEqual(cmd, rl.CMD_WRITE)
        self.assertEqual(rl.parse_pairs(payload), {0x2023: 1, 0x2024: 1, 0x2025: 125})

    def test_write_pairs_single_matches_write_value(self):
        self.assertEqual(rl.write_pairs([(0x2089, 1)]), rl.write_value(0x2089, 1))

    def test_scene_original_frames(self):
        args = rl.parse_args(["--scene", "original"])
        frames = rl.plan_eq_frames(args)
        self.assertEqual(len(frames), 10)  # 7 band frames + mixture + level + mode
        self.assertEqual(
            dict((key, value) for key, value, _ in frames[0]),
            {0x2023: 1, 0x2024: 1, 0x2025: 125, 0x2026: 2000, 0x2027: 100},
        )
        self.assertEqual(frames[7], [(0x2082, 0, "original mixture=0")])
        self.assertEqual(frames[8], [(0x2083, 0, "original level=0")])
        self.assertEqual(frames[9], [(0x2022, 0x0000, "scene=original:0")])

    def test_scene_sing_folk_reverb_and_mode(self):
        args = rl.parse_args(["--scene", "sing:1"])
        frames = rl.plan_eq_frames(args)
        self.assertEqual(frames[7], [(0x2082, 1, "folk mixture=1")])
        self.assertEqual(frames[8], [(0x2083, 1, "folk level=1")])
        self.assertEqual(frames[9], [(0x2022, 0x0301, "scene=sing:1")])
        self.assertEqual(
            dict((key, value) for key, value, _ in frames[0]),
            {0x2023: 1, 0x2024: 1, 0x2025: 171, 0x2026: 1980, 0x2027: 100},
        )

    def test_scene_podcast2_custom_flag(self):
        args = rl.parse_args(["--scene", "podcast:1", "--eq-flag", "1"])
        frames = rl.plan_eq_frames(args)
        self.assertEqual(frames[-1], [(0x2022, 0x0101 | 0x8000, "scene=podcast:1 custom")])

    def test_scene_both_channels(self):
        args = rl.parse_args(["--scene", "game", "--channel", "both"])
        frames = rl.plan_eq_frames(args)
        keys = [key for frame in frames for key, _, _ in frame]
        self.assertIn(0x2022, keys)
        self.assertIn(0x2822, keys)
        self.assertEqual(len(frames), 20)  # 2 * (7 bands + mixture + level + mode)

    def test_eq_band_edit(self):
        args = rl.parse_args(["--eq-band", "3", "1000", "-4", "2.5"])
        self.assertEqual(
            rl.plan_eq_frames(args),
            [
                [
                    (0x202D, 1, "band3 enable"),
                    (0x202E, 1, "band3 type=peak"),
                    (0x202F, 1000, "band3 freq=1000"),
                    (0x2030, 1960, "band3 gain=-4dB"),
                    (0x2031, 250, "band3 Q=2.5"),
                ]
            ],
        )

    def test_eq_band_edit_shelf_type(self):
        args = rl.parse_args(["--eq-band", "1", "60", "-4.5", "0.5", "low-shelf"])
        slot = rl.plan_eq_frames(args)[0]
        self.assertEqual(dict((key, value) for key, value, _ in slot)[0x2024], 0)
        self.assertEqual(dict((key, value) for key, value, _ in slot)[0x2026], 1955)

    def test_eq_hpf_lpf_edits(self):
        args = rl.parse_args(["--eq-hpf", "80:0.7", "--eq-lpf", "off"])
        frames = rl.plan_eq_frames(args)
        self.assertEqual(
            [(key, value) for key, value, _ in frames[0]],
            [(0x203C, 1), (0x203D, 5), (0x203E, 80), (0x203F, 2000), (0x2040, 70)],
        )
        self.assertEqual(
            [(key, value) for key, value, _ in frames[1]],
            [(0x2041, 1), (0x2042, 3), (0x2043, 20000), (0x2044, 2000), (0x2045, 100)],
        )

    def test_eq_reg_raw(self):
        args = rl.parse_args(["--eq-reg", "0x2882=1", "--eq-reg", "0x2022=0x8001"])
        self.assertEqual(
            rl.plan_eq_frames(args),
            [[(0x2882, 1, "raw 0x2882")], [(0x2022, 0x8001, "raw 0x2022")]],
        )

    def test_eq_preset_needs_no_mode_frame(self):
        args = rl.parse_args(["--eq-preset", "folk"])
        frames = rl.plan_eq_frames(args)
        self.assertEqual(len(frames), 9)  # 7 band frames + mixture + level
        self.assertNotIn(0x2022, [key for frame in frames for key, _, _ in frame])


class EqPresetTests(unittest.TestCase):
    def test_preset_table_integrity(self):
        self.assertEqual(
            set(rl.EQ_PRESETS),
            {"original", "podcast1", "podcast2", "game1", "game2", "pop", "folk"},
        )
        for key, curve in rl.EQ_PRESETS.items():
            self.assertEqual(len(curve["map_points"]), 5, key)
            self.assertEqual(curve["HPF"]["type"], 4, key)
            self.assertEqual(curve["LPF"]["type"], 3, key)
            for point in curve["map_points"]:
                self.assertIn(point["type"], (0, 1, 2), key)
            self.assertEqual(curve["sample_rate"], 48000, key)

    def test_preset_reverb_fields(self):
        self.assertEqual((rl.EQ_PRESETS["original"]["mixture"], rl.EQ_PRESETS["original"]["level"]), (0, 0))
        self.assertEqual((rl.EQ_PRESETS["podcast1"]["mixture"], rl.EQ_PRESETS["podcast1"]["level"]), (0, 0))
        self.assertEqual((rl.EQ_PRESETS["pop"]["mixture"], rl.EQ_PRESETS["pop"]["level"]), (1, 5))
        self.assertEqual((rl.EQ_PRESETS["folk"]["mixture"], rl.EQ_PRESETS["folk"]["level"]), (1, 1))

    def test_scene_tables(self):
        self.assertEqual(rl.SCENES, {"original": 0, "podcast": 1, "game": 2, "sing": 3})
        self.assertEqual(rl.SCENE_PRESETS["original"], ("original",))
        self.assertEqual(rl.SCENE_PRESETS["podcast"], ("podcast1", "podcast2"))
        self.assertEqual(rl.SCENE_PRESETS["game"], ("game1", "game2"))
        self.assertEqual(rl.SCENE_PRESETS["sing"], ("pop", "folk"))


class EqProfileTests(unittest.TestCase):
    def test_export_import_round_trip(self):
        args = rl.parse_args(["--eq-export", "unused.cfg", "--eq-preset", "podcast2"])
        curve, name, mixture, level, default = rl.curve_from_args(args)
        item = rl.parse_cfg_text(rl.cfg_text(name, curve, mixture, level, default))
        self.assertEqual(item["device_name"], "PD200XW")
        self.assertEqual(item["name"], "Podcast2")
        self.assertEqual((item["mixture"], item["level"]), (0, 0))
        self.assertTrue(item["default"])
        self.assertEqual(item["curve"]["curve_name"], "Podcast2")
        self.assertEqual(item["curve"]["map_points"][2]["frequence"], 546)

    def test_export_custom_curve_records_edits(self):
        args = rl.parse_args(
            [
                "--eq-export",
                "unused.cfg",
                "--eq-band",
                "1",
                "200",
                "3",
                "1.5",
                "--eq-hpf",
                "90",
                "--eq-name",
                "Podcast+",
                "--eq-mixture",
                "1",
                "--eq-level",
                "3",
            ]
        )
        curve, name, mixture, level, default = rl.curve_from_args(args)
        self.assertEqual(name, "Podcast+")
        self.assertEqual((mixture, level), (1, 3))
        self.assertFalse(default)
        item = rl.parse_cfg_text(rl.cfg_text(name, curve, mixture, level, default))
        self.assertEqual(item["curve"]["map_points"][0]["frequence"], 200)
        self.assertEqual(item["curve"]["map_points"][0]["Gain"], 3)
        self.assertEqual(item["curve"]["HPF"]["frequence"], 90)
        self.assertEqual(item["curve"]["LPF"]["frequence"], 20000)  # untouched default
        self.assertEqual((item["mixture"], item["level"]), (1, 3))

    def test_export_scene_source(self):
        args = rl.parse_args(["--eq-export", "unused.cfg", "--scene", "sing:1"])
        curve, name, mixture, level, default = rl.curve_from_args(args)
        self.assertEqual(name, "Folk")
        self.assertEqual((mixture, level), (1, 1))
        self.assertTrue(default)

    def test_parse_cfg_rejects_bad_input(self):
        for text in (
            "not json",
            "[]",
            '{"device_name": "PD200XW"}',
            json.dumps({"device_name": "PD200XW", "curve_contains": "{"}),
            json.dumps({"device_name": "PD200XW", "curve_contains": "{}"}),
        ):
            with self.assertRaises(rl.ConfigError, msg=text):
                rl.parse_cfg_text(text)

    def test_export_needs_no_device(self):
        args = rl.parse_args(["--eq-export", "unused.cfg", "--eq-preset", "pop"])
        self.assertFalse(rl.eq_device_needed(args))
        self.assertTrue(rl.eq_device_needed(rl.parse_args(["--eq-export", "unused.cfg", "--eq-status"])))
        self.assertTrue(rl.eq_device_needed(rl.parse_args(["--eq-band", "1", "100", "3", "1"])))
        self.assertTrue(rl.eq_device_needed(rl.parse_args(["--scene", "game"])))
        self.assertTrue(rl.eq_device_needed(rl.parse_args(["--eq-status"])))
        self.assertFalse(rl.eq_device_needed(rl.parse_args([])))

    def test_dry_run_needs_no_device(self):
        def fail(_args):
            raise AssertionError("--dry-run must not open the device")

        original = rl.open_device
        rl.open_device = fail
        try:
            for argv in (
                ["--scene", "game", "--dry-run"],
                ["--eq-band", "2", "800", "-3", "1.5", "--dry-run"],
                ["--eq-hpf", "80", "--dry-run"],
            ):
                out = io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    code = rl.main(argv)
                self.assertEqual(code, 0, argv)
                self.assertTrue(out.getvalue().startswith("dry-run "), argv)
        finally:
            rl.open_device = original

    def test_eq_status_record_decodes_mode(self):
        record = rl.eq_status_record({rl.EQ_MODE_OFF: 0x0101, rl.EQ_MIXTURE_OFF: 0, rl.EQ_LEVEL_OFF: 0})
        self.assertEqual(record["scene_name"], "podcast")
        self.assertEqual(record["preset"], "podcast2")
        self.assertEqual(record["preset_index"], 1)
        self.assertFalse(record["custom"])

    def test_eq_status_record_decodes_bands(self):
        values = {rl.EQ_MODE_OFF: 0x8000 | 0x0301, rl.EQ_MIXTURE_OFF: 1, rl.EQ_LEVEL_OFF: 1}
        for slot in range(rl.EQ_SLOT_COUNT):
            base = rl.EQ_BAND_OFF + slot * rl.EQ_REGS_PER_SLOT
            values[base + 0] = 1
            values[base + 1] = 5 if slot == rl.EQ_SLOT_HPF else (3 if slot == rl.EQ_SLOT_LPF else 1)
            values[base + 2] = 80
            values[base + 3] = 2000
            values[base + 4] = 70
        record = rl.eq_status_record(values)
        self.assertTrue(record["custom"])
        self.assertEqual(record["scene_name"], "sing")
        self.assertEqual(record["preset"], "folk")
        self.assertEqual(record["bands"][0]["name"], "band1")
        self.assertEqual(record["bands"][0]["gain"], 0)
        self.assertEqual(record["bands"][0]["q"], 0.7)
        self.assertEqual(record["bands"][rl.EQ_SLOT_HPF]["type"], "hpf")
        self.assertIsNone(record["bands"][rl.EQ_SLOT_HPF]["gain"])
        self.assertEqual(record["bands"][0]["enable"], 1)
        self.assertEqual(record["bands"][0]["type"], "peak")


class EqValidationTests(unittest.TestCase):
    def test_eq_validation_errors(self):
        bad_argv = (
            ["--scene", "rock"],
            ["--scene", "sing:2"],
            ["--scene", "original:1"],
            ["--eq-preset", "unknown"],
            ["--eq-flag", "1"],
            ["--eq-band", "6", "100", "1", "1"],
            ["--eq-band", "1", "100", "1"],
            ["--eq-band", "1", "100", "13", "1"],
            ["--eq-band", "1", "30000", "1", "1"],
            ["--eq-band", "1", "100", "1", "1", "notch"],
            ["--eq-hpf", "0"],
            ["--eq-lpf", "20000", "1"],
            ["--eq-reg", "0x2082"],
            ["--eq-reg", "0x10000=1"],
            ["--eq-mixture", "1"],
            ["--eq-name", "X"],
            ["--eq-export", "x.cfg", "--eq-import", "y.cfg"],
            ["--eq-export", "x.cfg", "--eq-reg", "0x2082=1"],
            ["--light", "on", "--scene", "game"],
            ["--eq-status", "--watch"],
        )
        with contextlib.redirect_stderr(io.StringIO()):
            for argv in bad_argv:
                with self.assertRaises(SystemExit, msg=repr(argv)):
                    rl.parse_args(argv)

    def test_eq_option_normalization(self):
        args = rl.parse_args(["--scene", "Sing:1", "--eq-band", "2", "800.0", "-3", "1.5"])
        self.assertEqual(args.scene, ("sing", 1))
        self.assertEqual(args.eq_band, [(2, 800, -3, 1.5, 0)])
        args = rl.parse_args(["--eq-hpf", "OFF", "--eq-lpf", "12000", "--eq-preset", "POP"])
        self.assertEqual(args.eq_hpf, (20, 1))
        self.assertEqual(args.eq_lpf, (12000, 1))
        self.assertEqual(args.eq_preset, "pop")


class InterfacePathTests(unittest.TestCase):
    def test_usb_interface_component(self):
        path = (
            "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-3/1-3:1.3/"
            "0003:352F:040E.0003/hidraw/hidraw6"
        )
        self.assertEqual(rl.interface_from_path(path), 3)

    def test_hid_instance_dir_is_not_an_interface(self):
        # ".../0411.0051" must not be read as interface 51.
        path = (
            "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.5/"
            "0003:352F:0411.0051/hidraw/hidraw6"
        )
        self.assertEqual(rl.interface_from_path(path), 5)

    def test_no_interface_component(self):
        path = "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/0003:352F:0411.0051/hidraw/hidraw6"
        self.assertIsNone(rl.interface_from_path(path))

    def test_multidigit_port_path(self):
        self.assertEqual(
            rl.interface_from_path("/sys/devices/x/3-2.1/3-2.1:1.51/hidraw/hidraw9"),
            51,
        )


if __name__ == "__main__":
    unittest.main()
