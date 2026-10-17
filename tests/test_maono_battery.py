"""Unit tests for maono_battery.py — frame building/parsing and lighting.

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


class EqEncodingTests(unittest.TestCase):
    def test_gain_encoding_matches_app(self):
        # FUN_18006d840: (int)(gain * 10 + 2000), truncating toward zero
        self.assertEqual(mb.encode_eq_gain(0), 2000)
        self.assertEqual(mb.encode_eq_gain(2.5), 2025)
        self.assertEqual(mb.encode_eq_gain(-4.5), 1955)
        self.assertEqual(mb.encode_eq_gain(-4.045714285714286), 1959)
        self.assertEqual(mb.encode_eq_gain(-12), 1880)
        self.assertEqual(mb.encode_eq_gain(-12.5), 2000)  # below -12 dB the app writes 0 dB
        self.assertEqual(mb.encode_eq_gain(-30), 2000)

    def test_q_encoding_matches_app(self):
        # FUN_18006d860: (int)(Q * 100)
        self.assertEqual(mb.encode_eq_q(0.7), 70)
        self.assertEqual(mb.encode_eq_q(2.5), 250)
        self.assertEqual(mb.encode_eq_q(8), 800)

    def test_slot_values_map_filter_types(self):
        # FUN_180045c40: JSON type 0 -> device 1, 1 -> 0, 2 -> 2, 3 -> 3, 4 -> 5;
        # HPF/LPF gains are forced to the 0 dB marker (2000)
        self.assertEqual(mb.eq_slot_values(1000, -3, 2, 0), [1, 1, 1000, 1970, 200])
        self.assertEqual(mb.eq_slot_values(60, -4.5, 0.5, 1), [1, 0, 60, 1955, 50])
        self.assertEqual(mb.eq_slot_values(10000, -7.062857142857143, 0.7, 2), [1, 2, 10000, 1929, 70])
        self.assertEqual(mb.eq_slot_values(20000, -1, 1, 3), [1, 3, 20000, 2000, 100])
        self.assertEqual(mb.eq_slot_values(63.26942754238026, -1, 1, 4), [1, 5, 63, 2000, 100])

    def test_eq_key_spaces(self):
        self.assertEqual(mb.eq_key(1, mb.EQ_MODE_OFF), 0x2022)
        self.assertEqual(mb.eq_key(2, mb.EQ_MODE_OFF), 0x2822)
        self.assertEqual(mb.eq_key(1, mb.EQ_BAND_OFF), 0x2023)
        self.assertEqual(mb.eq_key(2, mb.EQ_LEVEL_OFF), 0x2883)


class EqPlanTests(unittest.TestCase):
    def test_write_pairs_multiple(self):
        frame = mb.write_pairs([(0x2023, 1), (0x2024, 1), (0x2025, 125)])
        self.assertEqual(frame[:5], bytes.fromhex("c413000003"))  # len = 7 + 4*3
        parsed = mb.parse_frame(frame)
        self.assertIsNotNone(parsed)
        cmd, payload = parsed
        self.assertEqual(cmd, mb.CMD_WRITE)
        self.assertEqual(mb.parse_pairs(payload), {0x2023: 1, 0x2024: 1, 0x2025: 125})

    def test_write_pairs_single_matches_write_value(self):
        self.assertEqual(mb.write_pairs([(0x2089, 1)]), mb.write_value(0x2089, 1))

    def test_scene_original_frames(self):
        args = mb.parse_args(["--scene", "original"])
        frames = mb.plan_eq_frames(args)
        self.assertEqual(len(frames), 10)  # 7 band frames + mixture + level + mode
        self.assertEqual(
            dict((key, value) for key, value, _ in frames[0]),
            {0x2023: 1, 0x2024: 1, 0x2025: 125, 0x2026: 2000, 0x2027: 100},
        )
        self.assertEqual(frames[7], [(0x2082, 0, "original mixture=0")])
        self.assertEqual(frames[8], [(0x2083, 0, "original level=0")])
        self.assertEqual(frames[9], [(0x2022, 0x0000, "scene=original:0")])

    def test_scene_sing_folk_reverb_and_mode(self):
        args = mb.parse_args(["--scene", "sing:1"])
        frames = mb.plan_eq_frames(args)
        self.assertEqual(frames[7], [(0x2082, 1, "folk mixture=1")])
        self.assertEqual(frames[8], [(0x2083, 1, "folk level=1")])
        self.assertEqual(frames[9], [(0x2022, 0x0301, "scene=sing:1")])
        self.assertEqual(
            dict((key, value) for key, value, _ in frames[0]),
            {0x2023: 1, 0x2024: 1, 0x2025: 171, 0x2026: 1980, 0x2027: 100},
        )

    def test_scene_podcast2_custom_flag(self):
        args = mb.parse_args(["--scene", "podcast:1", "--eq-flag", "1"])
        frames = mb.plan_eq_frames(args)
        self.assertEqual(frames[-1], [(0x2022, 0x0101 | 0x8000, "scene=podcast:1 custom")])

    def test_scene_both_channels(self):
        args = mb.parse_args(["--scene", "game", "--channel", "both"])
        frames = mb.plan_eq_frames(args)
        keys = [key for frame in frames for key, _, _ in frame]
        self.assertIn(0x2022, keys)
        self.assertIn(0x2822, keys)
        self.assertEqual(len(frames), 20)  # 2 * (7 bands + mixture + level + mode)

    def test_eq_band_edit(self):
        args = mb.parse_args(["--eq-band", "3", "1000", "-4", "2.5"])
        self.assertEqual(
            mb.plan_eq_frames(args),
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
        args = mb.parse_args(["--eq-band", "1", "60", "-4.5", "0.5", "low-shelf"])
        slot = mb.plan_eq_frames(args)[0]
        self.assertEqual(dict((key, value) for key, value, _ in slot)[0x2024], 0)
        self.assertEqual(dict((key, value) for key, value, _ in slot)[0x2026], 1955)

    def test_eq_hpf_lpf_edits(self):
        args = mb.parse_args(["--eq-hpf", "80:0.7", "--eq-lpf", "off"])
        frames = mb.plan_eq_frames(args)
        self.assertEqual(
            [(key, value) for key, value, _ in frames[0]],
            [(0x203C, 1), (0x203D, 5), (0x203E, 80), (0x203F, 2000), (0x2040, 70)],
        )
        self.assertEqual(
            [(key, value) for key, value, _ in frames[1]],
            [(0x2041, 1), (0x2042, 3), (0x2043, 20000), (0x2044, 2000), (0x2045, 100)],
        )

    def test_eq_reg_raw(self):
        args = mb.parse_args(["--eq-reg", "0x2882=1", "--eq-reg", "0x2022=0x8001"])
        self.assertEqual(
            mb.plan_eq_frames(args),
            [[(0x2882, 1, "raw 0x2882")], [(0x2022, 0x8001, "raw 0x2022")]],
        )

    def test_eq_preset_needs_no_mode_frame(self):
        args = mb.parse_args(["--eq-preset", "folk"])
        frames = mb.plan_eq_frames(args)
        self.assertEqual(len(frames), 9)  # 7 band frames + mixture + level
        self.assertNotIn(0x2022, [key for frame in frames for key, _, _ in frame])


class EqPresetTests(unittest.TestCase):
    def test_preset_table_integrity(self):
        self.assertEqual(
            set(mb.EQ_PRESETS),
            {"original", "podcast1", "podcast2", "game1", "game2", "pop", "folk"},
        )
        for key, curve in mb.EQ_PRESETS.items():
            self.assertEqual(len(curve["map_points"]), 5, key)
            self.assertEqual(curve["HPF"]["type"], 4, key)
            self.assertEqual(curve["LPF"]["type"], 3, key)
            for point in curve["map_points"]:
                self.assertIn(point["type"], (0, 1, 2), key)
            self.assertEqual(curve["sample_rate"], 48000, key)

    def test_preset_reverb_fields(self):
        self.assertEqual((mb.EQ_PRESETS["original"]["mixture"], mb.EQ_PRESETS["original"]["level"]), (0, 0))
        self.assertEqual((mb.EQ_PRESETS["podcast1"]["mixture"], mb.EQ_PRESETS["podcast1"]["level"]), (0, 0))
        self.assertEqual((mb.EQ_PRESETS["pop"]["mixture"], mb.EQ_PRESETS["pop"]["level"]), (1, 5))
        self.assertEqual((mb.EQ_PRESETS["folk"]["mixture"], mb.EQ_PRESETS["folk"]["level"]), (1, 1))

    def test_scene_tables(self):
        self.assertEqual(mb.SCENES, {"original": 0, "podcast": 1, "game": 2, "sing": 3})
        self.assertEqual(mb.SCENE_PRESETS["original"], ("original",))
        self.assertEqual(mb.SCENE_PRESETS["podcast"], ("podcast1", "podcast2"))
        self.assertEqual(mb.SCENE_PRESETS["game"], ("game1", "game2"))
        self.assertEqual(mb.SCENE_PRESETS["sing"], ("pop", "folk"))


class EqProfileTests(unittest.TestCase):
    def test_export_import_round_trip(self):
        args = mb.parse_args(["--eq-export", "unused.cfg", "--eq-preset", "podcast2"])
        curve, name, mixture, level, default = mb.curve_from_args(args)
        item = mb.parse_cfg_text(mb.cfg_text(name, curve, mixture, level, default))
        self.assertEqual(item["device_name"], "PD200XW")
        self.assertEqual(item["name"], "Podcast2")
        self.assertEqual((item["mixture"], item["level"]), (0, 0))
        self.assertTrue(item["default"])
        self.assertEqual(item["curve"]["curve_name"], "Podcast2")
        self.assertEqual(item["curve"]["map_points"][2]["frequence"], 546)

    def test_export_custom_curve_records_edits(self):
        args = mb.parse_args(
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
        curve, name, mixture, level, default = mb.curve_from_args(args)
        self.assertEqual(name, "Podcast+")
        self.assertEqual((mixture, level), (1, 3))
        self.assertFalse(default)
        item = mb.parse_cfg_text(mb.cfg_text(name, curve, mixture, level, default))
        self.assertEqual(item["curve"]["map_points"][0]["frequence"], 200)
        self.assertEqual(item["curve"]["map_points"][0]["Gain"], 3)
        self.assertEqual(item["curve"]["HPF"]["frequence"], 90)
        self.assertEqual(item["curve"]["LPF"]["frequence"], 20000)  # untouched default
        self.assertEqual((item["mixture"], item["level"]), (1, 3))

    def test_export_scene_source(self):
        args = mb.parse_args(["--eq-export", "unused.cfg", "--scene", "sing:1"])
        curve, name, mixture, level, default = mb.curve_from_args(args)
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
            with self.assertRaises(mb.ConfigError, msg=text):
                mb.parse_cfg_text(text)

    def test_export_needs_no_device(self):
        args = mb.parse_args(["--eq-export", "unused.cfg", "--eq-preset", "pop"])
        self.assertFalse(mb.eq_device_needed(args))
        self.assertTrue(mb.eq_device_needed(mb.parse_args(["--eq-export", "unused.cfg", "--eq-status"])))
        self.assertTrue(mb.eq_device_needed(mb.parse_args(["--eq-band", "1", "100", "3", "1"])))
        self.assertTrue(mb.eq_device_needed(mb.parse_args(["--scene", "game"])))
        self.assertTrue(mb.eq_device_needed(mb.parse_args(["--eq-status"])))
        self.assertFalse(mb.eq_device_needed(mb.parse_args([])))

    def test_eq_status_record_decodes_mode(self):
        record = mb.eq_status_record({mb.EQ_MODE_OFF: 0x0101, mb.EQ_MIXTURE_OFF: 0, mb.EQ_LEVEL_OFF: 0})
        self.assertEqual(record["scene_name"], "podcast")
        self.assertEqual(record["preset"], "podcast2")
        self.assertEqual(record["preset_index"], 1)
        self.assertFalse(record["custom"])

    def test_eq_status_record_decodes_bands(self):
        values = {mb.EQ_MODE_OFF: 0x8000 | 0x0301, mb.EQ_MIXTURE_OFF: 1, mb.EQ_LEVEL_OFF: 1}
        for slot in range(mb.EQ_SLOT_COUNT):
            base = mb.EQ_BAND_OFF + slot * mb.EQ_REGS_PER_SLOT
            values[base + 0] = 1
            values[base + 1] = 5 if slot == mb.EQ_SLOT_HPF else (3 if slot == mb.EQ_SLOT_LPF else 1)
            values[base + 2] = 80
            values[base + 3] = 2000
            values[base + 4] = 70
        record = mb.eq_status_record(values)
        self.assertTrue(record["custom"])
        self.assertEqual(record["scene_name"], "sing")
        self.assertEqual(record["preset"], "folk")
        self.assertEqual(record["bands"][0]["name"], "band1")
        self.assertEqual(record["bands"][0]["gain"], 0)
        self.assertEqual(record["bands"][0]["q"], 0.7)
        self.assertEqual(record["bands"][mb.EQ_SLOT_HPF]["type"], "hpf")
        self.assertIsNone(record["bands"][mb.EQ_SLOT_HPF]["gain"])
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
                    mb.parse_args(argv)

    def test_eq_option_normalization(self):
        args = mb.parse_args(["--scene", "Sing:1", "--eq-band", "2", "800.0", "-3", "1.5"])
        self.assertEqual(args.scene, ("sing", 1))
        self.assertEqual(args.eq_band, [(2, 800, -3, 1.5, 0)])
        args = mb.parse_args(["--eq-hpf", "OFF", "--eq-lpf", "12000", "--eq-preset", "POP"])
        self.assertEqual(args.eq_hpf, (20, 1))
        self.assertEqual(args.eq_lpf, (12000, 1))
        self.assertEqual(args.eq_preset, "pop")


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
