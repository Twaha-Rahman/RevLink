#!/usr/bin/env python3
"""Battery status, RGB lighting and scene/PEQ control for Maono PD200W mics.

By default the tool probes the battery once, prints one status line and exits;
pass ``--watch`` to keep running and print updates whenever values change.
Lighting options (``--light*``) apply settings to the mic's LED ring instead
and exit after confirming what was written; ``--light-status`` reads back the
current lighting registers.  Scene/EQ options (``--scene``, ``--eq*``) select
one of the four sound presets or edit the seven-point PEQ (5 bands + HPF/LPF),
and read the active mode back with ``--eq-status``; ``--eq-export`` /
``--eq-import`` share sound profiles in the Windows app's ``.cfg`` format.

The PD200W RX dongle (and the wired USB-C mic, PID 0411) exposes a vendor HID
interface (VID 0x352f, VID 0x31b2 on older units) carrying a small framed
protocol (see docs/protocol.md):

    C4 | len u16 LE | 00 | cmd | payload... | cks u16 LE
    cks = (0x10000 - sum(frame[0 .. len-3])) & 0xFFFF

Battery data arrives in key/value pair frames (cmd 0x03/0x04):

  * key 0x42 - battery percentage:  low byte = TX1, high byte = TX2
  * key 0x49 - charge state:        low byte = TX1, high byte = TX2

The device answers cmd-0x04 single-key read requests for both keys (verified
on hardware); it also pushes other keys by itself (0x44, a ~10 Hz input-level
stream).  This tool sends read probes and/or listens passively.

Lighting control follows the Windows app's UI write path: cmd-0x03 write pairs
(``C4 0B 00 00 03 key value cks``) to per-mic registers (0x20xx = mic 1,
0x28xx = mic 2).  See docs/protocol.md §9 for the register map:

  * LED on/off     - offset 0x89, 1 = on, 0 = off
  * brightness     - offset 0x8a, 1..100
  * effect mode    - offset 0x8b, 0 = fixed, 2 = breathe, 1 = loop
  * color index    - offset 0x8c, presets 0..7, custom colors 8..12
  * custom colors  - offsets 0x8f..0x9d: 5 slots x (H, S, V)

Scene control follows the same cmd-0x03 path.  See docs/protocol.md §10:

  * EQ mode        - offset 0x22: scene<<8 | preset; bit 15 = custom-curve flag
  * EQ bands       - offsets 0x23..0x45: 7 slots x 5 registers, one frame per
                     slot (enable, type, frequency, gain, Q)
  * reverb mix     - offset 0x82/0x83: enabled/level for the "Sing" presets

Linux only; stdlib only; talks to /dev/hidraw* directly.

Exit codes: 0 = ok, 1 = error (no device, open/write failure),
            2 = no battery/lighting/EQ data received, 130 = interrupted.
"""

from __future__ import annotations

import argparse
import colorsys
import errno
import glob
import json
import os
import re
import select
import struct
import sys
import time

VERSION = "0.4.0"

# --- protocol constants (docs/protocol.md) ---------------------------------

MAGIC = 0xC4
CMD_WRITE = 0x03        # host -> device: write key/value pair(s)
CMD_ACK = CMD_WRITE     # ... and the opcode the device uses for ACK/reply pairs
CMD_READ = 0x04         # read request (host) / pair response (device)
CMD_READ_BLOCK = 0x06   # block read: fetch `value` u16 values starting at key
CMD_PAIR_TYPES = (0x03, 0x04)  # incoming key/value list frames

KEY_BATTERY = 0x42
KEY_CHARGE = 0x49

# --- lighting registers (docs/protocol.md §9) --------------------------------

LIGHT_CHANNEL_BASES = {1: 0x2000, 2: 0x2800}  # per-mic key spaces (TX1/TX2)
LIGHT_LED_OFF = 0x89           # 1 = LED ring on, 0 = off
LIGHT_BRIGHTNESS_OFF = 0x8A    # 1..100
LIGHT_MODE_OFF = 0x8B          # 0 = fixed, 2 = breathe, 1 = loop
LIGHT_COLOR_OFF = 0x8C         # presets 0..7; custom colors 8..12 (slot 1..5)
LIGHT_CUSTOM_COUNT_OFF = 0x8E  # number of stored custom colors
LIGHT_CUSTOM_OFF = 0x8F        # first custom slot: 3 keys per slot (H, S, V)
LIGHT_CUSTOM_SLOTS = 5

LIGHT_PRESETS = ("white", "red", "orange", "yellow", "green", "cyan", "blue", "magenta")
LIGHT_MODES = {"fixed": 0, "breathe": 2, "loop": 1}
LIGHT_MODE_NAMES = {value: name for name, value in LIGHT_MODES.items()}
LIGHT_STATUS_OFFSETS = (
    LIGHT_LED_OFF,
    LIGHT_BRIGHTNESS_OFF,
    LIGHT_MODE_OFF,
    LIGHT_COLOR_OFF,
    LIGHT_CUSTOM_COUNT_OFF,
)
LIGHT_STATUS_FIELDS = {
    LIGHT_LED_OFF: "led",
    LIGHT_BRIGHTNESS_OFF: "brightness",
    LIGHT_MODE_OFF: "mode",
    LIGHT_COLOR_OFF: "color",
    LIGHT_CUSTOM_COUNT_OFF: "custom_count",
}
LIGHT_WRITE_SPACING = 0.05  # seconds between write frames (the app paces too)

# --- device matching --------------------------------------------------------

USB_VIDS = (0x352F, 0x31B2)
USB_PIDS_RX = (0x040E, 0x040F, 0x0410)  # PD200W RX dongle
USB_PIDS_MIC = (0x0411,)                # PD200W USB-C microphone (same protocol)
REPORT_LEN = 64                         # vendor HID report payload size

# how long a one-shot run keeps reading after the first battery data arrives,
# waiting for the remaining fields (e.g. the charge-state response)
_SETTLE = 0.5


class DeviceError(Exception):
    """Fatal problem while finding/opening/using the device."""


class DeviceLost(Exception):
    """The hidraw node went away (unplugged); caller may re-detect."""


class ConfigError(Exception):
    """Bad sound profile (.cfg): unreadable, malformed or wrong device."""


# --- frame helpers ----------------------------------------------------------


def build_frame(cmd: int, payload: bytes = b"") -> bytes:
    """Build a single C4 frame (no HID report ID, no zero padding)."""
    length = 7 + len(payload)
    frame = bytearray((MAGIC, length & 0xFF, length >> 8, 0x00, cmd))
    frame.extend(payload)
    checksum = (-sum(frame)) & 0xFFFF
    frame.extend((checksum & 0xFF, checksum >> 8))
    return bytes(frame)


def single_read(key: int) -> bytes:
    """cmd 0x04 read frame for a single key (9 bytes)."""
    return build_frame(CMD_READ, struct.pack("<H", key))


def write_value(key: int, value: int) -> bytes:
    """cmd 0x03 write frame for one key/value pair (11 bytes)."""
    return build_frame(CMD_WRITE, struct.pack("<HH", key, value))


def write_pairs(pairs) -> bytes:
    """cmd 0x03 frame carrying several key/value pairs (one EQ band at a time).

    The app's multi-pair builder is ``FUN_180064b00``: same header as
    ``write_value`` but the payload is ``key u16, value u16`` repeated, and the
    length field is ``7 + 4 * count``.  A single pair produces byte-identical
    frames to :func:`write_value`.
    """
    payload = b"".join(struct.pack("<HH", key & 0xFFFF, value & 0xFFFF) for key, value in pairs)
    return build_frame(CMD_WRITE, payload)


def block_read(key: int, count: int) -> bytes:
    """cmd 0x06 block read: fetch `count` u16 values starting at `key` (11 bytes)."""
    return build_frame(CMD_READ_BLOCK, struct.pack("<HH", key, count))


def parse_frame(data: bytes):
    """Return (cmd, payload) for a valid frame, else None."""
    if len(data) < 9 or data[0] != MAGIC:
        return None
    length = data[1] | (data[2] << 8)
    if length < 9 or length > len(data):
        return None
    if data[3] != 0x00:
        return None
    expected = (-sum(data[: length - 2])) & 0xFFFF
    stored = data[length - 2] | (data[length - 1] << 8)
    if expected != stored:
        return None
    return data[4], bytes(data[5 : length - 2])


def parse_pairs(payload: bytes) -> dict:
    """Decode key/value u16 LE pairs (cmd 0x03/0x04 payloads)."""
    pairs = {}
    for offset in range(0, len(payload) - 3, 4):
        key = payload[offset] | (payload[offset + 1] << 8)
        value = payload[offset + 2] | (payload[offset + 3] << 8)
        pairs[key] = value
    return pairs


def strip_report_id(data: bytes) -> bytes:
    """Drop a leading HID report-ID byte if the frame starts one byte late."""
    if data and data[0] != MAGIC and len(data) >= 2 and data[1] == MAGIC:
        return data[1:]
    return data


# --- lighting helpers ---------------------------------------------------------


def light_key(channel: int, offset: int) -> int:
    """Wire key of one lighting register for mic 1/2 (0x20xx / 0x28xx spaces)."""
    return LIGHT_CHANNEL_BASES[channel] + offset


def parse_color(text: str):
    """Parse a preset name/index or an #RGB/#RRGGBB color.

    Returns ``("preset", index)`` or ``("custom", (r, g, b))``, or None when
    the text is not a color.
    """
    value = text.strip().lower()
    if value in LIGHT_PRESETS:
        return ("preset", LIGHT_PRESETS.index(value))
    digits = value[1:] if value.startswith("#") else value
    if re.fullmatch(r"[0-9a-f]{6}", digits):
        return ("custom", tuple(int(digits[i : i + 2], 16) for i in (0, 2, 4)))
    if value.startswith("#") and re.fullmatch(r"[0-9a-f]{3}", digits):
        return ("custom", tuple(int(digit * 2, 16) for digit in digits))
    if digits.isdigit() and 0 <= int(digits) < len(LIGHT_PRESETS):
        return ("preset", int(digits))
    return None


def rgb_to_light_hsv(red: int, green: int, blue: int):
    """RGB 0-255 -> the wire (H, S, V) values the Windows app sends.

    The app passes ``QColor::hue()`` (degrees, int) through its x100 double
    encoder for the H register, and ``saturationF()``/``valueF()`` (0..1)
    through the same encoder for S/V (i.e. percent).  So: H = degrees x100
    (0..35900), S/V = 0..100.
    """
    hue, sat, val = colorsys.rgb_to_hsv(red / 255.0, green / 255.0, blue / 255.0)
    degrees = int(round(hue * 360)) % 360
    return (degrees * 100, int(round(sat * 100)), int(round(val * 100)))


def light_value_names(offset: int, value: int) -> str:
    """Human-readable rendering of one lighting register value."""
    if offset == LIGHT_LED_OFF:
        return "on" if value else "off"
    if offset == LIGHT_MODE_OFF:
        return LIGHT_MODE_NAMES.get(value, f"?({value})")
    if offset == LIGHT_COLOR_OFF:
        if 0 <= value < len(LIGHT_PRESETS):
            return f"{LIGHT_PRESETS[value]}({value})"
        slot = value - 7
        if 1 <= slot <= LIGHT_CUSTOM_SLOTS:
            return f"custom{slot}({value})"
        return f"?({value})"
    return str(value)


def plan_lighting(args) -> list:
    """Translate parsed ``--light*`` options into ordered (key, value, label) writes."""
    channels = (1, 2) if args.channel == "both" else (int(args.channel),)
    writes = []

    def add(offset, value, label):
        for channel in channels:
            writes.append((light_key(channel, offset), value, label))

    def add_slot(slot, values):
        base = LIGHT_CUSTOM_OFF + 3 * (slot - 1)
        for index, value in enumerate(values):
            add(base + index, value, f"custom{slot}.{('h', 's', 'v')[index]}={value}")

    if args.light is not None:
        add(LIGHT_LED_OFF, 1 if args.light == "on" else 0, f"led={args.light}")
    if args.light_brightness is not None:
        add(LIGHT_BRIGHTNESS_OFF, args.light_brightness, f"brightness={args.light_brightness}")
    if args.light_mode is not None:
        value = LIGHT_MODES[args.light_mode]
        add(LIGHT_MODE_OFF, value, f"mode={args.light_mode}({value})")
    if args.light_color is not None:
        kind, payload = args.light_color
        if kind == "preset":
            add(LIGHT_COLOR_OFF, payload, f"color={LIGHT_PRESETS[payload]}({payload})")
        else:
            add_slot(args.light_slot, rgb_to_light_hsv(*payload))
            add(
                LIGHT_COLOR_OFF,
                7 + args.light_slot,
                f"color=custom{args.light_slot}({7 + args.light_slot})",
            )
    if args.light_hsv is not None:
        add_slot(args.light_slot, args.light_hsv)
    if args.light_count is not None:
        add(LIGHT_CUSTOM_COUNT_OFF, args.light_count, f"custom-count={args.light_count}")
    return writes


# --- scene / PEQ registers (docs/protocol.md §10) -----------------------------

EQ_CHANNEL_BASES = {1: 0x2000, 2: 0x2800}   # same key spaces as lighting

EQ_MODE_OFF = 0x22        # scene id << 8 | preset index; bit 15 = "SevenEQ" flag
EQ_BAND_OFF = 0x23        # first of 7 filter slots, 5 registers each
EQ_MIXTURE_OFF = 0x82     # blnMixture: reverb mix on/off (Sing presets = 1)
EQ_LEVEL_OFF = 0x83       # level: reverb depth (Pop = 5, Folk = 1, others 0)
EQ_MODE_FLAG = 0x8000     # bit 15: custom (user-edited) curve marker

EQ_SLOT_COUNT = 7         # slots 0..4 peaking bands, 5 = HPF, 6 = LPF
EQ_SLOT_HPF = 5
EQ_SLOT_LPF = 6
EQ_REGS_PER_SLOT = 5

EQ_ENABLE_REG = 0         # +0 = 1 for every slot the app writes (enabled)
EQ_TYPE_REG = 1           # +1 = filter type (device encoding, see EQ_DEVICE_TYPE)
EQ_FREQ_REG = 2           # +2 = frequency in Hz (u16, truncated)
EQ_GAIN_REG = 3           # +3 = gain x10 + 2000 (2000 = 0 dB)
EQ_Q_REG = 4              # +4 = Q x100

# JSON/AudioEQS point type -> device filter type byte (FUN_180045c40 mapping)
EQ_DEVICE_TYPE = {0: 1, 1: 0, 2: 2, 3: 3, 4: 5}
EQ_TYPE_NAMES = {0: "peak", 1: "low-shelf", 2: "high-shelf", 3: "lpf", 4: "hpf"}
EQ_DEVICE_NAMES = {0: "low-shelf", 1: "peak", 2: "high-shelf", 3: "lpf", 5: "hpf"}
EQ_BAND_TYPES = {"peak": 0, "low-shelf": 1, "lowshelf": 1, "high-shelf": 2, "highshelf": 2}

EQ_GAIN_MIN, EQ_GAIN_MAX = -12.0, 12.0   # below -12 dB the app writes 0 dB
EQ_Q_MIN, EQ_Q_MAX = 0.05, 20.0
EQ_FREQ_MIN, EQ_FREQ_MAX = 1, 20000
EQ_WRITE_SPACING = 0.05                   # seconds between write frames
EQ_BLOCK_CHUNK = 12                       # values per cmd-6 band read (fits one 64-byte type-6 answer)

SCENES = {"original": 0, "podcast": 1, "game": 2, "sing": 3}
SCENE_NAMES = {value: name for name, value in SCENES.items()}
SCENE_PRESETS = {
    "original": ("original",),
    "podcast": ("podcast1", "podcast2"),
    "game": ("game1", "game2"),
    "sing": ("pop", "folk"),
}

CFG_DEVICE_NAME = "PD200XW"               # device_name written into .cfg profiles
CFG_CURVE_FIELDS = (
    "HPF",
    "LPF",
    "blnBypass",
    "blnDefault",
    "blnVisible",
    "color",
    "curve_name",
    "map_points",
    "sample_rate",
    "width",
)


def _point(freq, gain, q, ftype, bypass=False):
    """One EQ point in the app's JSON shape (map_points / HPF / LPF entries)."""
    return {"frequence": freq, "Gain": gain, "Q": q, "type": ftype, "blnBypass": bypass}


def _curve(name, hpf, lpf, points, color="246|180|54", mixture=0, level=0):
    return {
        "curve_name": name,
        "HPF": hpf,
        "LPF": lpf,
        "map_points": points,
        "blnBypass": False,
        "blnDefault": True,
        "blnVisible": True,
        "color": color,
        "sample_rate": 48000,
        "width": 2,
        "mixture": mixture,
        "level": level,
    }


# The seven built-in curves, copied from the JSON templates embedded in
# PD200XW.dll (FUN_180046a80); ``mixture``/``level`` are the wrapper fields the
# app writes to registers 0x82/0x83 when the curve is selected (Sing presets
# turn the reverb mix on: Pop level 5, Folk level 1).
EQ_PRESETS = {
    "original": _curve(
        "Original",
        _point(20, -1, 1, 4),
        _point(20000, -1, 1, 3),
        [
            _point(125, 0, 1, 0),
            _point(250, 0, 1, 0),
            _point(500, 0, 1, 0),
            _point(1000, 0, 1, 0),
            _point(2000, 0, 1, 0),
        ],
    ),
    "podcast1": _curve(
        "Podcast1",
        _point(20, -1, 1, 4, bypass=True),
        _point(20000, -1, 1, 3, bypass=True),
        [
            _point(100, 2.5, 0.7, 0),
            _point(300, -4.045714285714286, 2, 0),
            _point(1100, 0, 0.7, 0),
            _point(4880, -3, 5, 0),
            _point(10000, 0, 0.7, 2),
        ],
    ),
    "podcast2": _curve(
        "Podcast2",
        _point(20, -1, 1, 4, bypass=True),
        _point(20000, -1, 1, 3, bypass=True),
        [
            _point(110, 3.5, 0.7, 0),
            _point(210, -2.5, 1.5, 0),
            _point(546, -3, 1.5, 0),
            _point(5170, -3, 5, 0),
            _point(8000, -3, 0.7, 2),
        ],
        color="255|93|239",
    ),
    "game1": _curve(
        "Game1",
        _point(20, -1, 1, 4, bypass=True),
        _point(20000, -1, 1, 3, bypass=True),
        [
            _point(60, -4.5, 0.5, 1),
            _point(117, -3, 1.5, 0),
            _point(900, 3, 0.5, 0),
            _point(5370, 0, 1, 0),
            _point(10000, -7.062857142857143, 0.7, 2),
        ],
    ),
    "game2": _curve(
        "Game2",
        _point(20, -1, 1, 4, bypass=True),
        _point(20000, -1, 1, 3, bypass=True),
        [
            _point(70, -12, 0.7, 1),
            _point(500, 0, 1, 0),
            _point(1200, 2, 0.7, 0),
            _point(5009, 0, 3, 0),
            _point(9880, -5, 5, 0),
        ],
    ),
    "pop": _curve(
        "Pop",
        _point(63.26942754238026, -1, 1, 4),
        _point(20000, -1, 1, 3, bypass=True),
        [
            _point(199, -3.0857142857142854, 1, 0),
            _point(500, 0, 1, 0),
            _point(1000, 0, 1, 0),
            _point(7010, -3, 8, 0),
            _point(11000, 1.5, 0.7, 2),
        ],
        mixture=1,
        level=5,
    ),
    "folk": _curve(
        "Folk",
        _point(40.518494556810865, -1, 1, 4),
        _point(20000, -1, 1, 3, bypass=True),
        [
            _point(171, -2, 1, 0),
            _point(3150, -2, 5, 0),
            _point(500, 3, 0.5, 0),
            _point(5700, -4.32, 5, 0),
            _point(8810, -3, 0.5, 2),
        ],
        color="211|243|251",
        mixture=1,
        level=1,
    ),
}


def eq_key(channel: int, offset: int) -> int:
    """Wire key of one EQ register for mic 1/2 (0x20xx / 0x28xx spaces)."""
    return EQ_CHANNEL_BASES[channel] + offset


def slot_name(slot: int) -> str:
    if slot == EQ_SLOT_HPF:
        return "hpf"
    if slot == EQ_SLOT_LPF:
        return "lpf"
    return f"band{slot + 1}"


def encode_eq_gain(gain: float) -> int:
    """Gain register value (app ``FUN_18006d840``): trunc(gain x10) + 2000.

    The app writes the 0 dB marker 2000 for gains below -12 dB, so the value is
    clamped here the same way (app parity).
    """
    if gain < EQ_GAIN_MIN:
        return 2000
    return int(gain * 10 + 2000)


def encode_eq_q(q: float) -> int:
    """Q register value (app ``FUN_18006d860``): trunc(Q x100)."""
    return int(q * 100)


def eq_slot_values(freq, gain, q, ftype) -> list:
    """The five register values the app writes for one EQ slot (FUN_180045c40)."""
    device_type = EQ_DEVICE_TYPE[ftype]
    gain_value = 2000 if device_type in (3, 5) else encode_eq_gain(gain)
    return [
        1,
        device_type,
        int(freq) & 0xFFFF,
        gain_value & 0xFFFF,
        encode_eq_q(q) & 0xFFFF,
    ]


def curve_slots(curve) -> list:
    """``(slot, freq, gain, q, json_type)`` for all seven slots of a curve."""
    slots = []
    for index, point in enumerate(curve["map_points"][:5]):
        slots.append((index, point["frequence"], point["Gain"], point["Q"], point["type"]))
    for slot, key in ((EQ_SLOT_HPF, "HPF"), (EQ_SLOT_LPF, "LPF")):
        point = curve[key]
        slots.append((slot, point["frequence"], point["Gain"], point["Q"], point["type"]))
    return slots


def _slot_frame(channel: int, slot: int, freq, gain, q, ftype, label: str) -> list:
    """One write frame: the five registers of a single EQ slot."""
    base = eq_key(channel, EQ_BAND_OFF + slot * EQ_REGS_PER_SLOT)
    values = eq_slot_values(freq, gain, q, ftype)
    type_name = EQ_TYPE_NAMES.get(ftype, f"type{ftype}")
    return [
        (base + EQ_ENABLE_REG, values[0], f"{label} enable"),
        (base + EQ_TYPE_REG, values[1], f"{label} type={type_name}"),
        (base + EQ_FREQ_REG, values[2], f"{label} freq={freq}"),
        (base + EQ_GAIN_REG, values[3], f"{label} gain={gain}dB"),
        (base + EQ_Q_REG, values[4], f"{label} Q={q}"),
    ]


def curve_frames(channels, curve, label: str) -> list:
    """Write frames for a whole curve: seven slots, one frame per slot."""
    frames = []
    for channel in channels:
        for slot, freq, gain, q, ftype in curve_slots(curve):
            frames.append(
                _slot_frame(channel, slot, freq, gain, q, ftype, f"{label} {slot_name(slot)}")
            )
    return frames


def scene_frames(channels, scene: str, index: int, flag: int = 0) -> list:
    """Write frames for ``--scene``: the preset curve, reverb mix and mode word."""
    preset_key = SCENE_PRESETS[scene][index]
    preset = EQ_PRESETS[preset_key]
    mode = (SCENES[scene] << 8) | (index & 0xFF) | (EQ_MODE_FLAG if flag else 0)
    mode_label = f"scene={scene}:{index}" + (" custom" if flag else "")
    frames = []
    for channel in channels:
        frames += curve_frames((channel,), preset, preset_key)
        frames.append(
            [(eq_key(channel, EQ_MIXTURE_OFF), preset["mixture"], f"{preset_key} mixture={preset['mixture']}")]
        )
        frames.append(
            [(eq_key(channel, EQ_LEVEL_OFF), preset["level"], f"{preset_key} level={preset['level']}")]
        )
        frames.append([(eq_key(channel, EQ_MODE_OFF), mode, mode_label)])
    return frames


def band_edit_frames(channels, bands, hpf, lpf) -> list:
    """Write frames for individual ``--eq-band`` / ``--eq-hpf`` / ``--eq-lpf`` edits."""
    frames = []
    for channel in channels:
        for n, freq, gain, q, ftype in bands:
            frames.append(_slot_frame(channel, n - 1, freq, gain, q, ftype, f"band{n}"))
        if hpf is not None:
            freq, q = hpf
            frames.append(_slot_frame(channel, EQ_SLOT_HPF, freq, -1, q, 4, "hpf"))
        if lpf is not None:
            freq, q = lpf
            frames.append(_slot_frame(channel, EQ_SLOT_LPF, freq, -1, q, 3, "lpf"))
    return frames


def raw_reg_frames(registers) -> list:
    """One single-pair frame per ``--eq-reg`` entry (raw wire key, no remapping)."""
    return [[(key, value, f"raw 0x{key:04x}")] for key, value in registers]


def plan_eq_frames(args) -> list:
    """All EQ write frames in send order (scene -> preset -> import -> edits)."""
    channels = (1, 2) if args.channel == "both" else (int(args.channel),)
    frames = []
    if args.scene is not None:
        scene, index = args.scene
        frames += scene_frames(channels, scene, index, args.eq_flag or 0)
    if args.eq_preset is not None:
        preset = EQ_PRESETS[args.eq_preset]
        for channel in channels:
            frames += curve_frames((channel,), preset, args.eq_preset)
            frames.append(
                [(eq_key(channel, EQ_MIXTURE_OFF), preset["mixture"], f"{args.eq_preset} mixture={preset['mixture']}")]
            )
            frames.append(
                [(eq_key(channel, EQ_LEVEL_OFF), preset["level"], f"{args.eq_preset} level={preset['level']}")]
            )
    if args.eq_import is not None:
        item = load_cfg(args.eq_import, getattr(args, "force", False))
        for channel in channels:
            frames += curve_frames((channel,), item["curve"], item["name"])
            frames.append(
                [(eq_key(channel, EQ_MIXTURE_OFF), item["mixture"], f"mixture={item['mixture']}")]
            )
            frames.append([(eq_key(channel, EQ_LEVEL_OFF), item["level"], f"level={item['level']}")])
    frames += band_edit_frames(channels, args.eq_band or [], args.eq_hpf, args.eq_lpf)
    frames += raw_reg_frames(args.eq_reg or [])
    return frames


def eq_requested(args) -> bool:
    """True when any --scene/--eq* option that writes to the device was given."""
    return any(
        (
            args.scene is not None,
            args.eq_preset is not None,
            args.eq_import is not None,
            bool(args.eq_band),
            args.eq_hpf is not None,
            args.eq_lpf is not None,
            bool(args.eq_reg),
        )
    )


def eq_device_needed(args) -> bool:
    """True when the command must open the mic (writes or status reads).

    ``--eq-export`` turns the scene/preset/band options into profile source data,
    so nothing is written and the device is only opened for ``--eq-status``.
    ``--eq-import``/``--eq-reg`` always write and may not be combined with it.
    """
    if args.eq_status:
        return True
    if args.eq_export is not None:
        return False
    return eq_requested(args)


# --- .cfg sound profiles (Windows app export/import format) -------------------


def _json_text(obj) -> str:
    """Serialise one nested object the way the app does (sorted keys, indent 4)."""
    return json.dumps(obj, indent=4, sort_keys=True)


def _clone_curve(curve) -> dict:
    clone = dict(curve)
    clone["HPF"] = dict(curve["HPF"])
    clone["LPF"] = dict(curve["LPF"])
    clone["map_points"] = [dict(point) for point in curve["map_points"]]
    return clone


def curve_json_text(curve) -> str:
    """The ``curve_contains`` JSON text for one curve (inner points escaped)."""
    doc = {}
    for field in CFG_CURVE_FIELDS:
        value = curve[field]
        if field in ("HPF", "LPF"):
            doc[field] = _json_text(value)
        elif field == "map_points":
            doc[field] = [_json_text(point) for point in value]
        else:
            doc[field] = value
    return _json_text(doc)


def cfg_text(name: str, curve, mixture: int, level: int, default: bool = True) -> str:
    """A complete ``.cfg`` profile wrapping one curve (app DeviceInfo fields)."""
    doc = {
        "device_name": CFG_DEVICE_NAME,
        "blnMixture": bool(mixture),
        "level": int(level),
        "InfoName": name,
        "curve_contains": curve_json_text(curve),
        "blnDefault": bool(default),
    }
    return _json_text(doc)


def _parse_point(text, where: str) -> dict:
    if not isinstance(text, str):
        raise ConfigError(f"{where}: expected a JSON point string")
    try:
        point = json.loads(text)
    except ValueError as exc:
        raise ConfigError(f"{where}: invalid point JSON ({exc})") from exc
    if not isinstance(point, dict):
        raise ConfigError(f"{where}: point JSON must be an object")
    for field in ("frequence", "Gain", "Q", "type"):
        if field not in point:
            raise ConfigError(f"{where}: missing field {field!r}")
    if not isinstance(point["type"], int) or point["type"] not in EQ_DEVICE_TYPE:
        raise ConfigError(f"{where}: unsupported filter type {point['type']!r}")
    for field in ("frequence", "Gain", "Q"):
        if not isinstance(point[field], (int, float)):
            raise ConfigError(f"{where}: {field} must be a number")
    return {
        "frequence": point["frequence"],
        "Gain": point["Gain"],
        "Q": point["Q"],
        "type": point["type"],
        "blnBypass": bool(point.get("blnBypass", False)),
    }


def _curve_from_doc(doc, where: str) -> dict:
    if not isinstance(doc, dict):
        raise ConfigError(f"{where}: curve JSON must be an object")
    for field in CFG_CURVE_FIELDS:
        if field not in doc:
            raise ConfigError(f"{where}: missing field {field!r}")
    curve = {
        "HPF": _parse_point(doc["HPF"], f"{where} HPF"),
        "LPF": _parse_point(doc["LPF"], f"{where} LPF"),
        "blnBypass": bool(doc["blnBypass"]),
        "blnDefault": bool(doc["blnDefault"]),
        "blnVisible": bool(doc["blnVisible"]),
        "color": str(doc["color"]),
        "curve_name": str(doc["curve_name"]),
        "sample_rate": doc["sample_rate"],
        "width": doc["width"],
    }
    if not isinstance(doc["map_points"], list) or not 1 <= len(doc["map_points"]) <= 5:
        raise ConfigError(f"{where}: map_points must hold 1..5 points")
    curve["map_points"] = [
        _parse_point(point, f"{where} map_points[{index}]")
        for index, point in enumerate(doc["map_points"])
    ]
    return curve


def parse_cfg_text(text: str) -> dict:
    """Parse a ``.cfg`` profile; returns device_name/name/curve/mixture/level/default."""
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise ConfigError(f"not valid JSON ({exc})") from exc
    if not isinstance(doc, dict):
        raise ConfigError("top-level JSON value must be an object")
    for field in ("device_name", "curve_contains"):
        if field not in doc:
            raise ConfigError(f"missing required field {field!r}")
    if not isinstance(doc["device_name"], str) or not isinstance(doc["curve_contains"], str):
        raise ConfigError("device_name and curve_contains must be strings")
    try:
        curve_doc = json.loads(doc["curve_contains"])
    except ValueError as exc:
        raise ConfigError(f"curve_contains is not valid JSON ({exc})") from exc
    curve = _curve_from_doc(curve_doc, doc.get("InfoName") or "Imported")
    return {
        "device_name": doc["device_name"],
        "name": doc.get("InfoName") or "Imported",
        "mixture": 1 if doc.get("blnMixture") else 0,
        "level": int(doc.get("level") or 0),
        "default": bool(doc.get("blnDefault", False)),
        "curve": curve,
    }


def load_cfg(path: str, force: bool = False) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    item = parse_cfg_text(text)
    if not force and item["device_name"] not in (CFG_DEVICE_NAME, "PD200W"):
        raise ConfigError(
            f"{path} was exported for device {item['device_name']!r}, not {CFG_DEVICE_NAME}; "
            "check that the profile matches this microphone (or pass --force)"
        )
    return item


def curve_from_args(args):
    """Curve + metadata for --eq-export (preset, scene preset or edited custom)."""
    if args.eq_preset is not None:
        preset = _clone_curve(EQ_PRESETS[args.eq_preset])
        return preset, preset["curve_name"], preset["mixture"], preset["level"], True
    if args.scene is not None:
        scene, index = args.scene
        preset = _clone_curve(EQ_PRESETS[SCENE_PRESETS[scene][index]])
        return preset, preset["curve_name"], preset["mixture"], preset["level"], True
    curve = _clone_curve(EQ_PRESETS["original"])
    name = args.eq_name or "Custom"
    curve["curve_name"] = name
    for n, freq, gain, q, ftype in args.eq_band or []:
        curve["map_points"][n - 1] = _point(freq, gain, q, ftype)
    if args.eq_hpf is not None:
        curve["HPF"] = _point(args.eq_hpf[0], -1, args.eq_hpf[1], 4)
    if args.eq_lpf is not None:
        curve["LPF"] = _point(args.eq_lpf[0], -1, args.eq_lpf[1], 3)
    mixture = args.eq_mixture if args.eq_mixture is not None else 0
    level = args.eq_level if args.eq_level is not None else 0
    return curve, name, mixture, level, False


# --- device discovery --------------------------------------------------------


def _uevent_fields(dirpath: str) -> dict:
    fields = {}
    try:
        with open(os.path.join(dirpath, "uevent"), "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return fields
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key.strip()] = value.strip()
    return fields


# The USB interface directory looks like "1-3:1.3" (bus-port:config.interface).
# Deliberately not "0003:352F:0411.0051", the per-instance HID device directory
# whose trailing ".0051" otherwise masquerades as an interface number.
_USB_INTERFACE_RE = re.compile(r"^\d+-[\d.]+:\d+\.\d+$")


def interface_from_path(path: str):
    """USB interface number extracted from a sysfs device path, or None."""
    for component in path.split(os.sep):
        if _USB_INTERFACE_RE.match(component):
            return int(component.rsplit(".", 1)[1])
    return None


def find_devices() -> list:
    """All hidraw nodes whose VID/PID matches the Maono PD200W family."""
    devices = []
    for syspath in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        uevent = _uevent_fields(os.path.join(syspath, "device"))
        parts = uevent.get("HID_ID", "").split(":")
        if len(parts) != 3:
            continue
        try:
            bus, vid, pid = (int(part, 16) for part in parts)
        except ValueError:
            continue
        if bus != 3 or vid not in USB_VIDS or pid not in USB_PIDS_RX + USB_PIDS_MIC:
            continue
        devices.append(
            {
                "dev": os.path.join("/dev", os.path.basename(syspath)),
                "vid": vid,
                "pid": pid,
                "interface": interface_from_path(os.path.realpath(syspath)),
                "name": uevent.get("HID_NAME", ""),
            }
        )
    return devices


def sort_candidates(devices: list) -> list:
    """Prefer the RX dongle and its vendor interface (mi_03)."""

    def rank(device):
        return (
            0 if device["pid"] in USB_PIDS_RX else 1,
            0 if device["interface"] == 3 else 1,
            device["dev"],
        )

    return sorted(devices, key=rank)


def describe(device: dict) -> str:
    if device.get("vid") is None:
        return device["dev"]
    name = device.get("name") or "HID device"
    interface = device.get("interface")
    extra = f", interface {interface}" if interface is not None else ""
    return f"{device['dev']} ({name}, {device['vid']:04x}:{device['pid']:04x}{extra})"


# --- state and rendering -----------------------------------------------------


class State:
    """Latest known battery percentage / charge state of the two mics."""

    def __init__(self):
        self.tx1_batt = None
        self.tx2_batt = None
        self.tx1_chg = None
        self.tx2_chg = None

    def snapshot(self):
        return (self.tx1_batt, self.tx2_batt, self.tx1_chg, self.tx2_chg)

    def has_data(self) -> bool:
        return any(value is not None for value in self.snapshot())

    def update_from_pairs(self, pairs: dict) -> None:
        if KEY_BATTERY in pairs:
            value = pairs[KEY_BATTERY] & 0xFFFF
            self.tx1_batt = value & 0xFF
            self.tx2_batt = value >> 8
        if KEY_CHARGE in pairs:
            value = pairs[KEY_CHARGE] & 0xFFFF
            self.tx1_chg = value & 0xFF
            self.tx2_chg = value >> 8


def _charge_suffix(value):
    if value is None:
        return ""
    if value == 1:
        return " (charging)"
    if value == 0:
        return " (not charging)"
    return f" (chg={value})"


def _device_field(label, battery, charge):
    text = f"{label}   ?%" if battery is None else f"{label} {battery:3d}%"
    return text + _charge_suffix(charge)


def print_status(state: State, as_json: bool) -> None:
    if as_json:
        print(
            json.dumps(
                {
                    "timestamp": time.time(),
                    "tx1": {"battery": state.tx1_batt, "charge": state.tx1_chg},
                    "tx2": {"battery": state.tx2_batt, "charge": state.tx2_chg},
                }
            ),
            flush=True,
        )
        return
    stamp = time.strftime("%H:%M:%S")
    left = _device_field("TX1", state.tx1_batt, state.tx1_chg)
    right = _device_field("TX2", state.tx2_batt, state.tx2_chg)
    print(f"{stamp}  {left}  |  {right}", flush=True)


def print_writes(writes: list, as_json: bool, prefix: str = "") -> None:
    """Print register writes as text lines or JSON (flat (key, value, label) list)."""
    for key, value, label in writes:
        if as_json:
            print(
                json.dumps(
                    {
                        "timestamp": time.time(),
                        "key": f"0x{key:04x}",
                        "value": value,
                        "label": label,
                        "dry_run": bool(prefix),
                    }
                ),
                flush=True,
            )
        else:
            print(f"{prefix}0x{key:04x} <= {value}   {label}", flush=True)


def light_status_record(values: dict) -> dict:
    """Decode one channel's lighting registers into a JSON-friendly dict."""
    record = {}
    for offset, name in LIGHT_STATUS_FIELDS.items():
        raw = values.get(offset)
        record[name] = raw
        if raw is not None and offset in (LIGHT_LED_OFF, LIGHT_MODE_OFF, LIGHT_COLOR_OFF):
            record[name + "_name"] = light_value_names(offset, raw)
    return record


def print_light_status(status: dict, as_json: bool) -> None:
    if as_json:
        payload = {"timestamp": time.time()}
        for channel, values in status.items():
            payload[f"tx{channel}"] = light_status_record(values)
        print(json.dumps(payload), flush=True)
        return
    for channel, values in status.items():
        parts = []
        for offset, name in LIGHT_STATUS_FIELDS.items():
            raw = values.get(offset)
            parts.append(f"{name}=" + ("?" if raw is None else light_value_names(offset, raw)))
        print(f"TX{channel}  " + "  ".join(parts), flush=True)


# --- HID I/O -----------------------------------------------------------------


def send_frame(fd: int, frame: bytes, report_id=None) -> None:
    buffer = frame.ljust(REPORT_LEN, b"\x00")
    if report_id is not None:
        buffer = bytes((report_id & 0xFF,)) + buffer
    try:
        os.write(fd, buffer)
    except OSError as exc:
        if exc.errno == errno.EINVAL:
            raise DeviceError(
                "hidraw rejected the report size (EINVAL); try --report-id 0 or --report-id 1"
            ) from exc
        if exc.errno in (errno.EIO, errno.ENODEV, errno.ENXIO, errno.EPIPE):
            raise DeviceLost("device disappeared during write") from exc
        raise


def _send_probe(fd: int, args) -> None:
    for key in (KEY_BATTERY, KEY_CHARGE):
        if args.verbose:
            print(f"[probe] single read of key {key:#04x}", file=sys.stderr)
        send_frame(fd, single_read(key), args.report_id)


def open_device(args):
    if args.device:
        device = {"dev": args.device, "vid": None, "pid": None, "interface": None, "name": ""}
    else:
        candidates = sort_candidates(find_devices())
        if args.verbose:
            for candidate in candidates:
                print("[info] candidate:", describe(candidate), file=sys.stderr)
        if not candidates:
            raise DeviceError(
                "no Maono hidraw device found (VID 352f/31b2, PID 040e/040f/0410/0411).\n"
                "  - is the dongle plugged in and are the microphones powered on?\n"
                "  - /dev/hidraw* is root-only by default; see README for a udev rule"
            )
        device = candidates[0]

    try:
        fd = os.open(device["dev"], os.O_RDWR | os.O_NONBLOCK)
        read_only = False
    except PermissionError:
        try:
            fd = os.open(device["dev"], os.O_RDONLY | os.O_NONBLOCK)
        except OSError as exc:
            raise DeviceError(f"cannot open {device['dev']}: {exc}") from exc
        read_only = True
        print("[warn] opened read-only: passive listening only", file=sys.stderr)
    except OSError as exc:
        raise DeviceError(f"cannot open {device['dev']}: {exc}") from exc
    return fd, device, read_only


# --- report handling ----------------------------------------------------------


def _handle_report(raw: bytes, state: State, args) -> bool:
    """Parse one HID report; return True if battery/charge data was seen."""
    if args.raw:
        print("[raw]", raw.hex(" "), file=sys.stderr)
    data = strip_report_id(raw)
    parsed = parse_frame(data)
    if parsed is None:
        if args.verbose and data[:1] == bytes((MAGIC,)):
            print("[warn] bad frame:", data[:24].hex(" "), file=sys.stderr)
        return False
    cmd, payload = parsed
    if cmd in CMD_PAIR_TYPES:
        pairs = parse_pairs(payload)
        if args.verbose:
            rendered = ", ".join(f"{key:#06x}={value:#06x}" for key, value in pairs.items())
            print(f"[frame] type {cmd:#04x}: {rendered}", file=sys.stderr)
        state.update_from_pairs(pairs)
        return KEY_BATTERY in pairs or KEY_CHARGE in pairs
    if args.verbose:
        print(f"[frame] type {cmd:#04x} payload={payload.hex(' ')}", file=sys.stderr)
    return False


def _recv_frame(fd: int, args):
    """Read one report; return (cmd, payload) for a valid frame, else None."""
    try:
        data = os.read(fd, REPORT_LEN + 1)
    except BlockingIOError:
        return None
    except OSError as exc:
        if exc.errno in (errno.EIO, errno.ENODEV, errno.ENXIO, errno.EPIPE):
            raise DeviceLost("device disappeared during read") from exc
        raise
    if not data:
        return None
    if args.raw:
        print("[raw]", data.hex(" "), file=sys.stderr)
    return parse_frame(strip_report_id(data))


def read_light_status(fd: int, args, wait: float, read_only: bool) -> dict:
    """Probe the lighting registers; return {channel: {offset: value}}."""
    channels = (1, 2) if args.channel == "both" else (int(args.channel),)
    wanted = {}
    status = {}
    for channel in channels:
        wanted[channel] = {light_key(channel, offset): offset for offset in LIGHT_STATUS_OFFSETS}
        status[channel] = {}
        if read_only:
            continue
        for key in wanted[channel]:
            if args.verbose:
                print(f"[probe] single read of key {key:#06x}", file=sys.stderr)
            send_frame(fd, single_read(key), args.report_id)

    pending = {key for keys in wanted.values() for key in keys}
    deadline = time.monotonic() + wait
    while pending and time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if not ready:
            continue
        frame = _recv_frame(fd, args)
        if frame is None:
            continue
        cmd, payload = frame
        if cmd in CMD_PAIR_TYPES:
            for key, value in parse_pairs(payload).items():
                if key in pending:
                    for channel, keys in wanted.items():
                        if key in keys:
                            status[channel][keys[key]] = value
                    pending.discard(key)
        elif args.verbose:
            print(f"[frame] type {cmd:#04x} payload={payload.hex(' ')}", file=sys.stderr)
    return status


# --- scene / EQ runtime -------------------------------------------------------


def eq_selected_channels(args):
    return (1, 2) if args.channel == "both" else (int(args.channel),)


def flatten_frames(frames: list) -> list:
    return [pair for frame in frames for pair in frame]


def eq_status_record(values: dict) -> dict:
    """Decode one channel's EQ registers (offsets, not wire keys) for display."""
    record = {
        "mode": values.get(EQ_MODE_OFF),
        "mixture": values.get(EQ_MIXTURE_OFF),
        "level": values.get(EQ_LEVEL_OFF),
    }
    mode = record["mode"]
    if mode is not None:
        scene_id = (mode & 0x7FFF) >> 8  # the custom-curve flag lives in bit 15
        index = mode & 0xFF
        record["scene"] = scene_id
        record["scene_name"] = SCENE_NAMES.get(scene_id)
        record["preset_index"] = index
        record["custom"] = bool(mode & EQ_MODE_FLAG)
        record["preset"] = None
        if record["scene_name"] is not None and index < len(SCENE_PRESETS[record["scene_name"]]):
            record["preset"] = SCENE_PRESETS[record["scene_name"]][index]
    bands = []
    for slot in range(EQ_SLOT_COUNT):
        base = EQ_BAND_OFF + slot * EQ_REGS_PER_SLOT
        raw = [values.get(base + reg) for reg in range(EQ_REGS_PER_SLOT)]
        if all(value is None for value in raw):
            bands.append(None)
            continue
        entry = {
            "slot": slot,
            "name": slot_name(slot),
            "enable": raw[0],
            "type_value": raw[1],
            "type": EQ_DEVICE_NAMES.get(raw[1]),
            "freq": raw[2],
        }
        if raw[3] is not None:
            entry["gain_raw"] = raw[3]
            entry["gain"] = None if raw[1] in (3, 5) else (raw[3] - 2000) / 10
        if raw[4] is not None:
            entry["q"] = raw[4] / 100
        bands.append(entry)
    record["bands"] = bands
    return record


def print_eq_status(status: dict, as_json: bool) -> None:
    if as_json:
        payload = {"timestamp": time.time()}
        for channel, values in status.items():
            payload[f"tx{channel}"] = eq_status_record(values)
        print(json.dumps(payload), flush=True)
        return
    for channel, values in status.items():
        record = eq_status_record(values)
        if record["mode"] is None:
            head = "mode=?"
        else:
            scene = record.get("scene_name") or f"scene{record['scene']}"
            preset = record.get("preset") or "-"
            kind = "custom" if record.get("custom") else "preset"
            head = (
                f"mode=0x{record['mode']:04x}  scene={scene}({record['scene']})  "
                f"preset={preset}({record['preset_index']})  {kind}  "
                f"mixture={record['mixture']}  level={record['level']}"
            )
        print(f"TX{channel}  {head}", flush=True)
        for entry in record["bands"]:
            if entry is None:
                continue
            freq = "?" if entry["freq"] is None else entry["freq"]
            q = "?" if entry.get("q") is None else f"{entry['q']:.2f}"
            gain = "-" if entry.get("gain") is None else f"{entry['gain']:+.1f}dB"
            print(
                f"TX{channel}  {entry['name']:<5} freq={freq}  gain={gain}  Q={q}  type={entry['type']}",
                flush=True,
            )


def read_eq_status(fd: int, args, wait: float, read_only: bool) -> dict:
    """Probe the EQ mode/mix registers plus the band registers (chunked block reads)."""
    channels = eq_selected_channels(args)
    total_band_values = EQ_SLOT_COUNT * EQ_REGS_PER_SLOT
    wanted = {}
    status = {}
    for channel in channels:
        mapping = {
            eq_key(channel, offset): offset
            for offset in (EQ_MODE_OFF, EQ_MIXTURE_OFF, EQ_LEVEL_OFF)
        }
        for slot in range(EQ_SLOT_COUNT):
            for reg in range(EQ_REGS_PER_SLOT):
                offset = EQ_BAND_OFF + slot * EQ_REGS_PER_SLOT + reg
                mapping[eq_key(channel, offset)] = offset
        wanted[channel] = mapping
        status[channel] = {}
        if read_only:
            continue
        for offset in (EQ_MODE_OFF, EQ_MIXTURE_OFF, EQ_LEVEL_OFF):
            key = eq_key(channel, offset)
            if args.verbose:
                print(f"[probe] single read of key {key:#06x}", file=sys.stderr)
            send_frame(fd, single_read(key), args.report_id)
        for start in range(0, total_band_values, EQ_BLOCK_CHUNK):
            count = min(EQ_BLOCK_CHUNK, total_band_values - start)
            key = eq_key(channel, EQ_BAND_OFF + start)
            if args.verbose:
                print(f"[probe] block read of {count} values at {key:#06x}", file=sys.stderr)
            send_frame(fd, block_read(key, count), args.report_id)

    pending = {key for keys in wanted.values() for key in keys}

    def store(wire_key, value):
        if wire_key not in pending:
            return
        for channel, keys in wanted.items():
            if wire_key in keys:
                status[channel][keys[wire_key]] = value
        pending.discard(wire_key)

    deadline = time.monotonic() + wait
    while pending and time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if not ready:
            continue
        frame = _recv_frame(fd, args)
        if frame is None:
            continue
        cmd, payload = frame
        if cmd in CMD_PAIR_TYPES:
            for key, value in parse_pairs(payload).items():
                store(key, value)
        elif cmd == CMD_READ_BLOCK and len(payload) >= 4:
            key, count = struct.unpack("<HH", payload[:4])
            for index in range(count):
                value = payload[4 + 2 * index : 6 + 2 * index]
                if len(value) == 2:
                    store(key + index, struct.unpack("<H", value)[0])
        elif args.verbose:
            print(f"[frame] type {cmd:#04x} payload={payload.hex(' ')}", file=sys.stderr)
    return status


def export_cfg(args) -> str:
    """Write the profile selected by --eq-export (no device needed)."""
    curve, name, mixture, level, default = curve_from_args(args)
    try:
        with open(args.eq_export, "w", encoding="utf-8") as handle:
            handle.write(cfg_text(name, curve, mixture, level, default))
    except OSError as exc:
        raise ConfigError(f"cannot write {args.eq_export}: {exc}") from exc
    return f"exported {name!r} -> {args.eq_export}"


def run_eq_export(args) -> int:
    print(export_cfg(args), flush=True)
    return 0


def run_eq(args) -> int:
    """Apply --scene/--eq* writes and/or read back the scene/EQ state (one-shot)."""
    fd, device, read_only = open_device(args)
    try:
        print(f"[info] using {describe(device)}", file=sys.stderr)
        if args.eq_export:
            print(export_cfg(args), flush=True)
        if eq_requested(args) and args.eq_export is None:
            if read_only:
                raise DeviceError(
                    "scene/EQ control needs write access to the hidraw node "
                    "(try sudo or add a udev rule; see README)"
                )
            frames = plan_eq_frames(args)
            if args.dry_run:
                print_writes(flatten_frames(frames), args.json, prefix="dry-run ")
            else:
                for frame in frames:
                    if args.verbose:
                        for key, value, label in frame:
                            print(f"[write] 0x{key:04x} <= {value:#06x}   ({label})", file=sys.stderr)
                    send_frame(fd, write_pairs([(key, value) for key, value, _ in frame]), args.report_id)
                    time.sleep(EQ_WRITE_SPACING)
                print_writes(flatten_frames(frames), args.json)
        if args.eq_status:
            status = read_eq_status(fd, args, args.wait, read_only)
            if not any(values for values in status.values()):
                print(
                    "no EQ data received (needs write access for probes? try sudo; "
                    "or use --raw to inspect traffic)",
                    file=sys.stderr,
                )
                return 2
            print_eq_status(status, args.json)
        return 0
    finally:
        os.close(fd)


# --- main loop ----------------------------------------------------------------


def run_session(args, fd: int, device: dict, read_only: bool) -> int:
    print(f"[info] using {describe(device)}", file=sys.stderr)
    state = State()
    started = time.monotonic()
    watch = args.watch
    probing = (not args.no_probe) and (not read_only)
    deadline = None if watch else started + args.wait
    # one-shot probes immediately; --watch listens first (pushes win over probes)
    next_probe = started + (args.probe_after if watch else 0.0)
    last_battery_at = None
    first_data_at = None
    last_key = None

    while True:
        now = time.monotonic()
        if deadline is not None and now >= deadline:
            break
        timeout = 0.25 if deadline is None else max(0.0, min(0.25, deadline - now))
        ready, _, _ = select.select([fd], [], [], timeout)
        if ready:
            try:
                data = os.read(fd, REPORT_LEN + 1)
            except BlockingIOError:
                data = b""
            except OSError as exc:
                if exc.errno in (errno.EIO, errno.ENODEV, errno.ENXIO, errno.EPIPE):
                    raise DeviceLost(
                        f"{device['dev']} disappeared ({exc.strerror})"
                    ) from exc
                raise
            if data and _handle_report(data, state, args):
                last_battery_at = time.monotonic()

        now = time.monotonic()
        recent = last_battery_at is not None and (now - last_battery_at) < args.interval
        if probing and now >= next_probe and not recent:
            _send_probe(fd, args)
            next_probe = now + args.interval

        if state.has_data():
            if first_data_at is None:
                first_data_at = now
            if watch:
                key = state.snapshot()
                if key != last_key:
                    print_status(state, args.json)
                    last_key = key
            else:
                have_both = state.tx1_batt is not None and state.tx1_chg is not None
                if have_both or (now - first_data_at) >= _SETTLE:
                    break

    if watch:
        return 0
    if state.has_data():
        print_status(state, args.json)
        return 0
    print(
        "no battery data received (needs write access for probes? try sudo; "
        "or use --raw to inspect traffic)",
        file=sys.stderr,
    )
    return 2


def lighting_requested(args) -> bool:
    """True when any --light* option that writes to the device was given."""
    return any(
        value is not None
        for value in (
            args.light,
            args.light_brightness,
            args.light_mode,
            args.light_color,
            args.light_hsv,
            args.light_count,
        )
    )


def _validate_lighting(parser, args) -> None:
    """Validate and normalize lighting options in place (argparse error on misuse)."""
    if args.light_mode is not None:
        mode = args.light_mode.strip().lower()
        if mode not in LIGHT_MODES:
            parser.error("--light-mode must be one of: fixed, breathe, loop")
        args.light_mode = mode
    if args.light_brightness is not None and not 1 <= args.light_brightness <= 100:
        parser.error("--light-brightness must be between 1 and 100")
    if args.light_color is not None:
        color = parse_color(args.light_color)
        if color is None:
            parser.error("--light-color must be a preset name, an index 0-7, or #RRGGBB")
        args.light_color = color
    if not 1 <= args.light_slot <= LIGHT_CUSTOM_SLOTS:
        parser.error(f"--light-slot must be between 1 and {LIGHT_CUSTOM_SLOTS}")
    if args.light_hsv is not None:
        parts = args.light_hsv.replace(",", " ").split()
        if len(parts) != 3 or not all(part.isdigit() and 0 <= int(part) <= 0xFFFF for part in parts):
            parser.error("--light-hsv must be three integers H,S,V between 0 and 65535")
        args.light_hsv = tuple(int(part) for part in parts)
    if args.light_count is not None and not 0 <= args.light_count <= LIGHT_CUSTOM_SLOTS:
        parser.error(f"--light-count must be between 0 and {LIGHT_CUSTOM_SLOTS}")
    if args.watch and (lighting_requested(args) or args.light_status):
        parser.error("--watch only applies to the battery status; drop it for lighting options")


def _normalize(value):
    value = float(value)
    return int(value) if value.is_integer() else value


def _number(text: str):
    """Parse a number for the EQ options; keep integral values as ints."""
    return _normalize(float(text))


def _parse_filter_arg(parser, option: str, text, neutral: float):
    """Parse --eq-hpf/--eq-lpf values: 'off' (neutral frequency), FREQ or FREQ:Q."""
    if text is None:
        return None
    cleaned = text.strip().lower()
    if cleaned in ("off", "none"):
        return (_normalize(neutral), 1)
    freq_text, sep, q_text = cleaned.partition(":")
    try:
        freq = _number(freq_text)
        q = _number(q_text) if sep else 1.0
    except ValueError:
        parser.error(f"{option} must be FREQ, FREQ:Q or off")
    if not EQ_FREQ_MIN <= freq <= EQ_FREQ_MAX:
        parser.error(f"{option} frequency must be {EQ_FREQ_MIN}..{EQ_FREQ_MAX} Hz")
    if not EQ_Q_MIN <= q <= EQ_Q_MAX:
        parser.error(f"{option} Q must be {EQ_Q_MIN:g}..{EQ_Q_MAX:g}")
    return (freq, q)


def _validate_eq(parser, args) -> None:
    """Validate and normalize scene/EQ options in place (argparse error on misuse)."""
    if args.watch and (eq_requested(args) or args.eq_status):
        parser.error("--watch only applies to the battery status; drop it for scene/EQ options")
    if (lighting_requested(args) or args.light_status) and (eq_requested(args) or args.eq_status):
        parser.error("lighting and scene/EQ options are separate commands; run them one at a time")

    if args.scene is not None:
        name, _, index_text = args.scene.partition(":")
        key = name.strip().lower()
        if key not in SCENES:
            parser.error("--scene must be original | podcast | game | sing, optionally name:N")
        try:
            index = int(index_text) if index_text.strip() else 0
        except ValueError:
            parser.error("--scene preset number must be an integer, e.g. --scene sing:1")
        if not 0 <= index < len(SCENE_PRESETS[key]):
            choices = " ".join(f"{key}:{i}" for i in range(len(SCENE_PRESETS[key])))
            parser.error(f"--scene {key} has {len(SCENE_PRESETS[key])} preset(s): {choices}")
        args.scene = (key, index)

    if args.eq_preset is not None:
        preset_key = args.eq_preset.strip().lower()
        if preset_key not in EQ_PRESETS:
            parser.error("--eq-preset must be one of: " + ", ".join(EQ_PRESETS))
        args.eq_preset = preset_key

    if args.eq_flag is not None and args.scene is None:
        parser.error("--eq-flag only makes sense together with --scene")

    bands = []
    for tokens in args.eq_band or []:
        if not 4 <= len(tokens) <= 5:
            parser.error("--eq-band needs 'N FREQ GAIN Q [peak|low-shelf|high-shelf]'")
        try:
            n = int(tokens[0])
            freq = _number(tokens[1])
            gain = _number(tokens[2])
            q = _number(tokens[3])
        except ValueError:
            parser.error("--eq-band: N, FREQ, GAIN and Q must be numbers")
        if not 1 <= n <= 5:
            parser.error("--eq-band N must be between 1 and 5")
        if not EQ_FREQ_MIN <= freq <= EQ_FREQ_MAX:
            parser.error(f"--eq-band frequency must be {EQ_FREQ_MIN}..{EQ_FREQ_MAX} Hz")
        if not EQ_GAIN_MIN <= gain <= EQ_GAIN_MAX:
            parser.error(f"--eq-band gain must be {EQ_GAIN_MIN:g}..{EQ_GAIN_MAX:g} dB")
        if not EQ_Q_MIN <= q <= EQ_Q_MAX:
            parser.error(f"--eq-band Q must be {EQ_Q_MIN:g}..{EQ_Q_MAX:g}")
        ftype = 0
        if len(tokens) == 5:
            type_key = tokens[4].strip().lower()
            if type_key not in EQ_BAND_TYPES:
                parser.error("--eq-band type must be peak | low-shelf | high-shelf")
            ftype = EQ_BAND_TYPES[type_key]
        bands.append((n, freq, gain, q, ftype))
    args.eq_band = bands

    args.eq_hpf = _parse_filter_arg(parser, "--eq-hpf", args.eq_hpf, 20)
    args.eq_lpf = _parse_filter_arg(parser, "--eq-lpf", args.eq_lpf, 20000)

    registers = []
    for item in args.eq_reg or []:
        key_text, sep, value_text = item.partition("=")
        if not sep:
            parser.error("--eq-reg needs KEY=VALUE, e.g. --eq-reg 0x2082=1")
        try:
            key = int(key_text, 0)
            value = int(value_text, 0)
        except ValueError:
            parser.error("--eq-reg KEY and VALUE must be integers, e.g. 0x2082=1")
        if not 0 <= key <= 0xFFFF or not 0 <= value <= 0xFFFF:
            parser.error("--eq-reg KEY and VALUE must be 16-bit (0..0xffff)")
        registers.append((key, value))
    args.eq_reg = registers

    if args.eq_name is not None and args.eq_export is None:
        parser.error("--eq-name only applies to --eq-export")
    if args.eq_mixture is not None and args.eq_export is None:
        parser.error("--eq-mixture only applies to --eq-export")
    if args.eq_level is not None:
        if args.eq_export is None:
            parser.error("--eq-level only applies to --eq-export")
        if not 0 <= args.eq_level <= 100:
            parser.error("--eq-level must be between 0 and 100")
    if args.eq_export is not None and args.eq_import is not None:
        parser.error("--eq-import applies a profile, --eq-export saves one; run them separately")
    if args.eq_export is not None and args.eq_reg:
        parser.error("--eq-reg writes registers, --eq-export saves a profile; run them separately")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="maono_battery",
        description="Battery status, RGB lighting and scene/PEQ control for Maono PD200W "
        "microphones (via the RX dongle or the wired USB-C mic).",
        epilog="Without --light*/--eq* options the battery status is probed once and printed; "
        "use --watch for live updates. Lighting and scene/EQ options write settings and exit; "
        "use --light-status / --eq-status to read the current settings back, and --eq-export / "
        "--eq-import to share sound profiles with the Windows app (.cfg). See docs/protocol.md.",
    )
    parser.add_argument("--device", metavar="PATH", help="use this hidraw node (e.g. /dev/hidraw3)")
    parser.add_argument("--list", action="store_true", help="list matching hidraw devices and exit")
    parser.add_argument("--watch", action="store_true", help="keep running and print updates (default: probe once, print and exit)")
    parser.add_argument("--once", action="store_true", help=argparse.SUPPRESS)  # default; kept for compatibility
    parser.add_argument("--wait", type=float, default=5.0, metavar="SEC", help="one-shot: how long to wait for data (default: 5)")
    parser.add_argument("--no-probe", action="store_true", help="never send anything; only listen for pushed frames")
    parser.add_argument("--probe-after", type=float, default=3.0, metavar="SEC", help="with --watch: listen this long before the first probe (default: 3)")
    parser.add_argument("--interval", type=float, default=3.0, metavar="SEC", help="re-probe interval while no battery data is arriving (default: 3)")
    parser.add_argument("--report-id", type=int, default=None, metavar="N", help="prepend a HID report ID byte to outgoing frames (usually not needed)")
    parser.add_argument("--raw", action="store_true", help="dump every received report (hex) to stderr")
    parser.add_argument("--json", action="store_true", help="print JSON lines instead of text")
    parser.add_argument("--verbose", action="store_true", help="extra diagnostics to stderr")
    parser.add_argument("--force", action="store_true", help="apply sound profiles even when they were exported for a different device name")
    parser.add_argument("--dry-run", action="store_true", help="print what scene/EQ options would write without touching the device")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    lighting = parser.add_argument_group("lighting (writes settings and exits)")
    lighting.add_argument("--light", choices=("on", "off"), help="turn the mic's LED ring on or off")
    lighting.add_argument("--light-brightness", type=int, metavar="1-100", help="LED ring brightness (1-100)")
    lighting.add_argument("--light-mode", metavar="MODE", help="LED effect: fixed | breathe | loop")
    lighting.add_argument(
        "--light-color",
        metavar="COLOR",
        help="LED color: preset name or index 0-7 (white red orange yellow green cyan blue "
        "magenta), or #RRGGBB to program and select a custom color",
    )
    lighting.add_argument("--light-slot", type=int, default=1, metavar="1-5", help="custom color slot for #RRGGBB / --light-hsv (default: 1)")
    lighting.add_argument("--light-hsv", metavar="H,S,V", help="advanced: raw custom-color register values (0-65535 each), bypassing RGB conversion")
    lighting.add_argument("--light-count", type=int, metavar="0-5", help="advanced: write the stored custom-color count register")
    lighting.add_argument("--light-status", action="store_true", help="read and print the current lighting settings")
    lighting.add_argument("--channel", choices=("1", "2", "both"), default="1", help="which mic to address (default: 1)")

    eq = parser.add_argument_group("scene / PEQ (writes settings and exits)")
    eq.add_argument(
        "--scene",
        metavar="SCENE[:N]",
        help="apply a scene preset: original | podcast | game | sing, optionally with the "
        "0-based preset number (e.g. --scene sing:1)",
    )
    eq.add_argument(
        "--eq-preset",
        metavar="NAME",
        help="push one built-in curve without changing the scene: " + ", ".join(EQ_PRESETS),
    )
    eq.add_argument(
        "--eq-band",
        nargs="+",
        action="append",
        metavar="N FREQ GAIN Q [TYPE]",
        help="write one peaking band (N=1..5, gain in dB, Q 0.05-20; TYPE: peak | low-shelf | "
        "high-shelf); repeat the option to write several bands",
    )
    eq.add_argument("--eq-hpf", metavar="FREQ[:Q]|off", help="high-pass filter at FREQ Hz (Q defaults to 1), or 'off' to bypass")
    eq.add_argument("--eq-lpf", metavar="FREQ[:Q]|off", help="low-pass filter at FREQ Hz (Q defaults to 1), or 'off' to bypass")
    eq.add_argument("--eq-flag", type=int, choices=(0, 1), metavar="0|1", help="advanced: SevenEQ (custom curve) bit in the mode register written by --scene")
    eq.add_argument("--eq-reg", action="append", metavar="KEY=VALUE", help="advanced: raw 16-bit register write, e.g. --eq-reg 0x2082=1 (repeatable; --channel is not applied)")
    eq.add_argument("--eq-status", action="store_true", help="read and print the active scene/preset and the seven EQ slots")
    eq.add_argument(
        "--eq-export",
        metavar="FILE",
        help="save an app-compatible .cfg sound profile: --eq-preset/--scene pick a built-in "
        "curve, --eq-band/--eq-hpf/--eq-lpf build a custom one (writes no device settings; "
        "the export source options are not applied to the mic)",
    )
    eq.add_argument("--eq-import", metavar="FILE", help="read an app .cfg sound profile and apply its curve to the mic")
    eq.add_argument("--eq-name", metavar="NAME", help="config name for --eq-export custom curves (default: Custom)")
    eq.add_argument("--eq-mixture", type=int, choices=(0, 1), metavar="0|1", help="advanced: reverb-mix flag in an exported profile (default: preset value, else 0)")
    eq.add_argument("--eq-level", type=int, metavar="N", help="advanced: reverb level in an exported profile (default: preset value, else 0)")

    args = parser.parse_args(argv)
    _validate_lighting(parser, args)
    _validate_eq(parser, args)
    return args


def run_lighting(args) -> int:
    """Apply --light* writes and/or read back the lighting status (one-shot)."""
    fd, device, read_only = open_device(args)
    try:
        print(f"[info] using {describe(device)}", file=sys.stderr)
        if lighting_requested(args):
            if read_only:
                raise DeviceError(
                    "lighting control needs write access to the hidraw node "
                    "(try sudo or add a udev rule; see README)"
                )
            writes = plan_lighting(args)
            for key, value, label in writes:
                if args.verbose:
                    print(f"[write] 0x{key:04x} <= {value:#06x}   ({label})", file=sys.stderr)
                send_frame(fd, write_value(key, value), args.report_id)
                time.sleep(LIGHT_WRITE_SPACING)
            print_writes(writes, args.json)
        if args.light_status:
            status = read_light_status(fd, args, args.wait, read_only)
            if not any(values for values in status.values()):
                print(
                    "no lighting data received (needs write access for probes? try sudo; "
                    "or use --raw to inspect traffic)",
                    file=sys.stderr,
                )
                return 2
            print_light_status(status, args.json)
        return 0
    finally:
        os.close(fd)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        if args.list:
            devices = sort_candidates(find_devices())
            for device in devices:
                print(describe(device))
            if not devices:
                print("no matching hidraw devices found", file=sys.stderr)
                return 1
            return 0

        if lighting_requested(args) or args.light_status:
            try:
                return run_lighting(args)
            except DeviceLost as exc:
                print(f"[warn] {exc}", file=sys.stderr)
                return 1

        if args.eq_export is not None and not eq_device_needed(args):
            return run_eq_export(args)

        if eq_device_needed(args):
            try:
                return run_eq(args)
            except DeviceLost as exc:
                print(f"[warn] {exc}", file=sys.stderr)
                return 1

        while True:
            fd, device, read_only = open_device(args)
            try:
                return run_session(args, fd, device, read_only)
            except DeviceLost as exc:
                print(f"[warn] {exc}", file=sys.stderr)
                if not args.watch:
                    return 1
                time.sleep(1.0)
            finally:
                os.close(fd)
    except DeviceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
