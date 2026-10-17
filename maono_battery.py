#!/usr/bin/env python3
"""Battery status and RGB lighting control for Maono PD200W microphones.

By default the tool probes the battery once, prints one status line and exits;
pass ``--watch`` to keep running and print updates whenever values change.
Lighting options (``--light*``) apply settings to the mic's LED ring instead
and exit after confirming what was written; ``--light-status`` reads back the
current lighting registers.

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

Linux only; stdlib only; talks to /dev/hidraw* directly.

Exit codes: 0 = ok, 1 = error (no device, open/write failure),
            2 = no battery/lighting data received, 130 = interrupted.
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

VERSION = "0.3.0"

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


def print_light_writes(writes: list, as_json: bool) -> None:
    for key, value, label in writes:
        if as_json:
            print(
                json.dumps(
                    {"timestamp": time.time(), "key": f"0x{key:04x}", "value": value, "label": label}
                ),
                flush=True,
            )
        else:
            print(f"0x{key:04x} <= {value}   {label}", flush=True)


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


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="maono_battery",
        description="Battery status and RGB lighting control for Maono PD200W microphones "
        "(via the RX dongle or the wired USB-C mic).",
        epilog="Without --light* options the battery status is probed once and printed; use "
        "--watch for live updates. Lighting options write to the mic's LED ring and exit; "
        "use --light-status to read the current settings back. See docs/protocol.md.",
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

    args = parser.parse_args(argv)
    _validate_lighting(parser, args)
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
            print_light_writes(writes, args.json)
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
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
