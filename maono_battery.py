#!/usr/bin/env python3
"""Show the battery status of Maono PD200W wireless microphones.

By default the tool probes once, prints one status line and exits; pass
``--watch`` to keep running and print updates whenever values change.

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

Linux only; stdlib only; talks to /dev/hidraw* directly.

Exit codes: 0 = ok, 1 = error (no device, open/write failure),
            2 = no battery data received, 130 = interrupted.
"""

from __future__ import annotations

import argparse
import errno
import glob
import json
import os
import re
import select
import struct
import sys
import time

VERSION = "0.2.0"

# --- protocol constants (docs/protocol.md) ---------------------------------

MAGIC = 0xC4
CMD_ACK = 0x03
CMD_READ = 0x04
CMD_WRITE = 0x06
CMD_PAIR_TYPES = (0x03, 0x04)  # incoming key/value list frames

KEY_BATTERY = 0x42
KEY_CHARGE = 0x49

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
    """cmd 0x06 write frame for one key/value pair (11 bytes)."""
    return build_frame(CMD_WRITE, struct.pack("<HH", key, value))


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


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="maono_battery",
        description="Show the battery status of Maono PD200W microphones via the RX dongle.",
        epilog="By default the status is probed once and printed; use --watch for live "
        "updates. Battery frames are requested with single-key read probes (keys 0x42 "
        "and 0x49); see docs/protocol.md for the wire format.",
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
    return parser.parse_args(argv)


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
