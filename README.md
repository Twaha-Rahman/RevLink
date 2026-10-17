# maono-pd200w

Reverse engineering of the **Maono PD200W** wireless microphone's USB HID
protocol (as implemented by the Windows "Maono Link" app), with a small Linux
CLI that shows the live battery status of the microphones (TX1 / TX2) via the
RX dongle and controls the mic's RGB LED ring.

## Documents

- [`docs/protocol.md`](docs/protocol.md) — reverse-engineered protocol
  reference: HID interface, frame format, commands, key registry, init
  sequence, battery handling, and lighting control.

No vendor binaries are tracked in this repository (see `.gitignore`).

## CLI

`maono_battery.py` is a dependency-free Python 3 script (stdlib only) that
shows the battery status of both microphones:

```sh
./maono_battery.py                   # one-shot: print the status and exit
./maono_battery.py --json            # one-shot, machine-readable
./maono_battery.py --watch           # keep running, print updates on change
./maono_battery.py --watch --json    # JSON lines
./maono_battery.py --raw --verbose   # dump every HID report (debugging)
./maono_battery.py --list            # show matching hidraw devices
```

One-shot mode sends single-key read probes (keys `0x42`/`0x49`) and prints one
line. With `--watch` it listens first and only re-probes while no battery data
is arriving (`--no-probe` makes it listen-only; `--device /dev/hidrawN` picks
a node explicitly).

Verified working on hardware with both the wireless RX dongle (`352f:040e`)
and the wired USB-C microphone (`352f:0411`).

### Lighting (RGB) control

The mic's LED ring can be configured with `--light*` options; they write to
the device and exit after printing the frames sent:

```sh
./maono_battery.py --light-status                  # read back the current LED settings
sudo ./maono_battery.py --light on                 # LED ring on (also: --light off)
sudo ./maono_battery.py --light-brightness 40      # 1-100 (affects battery runtime)
sudo ./maono_battery.py --light-mode breathe       # fixed | breathe | loop
sudo ./maono_battery.py --light-color red          # red | white orange yellow green cyan blue magenta | 0-7
sudo ./maono_battery.py --light-color '#3366FF'    # custom color into slot 1
sudo ./maono_battery.py --light-color '#3366FF' --light-slot 3
sudo ./maono_battery.py --light on --channel both  # address both mics (default: 1)
```

`--light-color #RRGGBB` converts RGB to the H/S/V register values the vendor
app stores (H = hue × 100, S/V = percent) and selects the custom color;
custom colors live in 5 slots (`--light-slot 1-5`). `--light-hsv H,S,V`
writes raw register values (escape hatch), `--light-count N` writes the
stored-color count register (advanced; can hide existing custom colors).

**The lighting protocol is reconstructed from the vendor app's UI code and is
not yet verified on hardware** (see §9 in `docs/protocol.md`); the writes use
the same cmd-0x03 frames the app sends. If a setting does not take effect,
run with `--raw --verbose` and keep the captured traffic.

### Device access

`/dev/hidraw*` nodes are root-only by default. Either run with `sudo` or add a
udev rule so the logged-in user gets access (one line per product ID):

```
# /etc/udev/rules.d/70-maono-pd200w.rules
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="352f", ATTRS{idProduct}=="040e", TAG+="uaccess"
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="352f", ATTRS{idProduct}=="040f", TAG+="uaccess"
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="352f", ATTRS{idProduct}=="0410", TAG+="uaccess"
```

### Tests

```sh
python3 -m unittest discover -s tests
```

