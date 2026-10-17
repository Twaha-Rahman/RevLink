# maono-pd200w

Reverse engineering of the **Maono PD200W** wireless microphone's USB HID
protocol (as implemented by the Windows "Maono Link" app), with a small Linux
CLI that shows the live battery status of the microphones (TX1 / TX2) via the
RX dongle, controls the mic's RGB LED ring and selects the app's scene presets
and seven-point PEQ.

## Documents

- [`docs/protocol.md`](docs/protocol.md) — reverse-engineered protocol
  reference: HID interface, frame format, commands, key registry, init
  sequence, battery handling, lighting control, and scene/PEQ registers.

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

**The lighting protocol was reconstructed from the vendor app's UI code** (see
§9 in `docs/protocol.md`) and is hardware-verified: the writes use the same
cmd-0x03 frames the app sends. If a setting does not take effect, run with
`--raw --verbose` and keep the captured traffic.

### Scene presets and PEQ

The four app scenes (Original / Podcast / Game / Sing) and their PEQ curves can
be applied with `--scene`; individual bands, the HPF/LPF and the raw registers
can be edited with `--eq-*` options:

```sh
./maono_battery.py --eq-status                     # read back scene, preset and all seven EQ slots
sudo ./maono_battery.py --scene game               # apply a scene preset (original|podcast|game|sing)
sudo ./maono_battery.py --scene sing:1             # preset 1 of that scene (0-based; sing:1 = Folk)
sudo ./maono_battery.py --eq-preset podcast1       # push one curve without switching the scene
sudo ./maono_battery.py --eq-band 3 1000 -4 2.5    # band 3: 1 kHz, -4 dB, Q 2.5 (bands 1-5)
sudo ./maono_battery.py --eq-band 1 200 3 1.5 low-shelf   # optional type: peak | low-shelf | high-shelf
sudo ./maono_battery.py --eq-hpf 80 --eq-lpf 12000 # high-/low-pass filter (FREQ[:Q], or 'off')
sudo ./maono_battery.py --eq-reg 0x2082=1          # advanced: raw register write
```

`--scene` writes the whole curve (7 slots), the reverb mix and the EQ mode
word, exactly like the app. Band edits write single slots; the mode word is
not touched (`--eq-flag 1` sets the "custom curve" bit when combined with
`--scene`). `--channel 1|2|both` selects the microphone, `--dry-run` prints
what would be written.

Sound profiles can be shared with the Windows app in its `.cfg` format:

```sh
./maono_battery.py --eq-export pop.cfg --eq-preset pop          # works without a device
./maono_battery.py --eq-export voice.cfg --eq-band 3 1000 -4 2.5 --eq-hpf 80 --eq-name "My Voice"
sudo ./maono_battery.py --eq-import pop.cfg                     # apply a profile to the mic
```

Exports use the app's JSON layout (`device_name` `PD200XW`, `blnMixture`,
`level`, `InfoName`, `curve_contains`, `blnDefault`), so the files import
straight into "Maono Link" (and vice versa). `--force` accepts a profile that
was exported for a different device name.

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

