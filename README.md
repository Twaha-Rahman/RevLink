## RevLink CLI (For the Maono PD200XW)

RevLink (`revlink.py`) is a dependency-free Python 3 script (stdlib only) that
shows the battery status of both microphones:

```sh
./revlink.py                   # one-shot: print the status and exit
./revlink.py --json            # one-shot, machine-readable
./revlink.py --watch           # keep running, print updates on change
./revlink.py --watch --json    # JSON lines
./revlink.py --raw --verbose   # dump every HID report (debugging)
./revlink.py --list            # show matching hidraw devices
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
./revlink.py --light-status                  # read back the current LED settings
sudo ./revlink.py --light on                 # LED ring on (also: --light off)
sudo ./revlink.py --light-brightness 40      # 1-100 (affects battery runtime)
sudo ./revlink.py --light-mode breathe       # fixed | breathe | loop
sudo ./revlink.py --light-color red          # red | white orange yellow green cyan blue magenta | 0-7
sudo ./revlink.py --light-color '#3366FF'    # custom color into slot 1
sudo ./revlink.py --light-color '#3366FF' --light-slot 3
sudo ./revlink.py --light on --channel both  # address both mics (default: 1)
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
./revlink.py --eq-status                     # read back scene, preset and all seven EQ slots
sudo ./revlink.py --scene game               # apply a scene preset (original|podcast|game|sing)
sudo ./revlink.py --scene sing:1             # preset 1 of that scene (0-based; sing:1 = Folk)
sudo ./revlink.py --eq-preset podcast1       # push one curve without switching the scene
sudo ./revlink.py --eq-band 3 1000 -4 2.5    # band 3: 1 kHz, -4 dB, Q 2.5 (bands 1-5)
sudo ./revlink.py --eq-band 1 200 3 1.5 low-shelf   # optional type: peak | low-shelf | high-shelf
sudo ./revlink.py --eq-hpf 80 --eq-lpf 12000 # high-/low-pass filter (FREQ[:Q], or 'off')
sudo ./revlink.py --eq-reg 0x2082=1          # advanced: raw register write
```

`--scene` writes the whole curve (7 slots), the reverb mix and the EQ mode
word, exactly like the app. Band edits write single slots; the mode word is
not touched (`--eq-flag 1` sets the "custom curve" bit when combined with
`--scene`). `--channel 1|2|both` selects the microphone; `--dry-run` prints
the frames a real run would send and works without device access.

Sound profiles can be shared with the Windows app in its `.cfg` format:

```sh
./revlink.py --eq-export pop.cfg --eq-preset pop          # works without a device
./revlink.py --eq-export voice.cfg --eq-band 3 1000 -4 2.5 --eq-hpf 80 --eq-name "My Voice"
sudo ./revlink.py --eq-import pop.cfg                     # apply a profile to the mic
```

Exports use the app's JSON layout (`device_name` `PD200XW`, `blnMixture`,
`level`, `InfoName`, `curve_contains`, `blnDefault`), so the files import
straight into "Maono Link" (and vice versa). `--force` accepts a profile that
was exported for a different device name.

Verified on hardware: the scene/band writes round-trip unchanged, and
`--eq-status` reads the mode word, the reverb registers and all seven EQ
slots back from the device.

### Noise reduction

The mic's three-stage noise canceller (the app page's "NR" control) can be
configured with `--noise-reduction*` options:

```sh
./revlink.py --noise-reduction-status                    # read back state and level
sudo ./revlink.py --noise-reduction on                   # enable (also: off)
sudo ./revlink.py --noise-reduction-level aggressive     # gentle | balanced | aggressive
sudo ./revlink.py --noise-reduction on --noise-reduction-level balanced --channel both
```

`--noise-reduction-level` also accepts the aliases `soft`/`mid`/`strong` and
the raw `0-2` register value. The registers come from the app's UI write path
(§11 in `docs/protocol.md`) and are **not hardware-verified yet** — `--dry-run`
prints the exact frames a real run would send. The "AI denoise" entry in the
app's AI panel is a separate Windows-side service feature and is not reachable
over this protocol.

### Device access

`/dev/hidraw*` nodes are root-only by default. Either run with `sudo` or add a
udev rule so the logged-in user gets access (one line per product ID; older
units report VID `31b2` instead of `352f`):

```
# /etc/udev/rules.d/70-maono-pd200w.rules
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="352f", ATTRS{idProduct}=="040e", TAG+="uaccess"
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="352f", ATTRS{idProduct}=="040f", TAG+="uaccess"
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="352f", ATTRS{idProduct}=="0410", TAG+="uaccess"
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="352f", ATTRS{idProduct}=="0411", TAG+="uaccess"
```

### Tests

```sh
python3 -m unittest discover -s tests
```

## Documents

- [`docs/protocol.md`](docs/protocol.md) — reverse-engineered protocol
  reference: HID interface, frame format, commands, key registry, init
  sequence, battery handling, lighting control, scene/PEQ registers and noise
  reduction.

No vendor binaries are tracked in this repository (see `.gitignore`).

# Disclaimer

Reverse engineering of the **Maono PD200W** wireless microphone's USB HID
protocol (as implemented by the Windows "Maono Link" app), with **RevLink**, a
small Linux CLI that shows the live battery status of the microphones (TX1 /
TX2) via the RX dongle, controls the mic's RGB LED ring, its three-stage noise
canceller and the app's scene presets and seven-point PEQ.

> **Disclaimer:** this is an unofficial, independent project; it is not
> affiliated with or endorsed by Maono. "Maono", "Maono Link" and "PD200W"
> are trademarks of their respective owners, used here only to identify the
> hardware and the vendor app this project interoperates with.


## License

[MIT](LICENSE) — this unofficial project is not affiliated with or endorsed by
Maono; hardware names are trademarks of their respective owners.

