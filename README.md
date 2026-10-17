# maono-pd200w

Reverse engineering of the **Maono PD200W** wireless microphone's USB HID
protocol (as implemented by the Windows "Maono Link" app), with a small Linux
CLI that shows the live battery status of the microphones (TX1 / TX2) via the
RX dongle.

## Documents

- [`docs/protocol.md`](docs/protocol.md) — reverse-engineered protocol
  reference: HID interface, frame format, commands, key registry, init
  sequence, and battery handling.

No vendor binaries are tracked in this repository (see `.gitignore`).

## CLI

`maono_battery.py` is a dependency-free Python 3 script (stdlib only) that
shows the battery status of both microphones:

```sh
./maono_battery.py                # live updates (Ctrl+C to quit)
./maono_battery.py --once --json  # one-shot, machine-readable
./maono_battery.py --raw --verbose   # dump every HID report (debugging)
./maono_battery.py --list         # show matching hidraw devices
```

By default it listens for pushed battery frames and, if nothing arrives,
starts sending single-key read probes every few seconds (`--no-probe`
disables probing; `--device /dev/hidrawN` picks a node explicitly).

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

