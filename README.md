# maono-pd200w

Reverse engineering of the **Maono PD200W** wireless microphone's USB HID
protocol (as implemented by the Windows "Maono Link" app), with the goal of
building a small Linux CLI that shows the live battery status of the
microphones (TX1 / TX2) via the RX dongle.

## Documents

- [`docs/protocol.md`](docs/protocol.md) — reverse-engineered protocol
  reference: HID interface, frame format, commands, key registry, init
  sequence, and battery handling.

No vendor binaries are tracked in this repository (see `.gitignore`).
