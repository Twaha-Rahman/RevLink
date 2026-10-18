# Maono PD200W — USB HID protocol (reverse-engineered)

Findings from static analysis of **Maono Link 4.0.88** (vendor installer
`Maono Link_V4.0.88_0918.exe`) and its extracted components.

Findings are reconstructed from the shipped binaries; §8 records what live
hardware testing has since confirmed. Statements that could not be verified
against hardware are marked **[unverified]**. §9 (lighting control) is
reconstructed from the app's UI code and is **not yet hardware-verified**.

## 1. Artifacts under analysis

| Artifact | SHA-256 | Notes |
|---|---|---|
| `Maono Link_V4.0.88_0918.exe` (installer, git-ignored) | `62848eef6162aac0a020adf8e5869d378061f0fa3c2300babd379d7c7e706ff5`* | NSIS self-extractor |
| `Maono Link.exe` (main app, extracted) | `62848eef6162aac0a020adf8e5869d378061f0fa3c2300babd379d7c7e706ff5` | Qt6 app; contains the HID transport (embedded hidapi + SetupAPI enumeration) |
| `PD200XW.dll` (product module, extracted) | `de07fb05cb440ca47156bc905eb0b209953fe03b751d2f3c52ee2fe82b4cb762` | Implements the wire protocol, device logic, battery handling, and the PD200W UI |

\* the installer digest equals the extracted `Maono Link.exe` digest as measured here;
the canonical digests for the extracted files are in the table above.

Extraction location during analysis: `/tmp/opencode/maono-extract/installer/`
(outside the repo; binaries are git-ignored).

`MaonoDevicesInfo.txt` (shipped with the app) maps USB PIDs to product modules:

```
pid_040E:Wireless Mic Kit,PD200W_RX,PD200XW.dll
pid_040F:Wireless Mic Kit,PD200W_RX,PD200XW.dll
pid_0410:Wireless Mic Kit,PD200W_RX,PD200XW.dll
pid_0411:PD200W,PD200W,PD200XW.dll
```

## 2. System architecture

```
  host app "Maono Link.exe"                    product module "PD200XW.dll"
  ┌──────────────────────────┐                 ┌───────────────────────────┐
  │ CHID_DeviceManager       │  raw 64-byte    │ DataCenter                │
  │  · enumerates HID paths  │  frames         │  · frame builders (cmd    │
  │  · CHID_Device (hidapi)  │ ───────────────▶│    3 / 4 / 6)             │
  │  · AnalyseRawData        │ ◀───────────────│  · incoming frame parser  │
  │  · MaonoRead read loop   │                 │  · battery handling       │
  └──────────────────────────┘                 └───────────────────────────┘
            │ USB HID (interrupt IN/OUT reports)
            ▼
       PD200W RX dongle (USB) ⇢ 2.4 GHz ⇢ PD200W TX1 / TX2 microphones
```

The app side is only a **transport**: it enumerates HID devices, opens the
vendor collection, writes 64-byte frames, reads 64-byte reports, and forwards
them to the product module. All protocol logic lives in `PD200XW.dll`.

Key app-side functions (addresses are VAs in `Maono Link.exe`):

| Address | Symbol | Role |
|---|---|---|
| `0x140091c20` … `0x140094860` | `CHID_DeviceManager::*` | device manager (PDB symbols recovered) |
| `0x140093bc0` | `CHID_DeviceManager::SendData` | routes an outgoing frame to the per-device transport |
| `0x1400934e0` | `CHID_DeviceManager::MaonoRead` | single HID read from the transport |
| `0x1400920d0` | `CHID_DeviceManager::AnalyseRawData` | classifies an incoming report by its 5th byte |
| `0x140092210` | `CHID_DeviceManager::AutoConnectDevice` | enumerate + connect |
| `0x140093600` | `CHID_DeviceManager::PathConnectDevice` | open one HID path |
| `0x14008e3c0` | `CHID_Device` ctor | per-device transport object (vtable at `.rdata 0x268f78`; `+0x30` open, `+0x48` write, `+0x50` read, `+0x60` path) |
| `0x14008f3b0` | `CHID_Device::Write` | pads and calls hidapi `hid_write` |
| `0x14008f340` | `CHID_Device::Read` | calls hidapi `hid_read_timeout` |
| `0x14013d6e0` | read thread body | 64-byte read loop, forwards to device module |
| `0x140094b50` … `0x1400963b0` | embedded **hidapi** (windows) | `hid_enumerate`, `hid_open_path`, `hid_read_timeout`, `hid_write`, … (resolved from `hid.dll` in `hid_init` @ `0x1400955d0`) |
| `0x140145f00` | `hid_enumerate` internals | `SetupDiGetClassDevsA` on the HID class GUID `{4d1e55b2-f16f-11cf-88cb-001111000030}` |

### 2.1 HID interface the app uses for the PD200W RX

The app matches device-interface paths against these strings
(`Maono Link.exe`, `.rdata`, VA range `0x14028b090`-ish):

```
vid_352f&pid_040e&mi_03&col01     <- full "vendor" path of the PD200W RX
vid_352f&pid_040e&mi_03&col0      <- prefix form
vid_352f / vid_31b2               <- bare VIDs (other product families)
```

So the control channel is:

* **VID `0x352f`** (older units may use `0x31b2`)
* **PID `0x040e`** (PD200W RX dongle; siblings `0x040f`/`0x0410`; the USB-C mic is `0x0411`)
* **USB interface 3** (`mi_03`), **top-level collection 1** (`col01`)

### 2.2 Report framing (OS layer)

* Input reports: 64-byte payload + report ID byte `0x00`. hidapi's Windows
  backend reads `InputReportByteLength` (65) bytes and strips a leading zero
  report ID (`hid_read_timeout` @ `0x140095ca0`).
* Output reports: callers hand hidapi 64/65-byte buffers; hidapi zero-pads to
  `OutputReportByteLength` (65 = 1-byte report ID + 64-byte payload) and writes
  exactly that (`hid_write` @ `0x1400963b0`).
* Verified on Linux `hidraw` (2026-10-17, see §8): reports are unnumbered
  **64-byte payloads** starting with `0xC4` (nothing to strip), and 64-byte
  zero-padded writes are accepted as-is (no report ID prefix needed).

## 3. Wire protocol (PD200XW.dll)

### 3.1 Logical frame layout

Both directions use one layout (shown *without* the OS report-ID byte):

```
off  size  field
 0    1    magic 0xC4
 1    2    frame length N (u16 LE) = total frame length in bytes
 3    1    0x00
 4    1    command / type  (see below)
 5    ..   payload
 N-2  2    checksum (u16 LE)  = (0x10000 - sum(frame[0..N-3])) & 0xFFFF
```

* The checksum is a 16-bit two's-complement of the byte sum of everything
  before it. Zero padding at the end does not affect it.
* All frames are sent inside a 64-byte HID report (zero padded); the largest
  meaningful frame the app ever builds is 63 bytes.

Direct example (`write` frame for key `0x1e`, value `0x10`, built by
`FUN_180064f70` using `[00 C4 0B 00 00 06 1E 00 10 00 FD FE]` before padding):

```
C4 0B 00 00 06 1E 00 10 00 FD FE   ; checksum FD FE = -(C4+0B+06+1E+10)
```

### 3.2 Commands host → device (byte 4)

| Cmd | Meaning | Payload | N |
|---|---|---|---|
| `0x03` | Write pair / ACK-reply | 1 × (key u16 LE, value u16 LE) — single-pair builder used for every app write | 11 |
| `0x04` | Read | n × key u16 LE at `[5+2i]` | `7 + 2n` |
| `0x06` | Block read | 1 × (key u16 LE, count u16 LE) — "stream me `count` consecutive u16 values starting at `key`" | 11 |

Notes:

* `0x03` is the opcode for every value the app writes: UI clicks, companion
  init writes and auto-ACKs. Layout (`FUN_180064a30`, checksum base `0xFF2E`
  = −(0xC4+0x0B+0x03)):
  `C4 0B 00 00 03 K_lo K_hi V_lo V_hi cks_lo cks_hi`
  e.g. LED ring on ⇒ `C4 0B 00 00 03 89 20 01 00 84 FE`. The device uses the
  *same* opcode for its ACK / pair reports.
* `0x06` (`FUN_180064f70`, checksum base `0xFF2B`) has the same 11-byte shape
  but requests a run of consecutive values, answered with type-`0x06`
  streaming frames (§3.3). App examples:
  `C4 0B 00 00 06 1E 00 10 00 FD FE` (16-value serial-number block at
  `0x1e`) and `C4 0B 00 00 06 8F 20 0F 00 6D FE` (15 values at `0x208f` =
  five custom colors × H/S/V).
* Empty read list ⇒ **no frame at all** is sent (builder returns an empty array).
* Single-key read `0x04` for key `K` is a fixed 9-byte frame:
  `C4 09 00 00 04 K_lo K_hi cks_lo cks_hi`
  e.g. key `0x42` ⇒ `C4 09 00 00 04 42 00 ED FE`.
* Builders: `FUN_180064a30` (cmd 3), `FUN_180064d70` (cmd 4 list),
  `FUN_180064940` (cmd 4 single), `FUN_180064f70` (cmd 6).

### 3.3 Types device → host (byte 4)

| Type | Meaning | Payload | N |
|---|---|---|---|
| `0x03`, `0x04` | key/value list ("random" read/write notification) | n × (key u16 LE, value u16 LE) at `[5+4i]` | `7 + 4n` |
| `0x06` | continuous/streaming values for one key | key u16 @ `[5..6]`, count u16 @ `[7..8]`, count × value u16 from `[9]` | `11 + 2n` |

Notes:

* The app's `AnalyseRawData` classifies incoming reports by byte 5 for `'K'`
  (0x4B)-prefixed protocols and by byte 4 otherwise, and forwards non-`K`
  frames with type `0x02`/`0x03`/`0x04` to the product module.
* Type `0x06` is the answer to a host block read: `key`, `count`, then
  `count` consecutive values from `key`. The DLL parses it in the stream
  splitter `FUN_180065040`; the per-device Analyzer consumes one value per
  key through its continuous-read slot (`FUN_180069330`).
* Only frames whose key is in the DLL's registered list are dispatched.
* Type-6 replay path: `FUN_1800455e0` → `DataPackage` (`FUN_1800644a0`).
* The DLL auto-replies with an ACK (cmd 3) when it receives the pair
  `(0x2084 | 0x2884 | 0x3084, 1)` (only when the corresponding init flags are
  set — see §5).

### 3.4 Registered keys (accepted from device)

Registered at `DataCenter` construction (`FUN_18004ff50`):

```
0x41 0x47 0x42 0x49 0x43 0x44 0x1e 0x2e 0x45 0x46 0x2022 0x2822 0x0b 0x20b3 0x28b3 0x3092
```

A second list (`DataCenter+0x70`) = `0x51, 0x21, 0x1b, 0x1f, 0x53` — purpose
not resolved. **[unknown]**

### 3.5 Key semantics relevant to battery

| Key | Handler | Meaning |
|---|---|---|
| `0x42` | `FUN_180052760` | u16 value: **low byte = TX1 battery, high byte = TX2 battery**; logs `#### Battery TX1:` / `Battery TX2 :`; stored into props `0x2a` / `0x2b` |
| `0x49` | `FUN_180053550` (`DataCenter::ProcessCharge`) | u16 value: **low byte = TX1 charge state, high byte = TX2 charge state**; logs `DataCenter::ProcessCharge`; stored into props `0x2d` / `0x2e` |
| `0x20b3` / `0x28b3` | dispatcher → `DataCenter::FetchAllInitPamaras(mode 2)` | "Get Ready" from TX1 / TX2; host then runs the full init sequence |
| `0x2084` / `0x2884` / `0x3084` | parser special-case; §11 | noise-reduction state (1 = on); when value == 1, DLL replies with an ACK frame |
| `0x2085` / `0x2885` / `0x3085` | §11 | noise-reduction level: 0/1/2 = gentle/balanced/aggressive |
| `0x41` | `FUN_180053d70` | (used in mode-1 init; likely also a "ready"/state key) |
| `0x44` | `FUN_180056040` | ~10 Hz streamed meter value: **audio input level** (drives `MainLevelWidget`, the VU meter; strings `refreshLevelWidget`, `-48dB`, `0dB`); stored as param `0x09` with `low byte = TX1, high byte = TX2` |
| `0x45, 0x46, 0x47` | various | device status/info keys (not battery) |
| `0x2022` / `0x2822` | inline | **EQ mode word** (scene `<< 8` \| preset index, bit 15 = custom-curve flag); see §10 |

Battery values: both handlers simply store the raw byte. The UI side
(verified in `FUN_180018a70`, the per-device widget property-change handler)
consumes them as follows:

* props `0x2a`/`0x2b` → `FUN_18001a970` sets the two `QProgressBar` battery
  gauges (widget `+0x78` = TX1, `+0x80` = TX2) to the value; the bar is styled
  green when `value > threshold` (10 or 20, depending on device state) and red
  otherwise, using `QProgressBar{...Electricity_n.png...}` stylesheets
  (`0x180082650` green / `0x1800828d0` red). Log labels: "后台给的电量1/2"
  ("battery 1/2 from backend") ⇒ the byte is a **percentage 0-100**.
  **[value scale unverified]**
* props `0x2d`/`0x2e` → `FUN_18001aaf0` shows/hides a small icon overlay
  (widget `+0x68` over the TX1 bar, `+0x70` over the TX2 bar) when the value
  is `1`. Log labels: "后台给的充电状态1/2" ("charge status 1/2 from
  backend") ⇒ charging indicator. **[exact enum values unverified]**

So the app shows, per device, both a battery percentage (key `0x42`) and a
charging state (key `0x49`). Note the two keys are NOT per-device: each key
carries both TX1 and TX2 data packed into one u16 (low byte = TX1, high byte
= TX2).

`0x42`/`0x49` are registered at construction and are never explicitly read by
the app. In the live sessions of §8 neither key was pushed spontaneously —
instead the device answers cmd-4 single-key reads for both keys (which is what
the CLI does).

## 4. App init sequence (after "Get Ready")

`DataCenter::FetchAllInitPamaras` (`FUN_18004a850`) — `mode 2` (full init),
triggered by incoming `0x20b3`/`0x28b3`, by a 1 s single-shot timer after
connect, and by the window-loading path:

TX1 block (`0x20xx`; the opcode of each step is annotated):

```
cmd3 write 0x2084 = 0          (only when init flag 68/69 set)
cmd3 write 0x20af = 2          (only when init flag 67 set)
cmd4 readList 0x207d 0x207e 0x207f
cmd4 readList 0x2084 0x2085 0x208e
cmd4 readList 0x2089 0x208b 0x208a 0x208c
cmd6 blockRead 0x1e,   16 values   (serial number)
cmd4 read 0x20af
cmd6 blockRead 0x2069, 10 values
```

TX2 block (`0x28xx`, only when a TX2 slot exists):

```
cmd3 write 0x2884 = 0; cmd3 write 0x28af = 2
cmd4 readList 0x287d 0x287e 0x287f
cmd4 readList 0x2884 0x2885 0x288e
cmd4 readList 0x2889 0x288b 0x288a 0x288c
cmd6 blockRead 0x2e,   16 values   (serial number)
cmd4 read 0x28af
cmd6 blockRead 0x2869, 10 values
```

RX block (`0x30xx`, when an RX slot exists):

```
cmd3 write 0x3088 = 2          (only when init flag 67 set)
cmd4 readList 0x307d (slot0==RX only) 0x3090 (slot1==RX only) 0x307e 0x307f
cmd4 readList 0x3084 0x3085
cmd4 read 0x3091
cmd4 readList 0x3093 0x3094     (twice)
cmd4 read 0x3088
cmd4 read 0x3086
cmd4 readList 0x3082 0x3083
```

Common tail: `cmd4 read 0x46`, `cmd6 blockRead 0x0b, 3 values`, then a
per-device loop calling `FUN_1800599b0` for each entry in the device map
(`DataCenter+0x1b8`; entry types: 1 = RX, 2/3 = TX).

An earlier reading of the `0x1e`/`0x2e`/`0x2069`/`0xb` steps as "writes" was
wrong: those frames come from the **cmd-6 block-read** builder, whose value
field is a *count* of consecutive values to stream back (16-value serial
number at `0x1e`/`0x2e`, 10-value block at `0x2069`/`0x2869`, 3 values at
`0x0b`). Only the `... = N` lines send cmd-3 write pairs.

The app's send path is queued: `FUN_18005b660` pushes a frame onto
`DataCenter+0x28` and lazily starts a 100 ms TX timer (timeout →
`FUN_1800606e0`).

## 5. What a battery CLI must do (playbook)

1. Find the RX HID node: VID `0x352f` (or `0x31b2`), PID `0x040e`/`0x040f`/`0x0410`
   (USB-C mic: PID `0x0411`, whose vendor collection sits on a different USB
   interface than the RX's `mi_03`).
   On Linux: `/sys/class/hidraw/hidraw*/device/uevent` `HID_ID=0003:0000352F:0000040E`,
   interface from the USB path (`…:1.3`).
2. Open the raw node; write 64-byte frames; read 64-byte reports.
3. Parse every report starting `0xC4`: validate length + checksum, then look at
   byte 4:
   * `0x03`/`0x04` → iterate pairs; for key `0x42` print
     `TX1 battery = value & 0xFF`, `TX2 battery = value >> 8`; for key `0x49`
     print the charge states the same way (low byte = TX1, high byte = TX2).
4. Fetch the values with cmd-4 single-key read probes — verified on hardware:
   the device answers immediately (responses also arrive as type `0x04`):
   ```
   request:  C4 09 00 00 04 42 00 ED FE            (padded to 64 bytes)
   response: C4 0B 00 00 04 42 00 63 00 88 FE      -> value 0x0063 = 99 %
   request:  C4 09 00 00 04 49 00 E6 FE
   response: C4 0B 00 00 04 49 00 00 00 E4 FE      -> value 0x0000
   ```
   In the observed sessions the device did **not** push `0x42`/`0x49` by
   itself; it does push the `0x44` level stream continuously.
5. Optional hardening (was not needed for reads to work):
   * mirror the app's RX init reads (no state-changing writes),
   * auto-ACK `(0x2084|0x2884|0x3084, 1)` pairs with an cmd-3 ACK.

Checksum template for arbitrary key `K` single read:
`C4 09 00 00 04 K_lo K_hi` + `(-(0xC4+0x09+0x04+K)) & 0xFFFF` (LE).

## 6. Open questions / unverified items

1. **0x42 vs 0x49 role** — resolved from the UI code: `0x42` = battery
   percentage (drives the gauges, props `0x2a`/`0x2b`), `0x49` = charge state
   (drives the charging icon, props `0x2d`/`0x2e`). Both keys carry TX1+TX2 in
   one u16 (low byte/high byte). Still to confirm on hardware: exact charge
   state enum values (the UI only special-cases `0`/`1`) and the battery
   value scale.
2. **Value scale** — assumed 0-100 (%); could be a 0-4 level code.
   Hardware observation (§8): 99 and 100 were reported — consistent with %.
3. **Push requirements** — resolved (§8): in the observed sessions neither the
   RX dongle nor the wired mic pushed `0x42`/`0x49` spontaneously; both answer
   cmd-4 reads without any init handshake.
4. **Linux report-ID behavior** — resolved (§8): unnumbered 64-byte reports;
   writes need no report ID prefix.
5. Second registered-key list (`0x51, 0x21, 0x1b, 0x1f, 0x53`) unresolved.
6. **Sibling PIDs** — resolved: `0x040e` (RX dongle) and `0x0411` (USB-C mic)
   both verified working on hardware; `0x040f`/`0x0410` presumed equivalent.
7. **Lighting registers (§9)** — resolved on hardware: the CLI's cmd-3
   writes (`0x2089`…`0x209d`) were exercised against both mics and behaved as
   documented (LED polarity, brightness, modes, preset and custom colors).
8. Semantics of UI messages `0x05`/`0x06`/`0x07` (wire keys
   `0x207d`/`0x207e`/`0x207f`) and `0x22` unresolved — likely unrelated to
   battery/lighting/EQ (possibly mic gain or loop-panel controls).
9. **Scene/EQ registers (§10)** — resolved on hardware (§8): the mode word,
   the reverb registers and all seven band slots (35 values) can be read back
   with cmd-4 / chunked cmd-6 reads, and written values round-trip unchanged.
   Still to confirm: the audible effect, the exact trigger for mode-word
   bit 15 (SevenEQ), and whether `0x2082`/`0x2083` really drive a reverb mix.
10. **Noise reduction (§11)** — resolved from the app's UI code: the page's "NR"
    widget (toggle + gentle/balanced/aggressive) maps to props `0xd`/`0xe` and
    to the wire keys `0x2084`/`0x2085` (TX1), `0x2884`/`0x2885` (TX2) and
    `0x3084`/`0x3085` (RX), written as cmd-3 pairs. Still to confirm on
    hardware: the polarity (`1` = on), the 0-based level encoding, and what the
    RX copies do. The app's separate "AI denoise" panel is host-side
    (`aiservices.exe`) and only ever writes `0` to these registers.

## 7. Evidence index (VAs)

`Maono Link.exe`:
`hid_init` 0x1400955d0 · `hid_read_timeout` 0x140095ca0 · `hid_write` 0x1400963b0 ·
`hid_open_path` 0x1400958f0 · `hid_enumerate` 0x140094b50 ·
`CHID_Device` vtable 0x268f78 (write +0x48 = 0x14008f3b0, read +0x50 = 0x14008f340,
path +0x60 = 0x14008f150) · `CHID_DeviceManager` vtable 0x269258 ·
`SendData` 0x140093bc0 · `MaonoRead` 0x1400934e0 · `AnalyseRawData` 0x1400920d0 ·
read-thread body 0x14013d6e0 · device-list forwarder 0x140094310 ·
PD200W path fragments `vid_352f&pid_040e&mi_03&col01` (`.rdata` ~0x14028b090).

`PD200XW.dll`:
frame builders 0x180064a30 / 0x180064940 / 0x180064d70 / 0x180064f70 ·
incoming parser 0x1800455e0 · stream splitter 0x180065040 ·
dispatcher 0x1800582f0 · battery 0x180052760 (0x42), charge 0x180053550 (0x49),
level 0x180056040 (0x44) ·
`DataCenter::FetchAllInitPamaras` 0x18004a850 · registered keys 0x18004ff50 ·
send queue 0x18005b660 · UI property handler 0x180018a70 ·
battery bar setter 0x18001a970 · charge icon updater 0x18001aaf0 ·
battery log strings 0x18008c7b0 / 0x18008c7c8 · charge log string 0x18008c7d8 ·
UI log strings 0x180084838 (battery1) / 0x180084850 (battery2) /
0x180084868 (charge1) / 0x180084888 (charge2) ·
battery stylesheets 0x180082650 (green) / 0x1800828d0 (red).

`PD200XW.dll` — scene/EQ (§10): EQ point→register encoder 0x180045c40 ·
multi-pair cmd-3 builder 0x180064b00 · mode write 0x18005c580 (plain) /
0x18005cb40 (with flag + log) · mode read-on-connect 0x18005d1e0 ·
per-device sync 0x180049450 · scene switch `EQ_SwitchScense` 0x180049fe0 ·
scene-default installer 0x180046a80 · reverb-mix writers 0x1800464a0
(`0x2082`) / 0x180046030 (`0x2083`) · selection getter 0x18004c940 ·
gain/Q encoders 0x18006d840 / 0x18006d860 · frame processor that sets the
SevenEQ flag 0x1800455e0 · config save 0x18005dfa0 / 0x18006d620 ·
export/import 0x180048220 / 0x180048830 · DeviceInfo builder 0x18006d190 /
curve export 0x18004ca30.

`PD200XW.dll` — lighting (§9): lighting page ctor 0x180024e10 ·
LED toggle 0x180029dd0 · mode buttons 0x18002a340 · brightness 0x18002a9e0 ·
preset colors 0x180029ba0 · custom color sender 0x18002e870 ·
custom delete/re-layout 0x18001dc80 · "+" color chooser 0x18001e270 ·
per-mic `Analyzer::slot_FromUI` 0x180069480 · `Analyzer::slot_FromUI` data
path 0x1800641b0 · per-device registration 0x180069d30 · RX/TX map insert
0x180068f50 · custom-color count handler 0x180068270 · ×100 encoder
0x18006d860 / ÷100 0x18006d890 / ×10+2000 0x18006d840 · watched-key list
0x180067ba0 · wrapper index/type setters 0x1800640c0 / 0x1800640d0.

`PD200XW.dll` — noise reduction (§11): page ctor 0x1800215e0 (NR widget
`page+0x158`) · toggle slot 0x18002a740 (prop `0xd`) · level slot 0x18002a910
(prop `0xe`) · option strings 0x180086738 / 0x180086740 / 0x180086748 ·
UI→wire writer 0x180069480 · key↔prop map 0x180069d30 / insert 0x180068f50 ·
event clear `FUN_18005be20` · AI-switch param map `FUN_180051ed0` ·
widget class `MaonoControlStandard.dll!MainToggleOptionGroupWidget`
(`changeChooseBtn` RVA 0x94fe0, `changeToggleState` RVA 0x97010, exported).

## 8. Hardware verification notes (2026-10-17)

Live captures with RevLink (`revlink.py`) on Linux `hidraw`, from a machine
where both the wireless RX dongle and the wired USB-C mic were tested:

* **Both devices speak this protocol**: RX dongle `352f:040e` (vendor
  collection on USB interface 3) and wired mic `352f:0411` (vendor collection
  on a different interface).
* **Report framing** on Linux: 64-byte reports, first byte `0xC4`, no report-ID
  byte; 64-byte zero-padded writes are accepted as-is and answered.
* **Device-pushed traffic**: the dongle and the wired mic both stream key
  `0x44` (param `0x09`, ~10 Hz input-level meter; values fluctuated 0-0x15).
  On the single-mic setups, the dongle duplicated the level in both bytes
  (`0x1010`, `0x0808`, …) while the wired mic reported `0x00NN`.
* **Battery fetch**: cmd-4 single-key reads are answered immediately (type
  `0x04` pair responses), no init handshake needed and no spontaneous
  `0x42`/`0x49` pushes observed:
  ```
  request:  C4 09 00 00 04 42 00 ED FE          -> response: C4 0B 00 00 04 42 00 63 00 88 FE
  request:  C4 09 00 00 04 49 00 E6 FE          -> response: C4 0B 00 00 04 49 00 00 00 E4 FE
  ```
  i.e. battery `0x0063` = 99 % (TX1), TX2 = 0 (second mic off/absent), charge
  state `0x0000`.
* **Lighting (§9)**: the CLI's `--light*` register writes were exercised on
  the same hardware and behaved as documented (LED on/off, brightness, mode,
  preset and custom colors).
* **Scene/EQ (§10)**: `--eq-status` reads the mode word, the reverb registers
  and all 35 band registers back without any handshake (cmd-4 for
  `0x2022`/`0x2082`/`0x2083`, chunked cmd-6 type-6 answers for
  `0x2023..0x2045`). Applying `--scene podcast` and `--scene original` and
  reading back returned exactly the written values:
  ```
  before:  mode=0x0000  bands 100/500/1000/2000/10000 Hz @ 0 dB  mix 0/level 1     (preset 0)
  write:   --scene podcast
  after:   mode=0x0100  scene=podcast(1) preset=podcast1(0)  mixture=0  level=0
           band1 100 Hz +2.5 dB Q 0.70 · band2 300 Hz −4.05 dB Q 2.00
           band3 1100 Hz 0 dB Q 0.70 · band4 4880 Hz −3 dB Q 5.00
           band5 10000 Hz 0 dB Q 0.70 high-shelf · HPF 20 Hz · LPF 20 kHz
  ```
  The values found before the first write (mode `0x0000`, bands
  100/500/1000/2000/10000 Hz flat, `0x2083` = 1) do **not** match the app's
  embedded Original preset (125/250/500/1000/2000 Hz): the device keeps its
  own persisted curve until the host overwrites it.
* Every captured frame satisfied the checksum rule of §3.1.

## 9. Lighting / RGB control (from the UI code)

The PD200W's LED ring is controlled by the same key/value protocol, using
per-mic key spaces (`0x20xx` = TX1, `0x28xx` = TX2). The Windows app's
lighting page emits UI message ids which the per-mic analyzer maps to wire
keys and sends as cmd-0x03 write pairs
(`FUN_180069480` → `FUN_180064a30`, §3.2). The register map below comes from
the UI lambdas and the analyzer's msg↔key registration; it has since been
exercised on hardware through the CLI (see §8).

### 9.1 Register map

| Offset | Key (TX1) | UI msg | Meaning | Values |
|---|---|---|---|---|
| `+0x89` | `0x2089` | `0x10` | LED ring on/off | `1` = on, `0` = off |
| `+0x8a` | `0x208a` | `0x11` | Brightness | `1..100` |
| `+0x8b` | `0x208b` | `0x12` | Effect mode | `0` = fixed, `2` = breathe, `1` = loop |
| `+0x8c` | `0x208c` | `0x13` | Selected color | `0..7` = presets, `8..12` = custom slots 1..5 |
| `+0x8d` | `0x208d` | `0x14` | registered key, no UI control found | `?` |
| `+0x8e` | `0x208e` | `0x15` | Number of stored custom colors | `0..5` |
| `+0x8f..0x91` | `0x208f..0x2091` | `0x38..0x3a` | Custom color 1: H, S, V | see §9.2 |
| `+0x92..0x94` | `0x2092..0x2094` | `0x3b..0x3d` | Custom color 2: H, S, V | |
| `+0x95..0x97` | `0x2095..0x2097` | `0x3e..0x40` | Custom color 3: H, S, V | |
| `+0x98..0x9a` | `0x2098..0x209a` | `0x41..0x43` | Custom color 4: H, S, V | |
| `+0x9b..0x9d` | `0x209b..0x209d` | `0x44..0x46` | Custom color 5: H, S, V | |

Preset color index order (same order as the app's color buttons):
`0` white, `1` red, `2` orange, `3` yellow, `4` green, `5` cyan, `6` blue,
`7` magenta.

Mode values are *not* the button order: the mode button group ids are
`0` = 固定 (fixed), `1` = 呼吸 (breathe), `2` = 循环 (loop), and the click
handler remaps them to wire values `0`, `2`, `1` respectively
(`FUN_18002a340` — id 1 → Breathe, id 2 → Loop).

The lighting page constructor wires up (`FUN_180024e10`):

* LED toggle (`FUN_180029dd0`): checked state → msg `0x10` (`1`/`0`);
  when unchecked the page shows an "off" placeholder label (`page+0x38`).
* Brightness slider (`FUN_18002a9e0`): slider value `1..100` → msg `0x11`.
* Mode buttons (`FUN_18002a340`): button id → msg `0x12` as above; Loop also
  shows an extra panel (QLabel at `page+0x40`).
* Preset color buttons (`FUN_180029ba0`): button objectName `0..7` →
  msg `0x13`; the chosen `QColor` is cached at `page+0x188`.
* Custom color buttons (`FUN_18001dc80`): selection sends msg `0x13` with
  `8 + slot − 1`; adding/deleting a color re-sends the current selection and
  the new count via msg `0x15`.

### 9.2 Custom color values

Each custom color is stored as three consecutive values (H, S, V). When the
user picks a color in the chooser, `FUN_18002e870` sends three cmd-3 pairs
(UI message ids `0x38`/`0x39`/`0x3a`, remapped per slot by tables
`DAT_18090b3c8`/`DAT_18090b3d0`):

* H comes from `QColor::hue()` (int degrees `0..359`),
* S comes from `QColor::saturationF()`, V from `QColor::valueF()`
  (floats `0..1`).

All fifteen custom-color keys are registered in the analyzer's "double,
×100" value list (`analyzer+0x48`, encoder `FUN_18006d860`), so every value
is sent as `(u16)(toDouble(v) × 100)`; the read-back path divides by 100
(`FUN_18006d890`):

* **H = hue × 100** (`0..35900`), i.e. centi-degrees,
* **S = round(saturationF × 100)** → `0..100`,
* **V = round(valueF × 100)** → `0..100`.

The device reports its stored custom-color count on key `0x208e`; the host
then answers with a cmd-6 **block read** of `count × 3` values starting at
`0x208f` (`FUN_180068270`, e.g. `C4 0B 00 00 06 8F 20 0F 00 6D FE` for five
colors) and updates the UI from the streamed type-6 values.

### 9.3 Status read-back

The four main registers plus the custom-color count are part of the app's
connect-time read lists (`cmd4 readList 0x2089 0x208b 0x208a 0x208c` and
`… 0x208e`, §4), so they can be probed with the same single-key cmd-0x04
reads the battery CLI uses, e.g.:

```
request:  C4 09 00 00 04 89 20 ...   (LED on/off)
request:  C4 09 00 00 04 8B 20 ...   (mode)
```

`revlink.py --light-status` probes `0x2089`, `0x208a`, `0x208b`,
`0x208c` and `0x208e` this way.

### 9.4 CLI mapping

| CLI option | Wire writes |
|---|---|
| `--light on\|off` | `+0x89 = 1\|0` |
| `--light-brightness N` | `+0x8a = N` (N = 1..100) |
| `--light-mode fixed\|breathe\|loop` | `+0x8b = 0\|2\|1` |
| `--light-color NAME\|0-7` | `+0x8c = index` |
| `--light-color #RRGGBB --light-slot N` | H,S,V to `+0x8f + 3(N−1)`… then `+0x8c = 7 + N` |
| `--light-hsv H,S,V --light-slot N` | raw H,S,V to the slot (advanced; no selection) |
| `--light-count N` | `+0x8e = N` (advanced; destructive for existing colors) |
| `--channel 1\|2\|both` | selects the `0x20xx` / `0x28xx` / both spaces |

Writes are spaced ~50 ms apart (the app queues frames on a ~100 ms timer);
each write is an 11-byte cmd-3 frame, e.g. LED on ⇒
`C4 0B 00 00 03 89 20 01 00 84 FE`.

## 10. Scene presets and PEQ (from the EQ/UI code)

The four scene buttons (场景 — 原声 Original / 播客 Podcast / 游戏 Game /
唱歌 Sing) each expand to a list of sound-config entries (我的场景) driven by
one EQ engine. Applying an entry writes the seven-point PEQ, sets the
reverb-mix registers and finally selects the scene/preset with the EQ mode
word. All of it uses the cmd-3 write path; each band is one multi-pair frame.

**[reconstructed from PD200XW.dll; verified on hardware (see §8)]**

### 10.1 Register map

| Offset | Key (TX1 / TX2) | Meaning | Values |
|---|---|---|---|
| `+0x22` | `0x2022` / `0x2822` | EQ mode word | `scene << 8 \| preset index`; bit 15 = "SevenEQ" custom-curve flag |
| `+0x23..+0x27` | `0x2023…` | peaking band 1: 5 registers | see §10.2 |
| `+0x28..+0x2c` | `0x2028…` | peaking band 2 | |
| `+0x2d..+0x31` | `0x202d…` | peaking band 3 | |
| `+0x32..+0x36` | `0x2032…` | peaking band 4 | |
| `+0x37..+0x3b` | `0x2037…` | peaking band 5 | |
| `+0x3c..+0x40` | `0x203c…` | high-pass filter slot | |
| `+0x41..+0x45` | `0x2041…` | low-pass filter slot | |
| `+0x82` | `0x2082` | reverb mix on/off (`blnMixture` item field) | `0`/`1` |
| `+0x83` | `0x2083` | reverb level (`level` item field) | `0..` (Sing presets: 5 / 1) |

Scene ids: `0` 原声 Original, `1` 播客 Podcast, `2` 游戏 Game, `3` 唱歌 Sing;
the preset index is the 0-based position inside the scene's config list
(§10.3). TX2 uses the same offsets in the `0x28xx` space.

### 10.2 Band register encoding

Each of the seven slots carries five consecutive u16 registers (encoder
`FUN_180045c40`, called once per EQ point; `base = (dev ? 0x2823 : 0x2023) +
slot × 5`):

| Register | Value |
|---|---|
| `+0` | slot enabled: the app always writes `1` |
| `+1` | device filter type: JSON/AudioEQS type `0` peak → `1`, `1` low-shelf → `0`, `2` high-shelf → `2`, `3` LPF → `3`, `4` HPF → `5` |
| `+2` | frequency in Hz: `(short)(int)freq` |
| `+3` | gain: `(int)(gain × 10 + 2000)` (`FUN_18006d840`; `2000` = 0 dB) — forced to `2000` for the HPF/LPF slots and for gains below −12 dB |
| `+4` | Q: `(int)(Q × 100)` (`FUN_18006d860`) |

The JSON point type also decides the slot: peaking points fill slots 0–4 in
order, a type-4 (HPF) point goes to slot 5, a type-3 (LPF) point to slot 6.

One slot = one multi-pair cmd-3 frame (`FUN_180064b00`, length `7 + 4×5`), so
a full curve is seven frames per mic, e.g. band 1 of Original:

```
C4 1B 00 00 03 23 20 01 00 24 20 01 00 25 20 7D 00 26 20 D0 07 27 20 64 00 ...
              +0/1    +1/1    +2/125      +3/2000     +4/100
```

### 10.3 Built-in presets ("我的场景")

The default entries embedded in `PD200XW.dll` (`FUN_180046a80`). Each curve
is the app's `curve_contains` JSON: five points plus HPF and LPF. `mixture`/
`level` are the wrapper fields the app writes to `+0x82`/`+0x83` when the
entry is selected (`FUN_180049450`; its scene-3 special case sets `1/5`).

| Scene | Preset (index) | curve_name | mixture/level | Notes |
|---|---|---|---|---|
| original (0) | 0 原声 | Original | 0/0 | flat, HPF/LPF bypassed |
| podcast (1) | 0 播客1 | Podcast1 | 0/0 | +2.5 dB @100 Hz, −4 dB @300 Hz |
| podcast (1) | 1 播客2 | Podcast2 | 0/0 | color `255\|93\|239` |
| game (2) | 0 游戏1 | Game1 | 0/0 | low-shelf @60 Hz, −7.1 dB @10 kHz |
| game (2) | 1 游戏2 | Game2 | 0/0 | low-shelf −12 dB @70 Hz |
| sing (3) | 0 流行 | Pop | 1/5 | HPF @63.3 Hz, reverb level 5 |
| sing (3) | 1 民谣 | Folk | 1/1 | HPF @40.5 Hz, reverb level 1 |

The full JSON of every preset is embedded in `PD200XW.dll` (in English and
Chinese name variants; the CLI carries the English names, e.g.
`--eq-preset folk`).

### 10.4 Scene switch / apply sequence

`FUN_18002a4a0` (scene button) → `FUN_180049fe0` (`EQ_SwitchScense`) stores
the current `(scene, index)` per device, then `FUN_180049450` syncs it: the
band frames are produced by the AudioEQS point→register encoder
(`FUN_180045c40`) and queued as multi-pair cmd-3 frames (`FUN_180064b00`),
the reverb mix is written, then `FUN_18005c580` writes the mode word
(`FUN_18005cb40` is the logging variant that can set the SevenEQ flag).
`FUN_180046a80` installs the scene's default entries when the list is empty;
a 60 ms timer (`FUN_180029fc0`) refreshes the UI afterwards.

On connect the app reads `0x2022`/`0x2822` once (`FUN_18005d1e0`) to restore
the active scene; it never reads the band registers back — the host always
pushes all seven slots.

The CLI replicates the write order per mic: (1) seven band frames, (2)
mixture, (3) level, (4) mode word. `--eq-flag 1` sets bit 15 — the frame
processor `FUN_1800455e0` sets that flag when EQ band frames are sent, i.e.
when the working curve has been customised.

### 10.5 Sound profiles (.cfg)

导出 writes and 导入配置 reads a small JSON file (dialog filter
`配置文件 (*.cfg)`; writer `FUN_18006d190`, builder `FUN_18004ca30`, export
`FUN_180048220`, import `FUN_180048830`):

```json
{
    "InfoName": "Pop",
    "blnDefault": true,
    "blnMixture": true,
    "curve_contains": "{ ...curve JSON... }",
    "device_name": "PD200XW",
    "level": 5
}
```

`curve_contains` is the curve JSON as a *string*; its `HPF`, `LPF` and
`map_points` fields are themselves JSON strings (Qt `QJsonDocument` output:
keys sorted, 4-space indent):

```json
{
    "HPF": "{\n    \"Gain\": -1,\n    \"Q\": 1,\n    \"blnBypass\": false,\n    \"frequence\": 63.26942754238026,\n    \"type\": 4\n}",
    "LPF": "...",
    "blnBypass": false,
    "blnDefault": true,
    "blnVisible": true,
    "color": "246|180|54",
    "curve_name": "Pop",
    "map_points": ["...", "...", "...", "...", "..."],
    "sample_rate": 48000,
    "width": 2
}
```

Point fields: `frequence` (Hz), `Gain` (dB), `Q`, `type` (`0` peak, `1`
low-shelf, `2` high-shelf, `3` LPF, `4` HPF), `blnBypass`. Import validation
strings: `Invalid JSON format for DeviceInfo - not an object`,
`Missing required fields in DeviceInfo JSON`,
`请检查并确保您导入的配置文件适用于当前麦克风型号` (foreign `device_name`).

`revlink.py --eq-export` writes this format for a built-in preset
(`--eq-preset`/`--scene`) or a custom curve built from
`--eq-band`/`--eq-hpf`/`--eq-lpf`; `--eq-import` parses it and applies the
curve registers plus `0x2082`/`0x2083`.

### 10.6 CLI mapping

| CLI option | Wire writes |
|---|---|
| `--scene NAME[:N]` | 7 band frames + `+0x82`/`+0x83` + `+0x22 = scene<<8 \| N` per mic |
| `--eq-flag 0\|1` | sets/clears bit 15 of the mode word written by `--scene` |
| `--eq-preset NAME` | 7 band frames + `+0x82`/`+0x83` (mode word untouched) |
| `--eq-band N FREQ GAIN Q [TYPE]` | one 5-register frame for slot N−1 |
| `--eq-hpf FREQ[:Q]` / `off` | slot-5 frame (type 5); `off` = neutral 20 Hz |
| `--eq-lpf FREQ[:Q]` / `off` | slot-6 frame (type 3); `off` = neutral 20 kHz |
| `--eq-reg KEY=VALUE` | raw single-pair write (no channel remapping) |
| `--eq-status` | cmd-4 reads of `+0x22`/`+0x82`/`+0x83` + chunked cmd-6 reads of `+0x23..+0x45` (12 values per request; type-6 answers) |
| `--eq-import FILE` / `--eq-export FILE` | apply / save a `.cfg` profile |

`--channel 1|2|both` selects the `0x20xx`/`0x28xx` key spaces as for
lighting. The band block read is chunked because a type-6 answer must fit one
64-byte report (11 + 2×count bytes ⇒ ≤26 values).

## 11. Noise reduction — the "NR" control

Besides the app's **host-side AI denoise** (a Windows service feature, §11.3),
the mic has a **device-side noise canceller with three stages** — the app's
product page exposes it as a toggle plus three option buttons.

### 11.1 UI wiring

* The page ctor (`FUN_1800215e0`) configures a
  `MAONOCONTROL::MainToggleOptionGroupWidget` (`page+0x158`) with the label `NR`
  and three option strings, translated via `QMetaObject::tr` from UTF-8 `.rdata`:

  | Index | String | Address | Meaning |
  |---|---|---|---|
  | 0 | 轻柔 | `0x180086738` | gentle |
  | 1 | 均衡 | `0x180086740` | balanced |
  | 2 | 激进 | `0x180086748` | aggressive |

  The neighbouring strings (`0x180086720`, `0x180086730`) belong to the page's
  "Gain and Volume" slider (`增益和音量`, values `0`/`20`) that follows in the
  same ctor.
* The widget's signals are captured by page lambdas that build a one-entry
  parameter map and emit it to the `DataCenter`:
  `sig_ToggleState_Changed` → prop `0xd` (u32 bool, `0x18002a740`) and
  `sig_buttonChoose_Changed` → prop `0xe` (int option index, `0x18002a910`).
* The generic UI→wire writer (`FUN_180069480`, the slot analyzer) looks the
  property id up in the per-slot key↔property map (`FUN_180069d30`, insert
  `FUN_180068f50`) and sends a **cmd-3 write of `(wire key, toInt(value))`**.
  For the NR properties no double/string re-encoding applies, so the value goes
  out unchanged.

### 11.2 Register map

| Register | Offset | TX1 | TX2 | RX (dongle) | Prop | Meaning |
|---|---|---|---|---|---|---|
| NR state | `+0x84` | `0x2084` | `0x2884` | `0x3084` | `0xd` | `1` = noise reduction on, `0` = off |
| NR level | `+0x85` | `0x2085` | `0x2885` | `0x3085` | `0xe` | `0` / `1` / `2` = gentle / balanced / aggressive |

* The property ids are reused per slot: the map is (re)built for the currently
  selected device (TX1/TX2/RX), so the one page widget drives whichever slot is
  active. All three slots carry NR registers.
* Examples (cmd-3 single pairs):

  ```
  NR on (TX1):      C4 0B 00 00 03 84 20 01 00 89 FE
  level gentle:     C4 0B 00 00 03 85 20 00 00 89 FE
  NR on (TX2):      C4 0B 00 00 03 84 28 01 00 81 FE
  ```
* At connect the app reads both registers back (`cmd4 readList 0x2084 0x2085 …`,
  §4) and pushes them into the widget via `changeToggleState` /
  `changeChooseBtn` (`FUN_18002c960`, apply types `0xd`/`0xe`).
* The level is **0-based**: the widget uses the device value as a direct
  0-based index into its option list and the write path sends the chosen index
  unchanged, so device value == 轻柔/均衡/激进 index. **[not hardware-verified]**

### 11.3 Interaction with the app's host-side "AI denoise"

The app (not the mic) also offers an AI panel — AI denoise, echo cancellation,
voice change and monitoring — implemented by a Windows service
(`aiservices.exe`, 77 MB, output device "Maono AI Microphone"). Per-product
switch keys such as `PD200WNoiseSwitch` are exchanged with the product module as
`AIDenoiseSwitch` / `AIVoiceSwitch`.

While those switches are on, the module keeps the **device** NR off:

* `DataCenter::UpdateParamMap` (`FUN_180051ed0`) writes `0x2084 = 0` /
  `0x2884 = 0` / `0x3084 = 0` through `FUN_18005be20` whenever the AI flags
  (`+0x69`/`+0x68`) are set — both from the window-complete path and from init
  (§4). It never writes `1`.
* The parser (`FUN_1800455e0`) answers an incoming `(0x2084|0x2884|0x3084, 1)`
  pair with a cmd-3 ACK that writes the same key = **0**, but only when those
  AI flags are set — i.e. a device-side "NR changed" notification is cleared
  while host AI processing is active.

So the `1` values on these registers come from the page widget (and from the
device itself); the AI panel feature is host-side and not reachable over this
HID protocol.

### 11.4 CLI mapping

| CLI option | Wire writes |
|---|---|
| `--noise on\|off` | `+0x84` = 1 / 0 per mic |
| `--noise-level gentle\|balanced\|aggressive` (aliases `soft`/`mid`/`strong`, or raw `0-2`) | `+0x85` = 0 / 1 / 2 per mic |
| `--noise-status` | cmd-4 single reads of `+0x84` and `+0x85` per mic |
| `--channel 1\|2\|both` | selects the `0x20xx`/`0x28xx` key space |
| `--dry-run` | prints the frames without opening the device |

The RX slot's own copies (`0x3084`/`0x3085`) are not exposed: the CLI only
speaks the TX key spaces, like lighting and EQ. Whether the RX registers mirror
the mics or hold a dongle-side NR setting is unresolved. **[unknown]**

**[unverified]** — the polarity (`1` = on), the 0-based level encoding and the
wired mic's behaviour are taken from the app's UI code but have not been
confirmed on hardware yet; `--noise-status` is the quickest way to check.
