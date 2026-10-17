# Maono PD200W — USB HID protocol (reverse-engineered)

Findings from static analysis of **Maono Link 4.0.88** (vendor installer
`Maono Link_V4.0.88_0918.exe`) and its extracted components.

Findings are reconstructed from the shipped binaries; §8 records what live
hardware testing has since confirmed. Statements that could not be verified
against hardware are marked **[unverified]**.

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
| `0x03` | ACK / reply | n × (key u16 LE, value u16 LE) at `[5+4i]` | `7 + 4n` |
| `0x04` | Read | n × key u16 LE at `[5+2i]` | `7 + 2n` |
| `0x06` | Write | n × (key u16 LE, value u16 LE) at `[5+4i]` | `7 + 4n` |

Special cases:

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
  frames with type `0x02`/`0x03`/`0x04` to the product module. Type `0x06`
  frames are only understood by the DLL parser — in the app's HID path they
  appear to be unused (device emits pair frames).
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
| `0x2084` / `0x2884` / `0x3084` | parser special-case | when value == 1, DLL replies with an ACK frame |
| `0x41` | `FUN_180053d70` | (used in mode-1 init; likely also a "ready"/state key) |
| `0x44` | `FUN_180056040` | ~10 Hz streamed meter value: **audio input level** (drives `MainLevelWidget`, the VU meter; strings `refreshLevelWidget`, `-48dB`, `0dB`); stored as param `0x09` with `low byte = TX1, high byte = TX2` |
| `0x45, 0x46, 0x47` | various | device status/info keys (not battery) |
| `0x2022` / `0x2822` | inline | TX channel/state handling |

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

TX1 block (`0x20xx`):

```
if(flag68||flag69) ack(0x2084, 0)
if(flag67)         ack(0x20af, 2)
readList 0x207d 0x207e 0x207f
readList 0x2084 0x2085 0x208e
readList 0x2089 0x208b 0x208a 0x208c
write 0x1e = 0x10
read 0x20af
write 0x2069 = 0x0a
```

TX2 block (`0x28xx`, only when a TX2 slot exists):

```
ack(0x2884, 0); ack(0x28af, 2)
readList 0x287d 0x287e 0x287f
readList 0x2884 0x2885 0x288e
readList 0x2889 0x288b 0x288a 0x288c
write 0x2e = 0x10
read 0x28af
write 0x2869 = 0x0a
```

RX block (`0x30xx`, when an RX slot exists):

```
if(flag67) ack(0x3088, 2)
readList 0x307d (slot0==RX only) 0x3090 (slot1==RX only) 0x307e 0x307f
readList 0x3084 0x3085
read 0x3091
readList 0x3093 0x3094     (twice)
read 0x3088
read 0x3086
readList 0x3082 0x3083
```

Common tail: `read 0x46`, one cmd-6 builder call (args unresolved), then a
per-device loop calling `FUN_1800599b0` for each entry in the device map
(`DataCenter+0x1b8`; entry types: 1 = RX, 2/3 = TX).

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

## 8. Hardware verification notes (2026-10-17)

Live captures with the project's `maono_battery.py` on Linux `hidraw`, from a
machine where both the wireless RX dongle and the wired USB-C mic were tested:

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
* Every captured frame satisfied the checksum rule of §3.1.
