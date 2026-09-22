# Design: Wireshark extcap integration for the ESP32 WiFi Sniffer

## Goal & principle

Add a **desktop extcap binary** that makes the ESP32 sniffer appear as a native
Wireshark interface with a **toolbar** replicating the web page's controls
(channel / frame / MAC / RSSI) and **automatic time-sync**.

This is purely **additive**: the firmware is **not touched**, and today's
`wireshark -i TCP@<ip> -k` path keeps working unchanged.

## Two launch methods (same device)

| Method | Command | Control plane | Time sync |
|---|---|---|---|
| **A — today (unchanged)** | `wireshark -i TCP@192.168.5.1:19000 -k` | web page | manual (open browser) |
| **B — extcap (new)** | select **"ESP32 WiFi Sniffer"** in the GUI, or `wireshark --extcap-interface esp32wifi -i esp32wifi -k` | **Wireshark toolbar** (web page still works too) | **automatic** (binary pushes host clock) |

## Architecture

```
                         +----------------- PC ------------------+
 Wireshark  --fifo(pcap)--+  extcap binary (single static .exe)  |
   |  toolbar changes ---->|   * data pump : TCP :19000 -> fifo   |
   |  (control pipe)       |   * control   : toolbar -> HTTP      |--HTTP /api/filter-->+
   +-----------------------|   * timesync  : host clock -> HTTP   |--HTTP /api/time---->|
                           +--------------------------------------+                     |
                                                                        ESP32 (unchanged)
                                                              :19000 pcap stream <-------+
                                                              :80 web page (still works)
```

The binary is a **thin relay**. It reuses the firmware's existing endpoints and
stream; there are no new firmware endpoints:

- **Data:** connect to `:19000` → firmware auto-starts capture on `accept()`
  (`main/main.c` `on_socket_accept_handler`) and streams classic pcap
  (global header + records), DLT **127** radiotap (`components/capture_lib/capture_lib.c`).
- **Control:** `GET /api/filter?channel=|frame=|rssi=|macFilterAddress=`
  (`main/config_http_server.c` `filter_get_handler`) — applied live during capture.
- **Time:** `GET /api/time?value=<epoch_ms>` → `sniffer_set_time()`
  (`main/config_http_server.c` `timer_get_handler`). The ESP32 has no RTC, so the
  binary pushes host wall-clock time.

## extcap binary (Go → one static `.exe`)

**Phases Wireshark drives:**

- `--extcap-interfaces` → advertise interface `esp32wifi` and declare the toolbar controls.
- `--extcap-dlts` → `DLT 127 (IEEE802_11_RADIO)` (must match firmware).
- `--extcap-config` → the pre-capture dialog args.
- `--capture --fifo … --extcap-control-in … --extcap-control-out … <args>` → run.

**Pre-capture config args:** `address` (string, default `192.168.5.1`),
`dataport` (int, default `19000`, advanced), `channel`, `mac`, `rssi`,
`timesync` interval (int sec, default `60`, advanced).

**Toolbar controls (live, via control pipe):**

| # | Control | Type | Relayed call |
|---|---|---|---|
| 0 | Channel | `selector` (1–13) | `/api/filter?channel=N` |
| 1–4 | mgmt / data / ctrl / misc | `boolean` | `/api/filter?frame=<csv of enabled>` |
| 5 | MAC filter | `string` | `/api/filter?macFilterAddress=…` |
| 6 | RSSI | `string` (numeric) | `/api/filter?rssi=…` |
| 7 | Apply | `button` | re-flush MAC + RSSI |
| 8 | Log | `button` role=logger | status / errors |

**Runtime loops:**

1. **data pump** — copy `:19000` bytes → fifo verbatim.
2. **control reader** — parse control-pipe frames, HTTP GET to `/api/filter`.
3. **time-sync** — push `epoch_ms` at start and every `timesync` seconds.

## Control-pipe wire format (from Wireshark's `extcap_example.py`)

Frame: `'T'` (0x54) sync byte, 1 reserved byte (0x00), 2-byte big-endian length
(counts `arg` + `command` + payload), then `arg` (control number), `command`,
UTF-8 payload. Quit frame uses sync byte `'Q'` (0x51).

Commands: `INITIALIZED=0 SET=1 ADD=2 REMOVE=3 ENABLE=4 DISABLE=5 STATUSBAR=6
INFORMATION=7 WARNING=8 ERROR=9`.

Inbound (Wireshark → extcap) on a user change: `SET` with payload = boolean
single byte (0/non-zero), selector/string value as UTF-8, or empty for a button.

## v1 vs v2 scope

- **v1 (this cut):** single device via a manual `address` field; toolbar + config
  + time-sync; Windows `.exe`.
- **v2:** **mDNS auto-discovery** (firmware already advertises over `_http._tcp`,
  `main/main.c` `init_mdns`) listing each detected sniffer as its own interface,
  enabling **multiple sniffers** at once.

## Deployment

Copy the one binary into Wireshark's extcap dir
(*Help → About Wireshark → Folders → "Personal Extcap path"*, typically
`%APPDATA%\Wireshark\extcap\`). No runtime, no interpreter. The Windows binary
cross-compiles from any OS.

## Known risks / to verify while building

- **Named-pipe I/O on Windows:** the `--fifo` and control pipes are Windows named
  pipes; verify Go `os.OpenFile` opens them cleanly against the target Wireshark.
- **Single-consumer socket:** firmware handles one `:19000` client (`listen(...,1)`,
  single global `_sock`), so Method A and extcap cannot capture simultaneously
  (fine — one at a time). The web page (:80) is independent and coexists.
- **Filter race:** the web page and the toolbar both write `/api/filter` —
  last-writer-wins, harmless.
- **Time units:** `/api/time?value=` expects **epoch milliseconds**
  (matches `sniffer_get_time`).
- **All-frames-off edge case:** firmware ignores `frame=` when the mask resolves
  to 0, so unchecking every frame box keeps the previous filter.
