# ESP32 WiFi Sniffer — Wireshark extcap

A single self-contained executable that makes the ESP32 WiFi sniffer show up as a
native **capture interface** in Wireshark, with a **toolbar** for changing
channel / frame types / MAC / RSSI *live during capture*, and **automatic
time synchronization**.

It does **not** change the firmware. It reuses the device's existing HTTP API
(`/api/filter`, `/api/time`) and its TCP pcap stream (port 19000). The classic
`wireshark -i TCP@<ip>:19000 -k` method keeps working unchanged.

See [DESIGN.md](DESIGN.md) for the full design and the v1/v2 scope.

## Build

Requires the [Go toolchain](https://go.dev/dl/) (a single installer; no runtime
is needed to *run* the result — it produces one static `.exe`).

From this `extcap/` directory:

```bash
# Native build
go build -o esp32wifi.exe .

# Or cross-compile a Windows binary from macOS/Linux
GOOS=windows GOARCH=amd64 go build -o esp32wifi.exe .
```

On Windows you can also run `./build.ps1` (add `-Install` to copy it straight
into Wireshark's extcap folder).

## Building from an IDE

### VS Code

A `.vscode/tasks.json` at the project root defines two tasks (needs the
[Go extension](https://marketplace.visualstudio.com/items?itemName=golang.Go)):

- **extcap: build** — `go build`
- **extcap: build & install** — build + copy into `%APPDATA%\Wireshark\extcap`
  (the default build task)

Run them with **Terminal → Run Build Task…** (`Ctrl+Shift+B`).

### Espressif IDE / Eclipse (External Tools)

Eclipse can't compile Go itself, but it can drive the build script:

1. **Run → External Tools → External Tools Configurations…**
2. New **Program**:
   - **Location:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
   - **Working Directory:** the `extcap` folder (e.g. `${workspace_loc}/extcap`)
   - **Arguments:** `-NoProfile -ExecutionPolicy Bypass -File build.ps1 -Install`
3. **Apply**, then **Run**. The build output appears in the Eclipse console.

(To build without installing, drop `-Install`, or set Location to
`C:\Program Files\Go\bin\go.exe` with Arguments `build -o esp32wifi.exe .`.)

## Install

1. In Wireshark open **Help → About Wireshark → Folders** and note the
   **"Personal Extcap path"** (typically `%APPDATA%\Wireshark\extcap\`).
2. Copy `esp32wifi.exe` into that folder.
3. Restart Wireshark, or **Capture → Refresh Interfaces** (F5).

**ESP32 WiFi Sniffer** now appears in the interface list.

## Use

1. Click the gear next to **ESP32 WiFi Sniffer** to set the **Sniffer address**
   (default `192.168.5.1`) and initial channel / MAC / RSSI.
2. Start the capture.
3. Show the toolbar via **View → Interface Toolbars → ESP32 WiFi Sniffer** to
   change channel, frame types, MAC and RSSI on the fly. Changes are relayed to
   the device immediately.

Host time is pushed to the device at start and every *Time sync interval*
seconds (default 60), so packet timestamps are correct without opening the web
page.

## Command line

Wireshark drives the executable, but you can launch it directly too:

```bash
wireshark --extcap-interface esp32wifi -i esp32wifi -k
```

For debugging, the extcap protocol calls also work standalone:

```bash
./esp32wifi.exe --extcap-interfaces
./esp32wifi.exe --extcap-dlts --extcap-interface esp32wifi
./esp32wifi.exe --extcap-config --extcap-interface esp32wifi
```

## Debugging

The binary is silent by default. Tick **Debug log** in the interface's options
(Advanced) to write `esp32wifi-extcap.log` next to the exe. It records the argv
Wireshark passed, pipe open results, every control message and HTTP call, and a
throughput line every 5 s while capturing.

## Performance

The extcap is a plain byte pump: it copies the pcap stream from the device's TCP
port straight to Wireshark's fifo with no per-packet processing (control and
time-sync run on a separate goroutine). The fifo is a local named pipe with
far more capacity than the ESP can push over USB-NCM, so it is not the
bottleneck — the ceiling is the ESP's WiFi capture + USB-NCM link, the same
limit as the classic `TCP@` method. Backpressure is safe: if Wireshark can't
keep up, the fifo write blocks, TCP flow control kicks in, and the ESP drops at
its rx layer; nothing is buffered without bound in the exe. Enable **Debug log**
to see the actual throughput.

## Notes / limitations (v1)

- One capture consumer at a time: the firmware serves a single TCP client on
  :19000, so you can't run the classic `TCP@` method and extcap simultaneously.
  The web page (:80) works alongside either.
- Single device. Multiple sniffers and mDNS auto-discovery are planned for v2.
