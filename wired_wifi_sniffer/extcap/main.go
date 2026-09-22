// Command esp32wifi is a Wireshark extcap that exposes the ESP32 WiFi sniffer as
// a native capture interface with a live control toolbar.
//
// It is a thin desktop relay over the firmware's EXISTING interfaces:
//   - reads the classic-pcap stream from the sniffer's TCP port (default 19000)
//     and copies it to Wireshark's fifo;
//   - relays toolbar/config changes to GET /api/filter (channel/frame/mac/rssi);
//   - pushes host wall-clock time to GET /api/time (the ESP32 has no RTC).
//
// The firmware is not modified. The legacy `wireshark -i TCP@<ip>:19000 -k`
// path keeps working independently.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	ifaceValue   = "esp32wifi"
	ifaceDisplay = "ESP32 WiFi Sniffer"
	helpURL      = "https://github.com/emaayan/wired_wifi_sniffer"
	linkTypeDLT  = 127 // DLT_IEEE802_11_RADIO (radiotap) — matches capture_lib.c
	maxChannel   = 13
)

// Toolbar control numbers (must match the `control {number=N}` lines emitted by
// printInterfaces).
const (
	ctlChannel = 0
	ctlAll     = 1
	ctlMgmt    = 2
	ctlData    = 3
	ctlCtrl    = 4
	ctlMisc    = 5
	ctlMpdu    = 6
	ctlAmpdu   = 7
	ctlFcs     = 8
	ctlMAC     = 9
	ctlRSSI    = 10
	ctlLogger  = 11
	// No submit button: Wireshark gives every string control its own inline
	// submit arrow (and Enter), so the MAC field submits itself — like the web
	// UI's "OK". A separate button would be redundant and, since Wireshark
	// renders all buttons at the far end of the toolbar, couldn't sit next to
	// the MAC field anyway.
)

// frameControls lists the firmware frame-type tokens, their toolbar control
// numbers, display labels and default state — in the same order the web UI
// lists them (files/index.html). "all" is a meta-toggle that, when set, selects
// every token and disables the individual boxes.
var frameControls = []struct {
	token   string
	display string
	ctl     int
	def     bool
}{
	{"all", "All", ctlAll, false},
	{"mgmt", "Mgmt", ctlMgmt, true},
	{"data", "Data", ctlData, true},
	{"ctrl", "Ctrl", ctlCtrl, true},
	{"misc", "Misc", ctlMisc, true},
	{"mpdu", "MPDU", ctlMpdu, false},
	{"ampdu", "AMPDU", ctlAmpdu, false},
	{"fcsfail", "FCS Fail", ctlFcs, false},
}

// rssiPresets are the RSSI threshold options, matching the web UI's radio group.
var rssiPresets = []int{-50, -70, -90}

// macValidation returns the MAC-filter validation regex: 0–6 hex pairs (even
// length, max 12 chars, empty allowed to clear) — the same constraint as the
// web UI's pattern="(?:[0-9A-Fa-f]{2}){1,6}". It is built brace-free on purpose:
// Wireshark's control parser treats { and } as delimiters, so a {1,6}
// quantifier in the value would corrupt the control line.
func macValidation() string {
	const hexPair = "[0-9A-Fa-f][0-9A-Fa-f]"
	expr := ""
	for i := 0; i < 6; i++ {
		expr = "(" + hexPair + expr + ")?"
	}
	return "^" + expr + "$"
}

func frameTokenByCtl(ctl byte) (string, bool) {
	for _, fc := range frameControls {
		if byte(fc.ctl) == ctl {
			return fc.token, true
		}
	}
	return "", false
}

func defaultFrames() map[string]bool {
	m := make(map[string]bool, len(frameControls))
	for _, fc := range frameControls {
		m[fc.token] = fc.def
	}
	return m
}

// frameTokens mirrors the web UI (index.html filterFrame): if "all" is set,
// every token is sent; otherwise only the individually-enabled ones.
func frameTokens(f map[string]bool) []string {
	all := f["all"]
	var parts []string
	for _, fc := range frameControls {
		if all || f[fc.token] {
			parts = append(parts, fc.token)
		}
	}
	return parts
}

// dbg is the debug log, enabled only with --debug. It writes to a file because
// under Wireshark our stderr is invisible. Safe to call when disabled (Discard).
var dbg = log.New(io.Discard, "", 0)
var dbgEnabled bool

func initDebug() {
	// Log next to the executable so the path is deterministic regardless of how
	// the process is spawned (Wireshark vs dumpcap may have different %TEMP%).
	dir := os.TempDir()
	exe, exeErr := os.Executable()
	if exeErr == nil {
		dir = filepath.Dir(exe)
	}
	f, err := os.OpenFile(filepath.Join(dir, "esp32wifi-extcap.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// Fall back to %TEMP% if the exe dir is not writable.
		f, err = os.OpenFile(filepath.Join(os.TempDir(), "esp32wifi-extcap.log"),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return
		}
	}
	dbg = log.New(f, "", log.LstdFlags|log.Lmicroseconds)
	dbgEnabled = true
	dbg.Printf("---- start pid=%d exe=%q err=%v ----", os.Getpid(), exe, exeErr)
	dbg.Printf("argv: %q", os.Args)
}

type opts struct {
	doInterfaces bool
	doDLTs       bool
	doConfig     bool
	doCapture    bool

	iface   string
	fifo    string
	ctrlIn  string
	ctrlOut string

	address  string
	dataport int
	channel  string
	mac      string
	rssi     string
	timesync int
	debug    bool
}

func defaultOpts() opts {
	return opts{
		address:  "192.168.5.1",
		dataport: 19000,
		channel:  "1",
		rssi:     "-70",
		timesync: 60,
	}
}

// parseArgs is a tolerant parser: it understands our flags and Wireshark's
// extcap flags, consumes the value of any known value-flag (even a negative
// number like "-70"), and silently ignores anything else Wireshark may pass.
func parseArgs(argv []string) opts {
	o := defaultOpts()

	boolFlags := map[string]*bool{
		"extcap-interfaces": &o.doInterfaces,
		"extcap-dlts":       &o.doDLTs,
		"extcap-config":     &o.doConfig,
		"capture":           &o.doCapture,
		"debug":             &o.debug,
	}
	valueFlags := map[string]bool{
		"extcap-interface": true, "fifo": true,
		"extcap-control-in": true, "extcap-control-out": true,
		"address": true, "dataport": true, "channel": true,
		"mac": true, "rssi": true, "timesync": true,
		// known-but-ignored value flags Wireshark may pass:
		"extcap-version": true, "extcap-capture-filter": true,
		"extcap-reload-option": true, "extcap-dlt": true,
	}

	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name := strings.TrimLeft(a, "-")
		val := ""
		hasVal := false
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			val, hasVal = name[eq+1:], true
			name = name[:eq]
		}

		if bp, ok := boolFlags[name]; ok {
			*bp = true
			continue
		}
		if !hasVal && valueFlags[name] && i+1 < len(argv) {
			val, hasVal = argv[i+1], true
			i++
		}
		if !hasVal {
			// Unknown bare flag, or unknown flag with a separate value we
			// can't classify: best-effort skip a following non-flag token.
			if !valueFlags[name] && i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
				i++
			}
			continue
		}

		switch name {
		case "extcap-interface":
			o.iface = val
		case "fifo":
			o.fifo = val
		case "extcap-control-in":
			o.ctrlIn = val
		case "extcap-control-out":
			o.ctrlOut = val
		case "address":
			o.address = val
		case "dataport":
			o.dataport = atoiDefault(val, 19000)
		case "channel":
			o.channel = val
		case "mac":
			o.mac = val
		case "rssi":
			o.rssi = val
		case "timesync":
			o.timesync = atoiDefault(val, 60)
		}
	}
	return o
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

func main() {
	o := parseArgs(os.Args[1:])
	if o.debug {
		initDebug()
	}
	switch {
	case o.doInterfaces:
		printInterfaces()
	case o.doDLTs:
		printDLTs()
	case o.doConfig:
		printConfig()
	case o.doCapture:
		if err := runCapture(o); err != nil {
			dbg.Printf("capture error: %v", err)
			fmt.Fprintln(os.Stderr, "capture error:", err)
			os.Exit(1)
		}
	default:
		// Wireshark always probes --extcap-interfaces first; be helpful if run bare.
		printInterfaces()
	}
}

func printInterfaces() {
	fmt.Printf("extcap {version=1.0}{help=%s}{display=%s}\n", helpURL, ifaceDisplay)
	fmt.Printf("interface {value=%s}{display=%s}\n", ifaceValue, ifaceDisplay)

	fmt.Printf("control {number=%d}{type=selector}{display=Channel}{tooltip=WiFi channel}\n", ctlChannel)
	for _, fc := range frameControls {
		def := ""
		if fc.def {
			def = "{default=true}"
		}
		fmt.Printf("control {number=%d}{type=boolean}{display=%s}%s{tooltip=Capture %s frames}\n",
			fc.ctl, fc.display, def, fc.display)
	}
	fmt.Printf("control {number=%d}{type=string}{display=MAC filter}{validation=%s}{tooltip=Source MAC, 1-6 hex pairs e.g. AABBCCDDEEFF; press Enter/arrow to apply, empty clears}\n", ctlMAC, macValidation())
	fmt.Printf("control {number=%d}{type=selector}{display=RSSI}{tooltip=RSSI threshold}\n", ctlRSSI)
	fmt.Printf("control {number=%d}{type=button}{role=logger}{display=Log}{tooltip=Status and errors}\n", ctlLogger)

	for ch := 1; ch <= maxChannel; ch++ {
		def := ""
		if ch == 1 {
			def = "{default=true}"
		}
		fmt.Printf("value {control=%d}{value=%d}{display=%d}%s\n", ctlChannel, ch, ch, def)
	}
	for _, r := range rssiPresets {
		def := ""
		if r == -70 {
			def = "{default=true}"
		}
		fmt.Printf("value {control=%d}{value=%d}{display=%d}%s\n", ctlRSSI, r, r, def)
	}
}

func printDLTs() {
	fmt.Printf("dlt {number=%d}{name=IEEE802_11_RADIO}{display=802.11 plus radiotap header}\n", linkTypeDLT)
}

func printConfig() {
	// Channel / frames / MAC / RSSI are NOT config args: they are read from the
	// device's persisted state at capture start and driven live from the toolbar.
	fmt.Println("arg {number=0}{call=--address}{display=Sniffer address}{type=string}{default=192.168.5.1}{tooltip=IP or hostname of the ESP32 sniffer}")
	fmt.Println("arg {number=1}{call=--dataport}{display=Data port}{type=integer}{default=19000}{group=Advanced}{tooltip=TCP pcap stream port}")
	fmt.Println("arg {number=2}{call=--timesync}{display=Time sync interval (s)}{type=integer}{default=60}{range=1,3600}{group=Advanced}{tooltip=How often to push host time to the device}")
	fmt.Println("arg {number=3}{call=--debug}{display=Debug log}{type=boolflag}{default=false}{group=Advanced}{tooltip=Write esp32wifi-extcap.log next to the exe (troubleshooting; includes throughput)}")
}

// ---- capture ----------------------------------------------------------------

func runCapture(o opts) error {
	if o.fifo == "" {
		return fmt.Errorf("--fifo is required for capture")
	}
	dbg.Printf("capture: address=%s dataport=%d channel=%s mac=%q rssi=%s timesync=%d",
		o.address, o.dataport, o.channel, o.mac, o.rssi, o.timesync)
	dbg.Printf("capture: fifo=%q control-in=%q control-out=%q", o.fifo, o.ctrlIn, o.ctrlOut)

	// Open the output fifo FIRST (matches doc/extcap_example.py ordering: some
	// platforms only wire up the control pipes once the fifo is connected).
	fifo, err := os.OpenFile(o.fifo, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open fifo %q: %w", o.fifo, err)
	}
	defer fifo.Close()
	dbg.Printf("fifo opened OK")

	// Control-out (extcap -> Wireshark toolbar/log).
	var cout *controlOut
	if o.ctrlOut != "" {
		if f, err := os.OpenFile(o.ctrlOut, os.O_WRONLY, 0); err == nil {
			defer f.Close()
			cout = newControlOut(f)
			dbg.Printf("control-out opened OK")
		} else {
			dbg.Printf("control-out open FAILED: %v", err)
		}
	} else {
		dbg.Printf("control-out NOT provided by Wireshark")
	}
	logf := func(format string, a ...interface{}) {
		msg := fmt.Sprintf(format, a...)
		dbg.Printf("log: %s", msg)
		_ = cout.write(ctlLogger, ctrlCmdAdd, msg+"\n")
	}

	dev := &device{
		base: "http://" + o.address,
		client: &http.Client{
			Timeout: 4 * time.Second,
			// The ESP httpd emits a stray trailing byte after chunked JSON
			// responses, which poisons a reused keep-alive connection ("un-
			// solicited response on idle HTTP channel"). Use a fresh connection
			// per request instead of pooling.
			Transport: &http.Transport{DisableKeepAlives: true},
		},
		channel: o.channel,
		mac:     o.mac,
		rssi:    o.rssi,
	}
	frames := defaultFrames()

	// Read the device's current (NVS-persisted) filter state so the toolbar
	// reflects what the sniffer is actually doing, instead of clobbering it with
	// defaults. Fall back to defaults if the device can't be reached.
	if st, err := dev.getState(); err == nil {
		dbg.Printf("device state: channel=%d frameType=%q mac=%q rssi=%d",
			st.Channel, st.FrameType, st.Mac, st.Rssi)
		applyState(dev, frames, st)
	} else {
		dbg.Printf("getState failed (%v); using defaults", err)
	}
	// Only push time (the ESP has no RTC); leave the device's filters untouched.
	dev.syncTime()

	// Connect to the pcap stream; the firmware auto-starts capture on accept().
	addr := net.JoinHostPort(o.address, strconv.Itoa(o.dataport))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		logf("connect %s failed: %v", addr, err)
		return err
	}
	defer conn.Close()
	logf("connected to %s", addr)

	// Enlarge the socket receive buffer to absorb bursts before backpressure.
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetReadBuffer(1 << 20) // 1 MiB
	}

	// Data pump: copy the pcap byte stream straight to Wireshark. This is a
	// plain byte copy (no per-packet work); if Wireshark can't keep up, the fifo
	// write blocks -> TCP flow control -> the ESP drops at its rx layer. There is
	// no unbounded buffering here.
	cw := &countWriter{w: fifo}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 256*1024)
		n, e := io.CopyBuffer(cw, conn, buf)
		dbg.Printf("stream copy ended after %d bytes: %v", n, e)
		close(done)
	}()
	if dbgEnabled {
		go logThroughput(cw, done)
	}

	// Control-in (Wireshark toolbar -> extcap). Opened after the fifo.
	var ctrlCh chan controlMsg
	if o.ctrlIn != "" {
		if cin, err := os.OpenFile(o.ctrlIn, os.O_RDONLY, 0); err == nil {
			defer cin.Close()
			ctrlCh = make(chan controlMsg, 16)
			go readControls(cin, ctrlCh)
			dbg.Printf("control-in opened OK; reader started")
		} else {
			dbg.Printf("control-in open FAILED: %v", err)
		}
	} else {
		dbg.Printf("control-in NOT provided by Wireshark")
	}

	ticker := time.NewTicker(time.Duration(maxInt(o.timesync, 1)) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			logf("capture stream closed")
			return nil
		case <-ticker.C:
			dev.syncTime()
		case m, ok := <-ctrlCh: // nil channel (no toolbar) never fires
			if !ok {
				logf("control pipe closed; stopping")
				conn.Close()
				return nil
			}
			handleControl(dev, frames, m, cout, logf)
		}
	}
}

func handleControl(dev *device, frames map[string]bool, m controlMsg, cout *controlOut, logf func(string, ...interface{})) {
	dbg.Printf("ctrl-in: arg=%d cmd=%d payload=%q", m.arg, m.cmd, string(m.payload))

	if m.cmd == ctrlCmdInitialized {
		// Toolbar is ready; push the device's current state so it matches.
		syncToolbar(cout, dev, frames)
		logf("toolbar ready; synced to device state")
		return
	}
	if m.cmd != ctrlCmdSet {
		return
	}

	// Frame-type checkboxes (including the "All" meta-toggle).
	if token, ok := frameTokenByCtl(m.arg); ok {
		frames[token] = boolPayload(m.payload)
		if token == "all" {
			// Mirror the web UI: disable the individual boxes while All is on.
			cmd := byte(ctrlCmdEnable)
			if frames["all"] {
				cmd = ctrlCmdDisable
			}
			for _, fc := range frameControls {
				if fc.token != "all" {
					_ = cout.write(byte(fc.ctl), cmd, "")
				}
			}
		}
		dev.setFrames(frames)
		logf("frames = %s", strings.Join(frameTokens(frames), ","))
		return
	}

	val := strings.TrimSpace(string(m.payload))
	switch m.arg {
	case ctlChannel:
		dev.setChannel(val)
		logf("channel = %s", val)
	case ctlMAC:
		dev.mac = val
		dev.setMAC(val)
		logf("mac = %q", val)
	case ctlRSSI:
		dev.rssi = val
		dev.setRSSI(val)
		logf("rssi = %s", val)
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// countWriter wraps the fifo and tallies bytes copied, for throughput logging.
type countWriter struct {
	w io.Writer
	n atomic.Uint64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(uint64(n))
	return n, err
}

// logThroughput logs the data-pump rate every 5s while capturing (debug only),
// so a high-volume setup can be measured against the pipe's capacity.
func logThroughput(cw *countWriter, done <-chan struct{}) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	var last uint64
	for {
		select {
		case <-done:
			return
		case <-t.C:
			cur := cw.n.Load()
			dbg.Printf("throughput: total=%d KiB rate=%.1f KiB/s",
				cur/1024, float64(cur-last)/1024.0/5.0)
			last = cur
		}
	}
}

// ---- device relay -----------------------------------------------------------

type device struct {
	base    string
	client  *http.Client
	channel string
	mac     string
	rssi    string
}

// devState is the JSON returned by GET /api/filter (no query) — the sniffer's
// current, NVS-persisted filter state (see config_http_server.c).
type devState struct {
	FrameType string `json:"frameType"`
	Mac       string `json:"mac"`
	Rssi      int    `json:"rssi"`
	Channel   int    `json:"channel"`
}

func (d *device) getState() (*devState, error) {
	resp, err := d.client.Get(d.base + "/api/filter")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var s devState
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, fmt.Errorf("parse %q: %w", string(body), err)
	}
	return &s, nil
}

// applyState loads the device's reported state into our local channel/mac/rssi
// and the frame-checkbox map.
func applyState(dev *device, frames map[string]bool, st *devState) {
	dev.channel = strconv.Itoa(st.Channel)
	dev.mac = st.Mac
	dev.rssi = strconv.Itoa(st.Rssi)
	for k := range frames {
		frames[k] = false
	}
	for _, tok := range strings.Split(st.FrameType, ",") {
		if tok = strings.TrimSpace(tok); tok != "" {
			frames[tok] = true
		}
	}
}

// syncToolbar pushes the current local state out to the Wireshark toolbar so the
// controls display what the device is actually using. Programmatic SETs do not
// echo back as user changes, so this does not loop.
func syncToolbar(cout *controlOut, dev *device, frames map[string]bool) {
	if dev.channel != "" {
		_ = cout.write(ctlChannel, ctrlCmdSet, dev.channel)
	}
	for _, fc := range frameControls {
		_ = cout.write(byte(fc.ctl), ctrlCmdSet, boolByte(frames[fc.token]))
	}
	_ = cout.write(ctlMAC, ctrlCmdSet, dev.mac)
	_ = cout.write(ctlRSSI, ctrlCmdSet, dev.rssi)
	if frames["all"] {
		// Match the web UI: the individual boxes are disabled while All is on.
		for _, fc := range frameControls {
			if fc.token != "all" {
				_ = cout.write(byte(fc.ctl), ctrlCmdDisable, "")
			}
		}
	}
}

// boolByte encodes a boolean control value as the single-byte payload Wireshark
// expects (0x00 / 0x01).
func boolByte(b bool) string {
	if b {
		return "\x01"
	}
	return "\x00"
}

func (d *device) get(path string) {
	resp, err := d.client.Get(d.base + path)
	if err != nil {
		dbg.Printf("http GET %s ERROR: %v", path, err)
		fmt.Fprintf(os.Stderr, "http GET %s: %v\n", path, err)
		return
	}
	dbg.Printf("http GET %s -> %s", path, resp.Status)
	// Drain and close so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func (d *device) setChannel(ch string) {
	if ch == "" {
		return
	}
	d.get("/api/filter?channel=" + url.QueryEscape(ch))
}

func (d *device) setRSSI(r string) {
	if strings.TrimSpace(r) == "" {
		return
	}
	d.get("/api/filter?rssi=" + url.QueryEscape(r))
}

func (d *device) setMAC(m string) {
	// Empty MAC clears the filter on the device.
	d.get("/api/filter?macFilterAddress=" + url.QueryEscape(m))
}

func (d *device) setFrames(f map[string]bool) {
	parts := frameTokens(f)
	if len(parts) == 0 {
		// Firmware ignores frame=0; nothing sane to send when all are off.
		return
	}
	d.get("/api/filter?frame=" + strings.Join(parts, ","))
}

func (d *device) syncTime() {
	d.get(fmt.Sprintf("/api/time?value=%d", time.Now().UnixMilli()))
}
