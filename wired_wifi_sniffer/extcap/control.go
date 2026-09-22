package main

// Wireshark extcap control-pipe protocol.
//
// Frame layout (see Wireshark doc/extcap_example.py, struct '>sBHBB' + payload):
//
//	byte 0      sync indication: 'T' toolbar control, 'Q' quit
//	byte 1      reserved (0x00)
//	bytes 2-3   uint16 big-endian length = len(arg + command + payload)
//	byte 4      control number (arg)
//	byte 5      command
//	bytes 6+    UTF-8 payload

import (
	"encoding/binary"
	"io"
	"sync"
)

const (
	ctrlCmdInitialized = 0
	ctrlCmdSet         = 1
	ctrlCmdAdd         = 2
	ctrlCmdRemove      = 3
	ctrlCmdEnable      = 4
	ctrlCmdDisable     = 5
	ctrlCmdStatusbar   = 6
	ctrlCmdInformation = 7
	ctrlCmdWarning     = 8
	ctrlCmdError       = 9
)

const (
	syncData byte = 'T'
	syncQuit byte = 'Q'
)

// controlMsg is one inbound control-pipe message (Wireshark -> extcap).
type controlMsg struct {
	arg     byte
	cmd     byte
	payload []byte
}

// controlOut serializes writes to the extcap control-out pipe across goroutines.
type controlOut struct {
	mu sync.Mutex
	w  io.Writer
}

func newControlOut(w io.Writer) *controlOut { return &controlOut{w: w} }

// write emits one control frame. arg is the control number, cmd one of ctrlCmd*.
func (c *controlOut) write(arg, cmd byte, payload string) error {
	if c == nil || c.w == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	body := make([]byte, 0, 2+len(payload))
	body = append(body, arg, cmd)
	body = append(body, payload...)

	hdr := make([]byte, 4)
	hdr[0] = syncData
	hdr[1] = 0x00
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(body)))

	if _, err := c.w.Write(hdr); err != nil {
		return err
	}
	_, err := c.w.Write(body)
	return err
}

// readControls parses inbound control frames and forwards them on ch. It returns
// (closing ch) on a Quit frame, on EOF, or on any read error.
func readControls(r io.Reader, ch chan<- controlMsg) {
	defer close(ch)
	hdr := make([]byte, 4)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			return
		}
		n := binary.BigEndian.Uint16(hdr[2:])
		body := make([]byte, n)
		if n > 0 {
			if _, err := io.ReadFull(r, body); err != nil {
				return
			}
		}
		if hdr[0] == syncQuit {
			return
		}
		if n < 2 {
			continue
		}
		ch <- controlMsg{arg: body[0], cmd: body[1], payload: body[2:]}
	}
}

// boolPayload interprets a boolean control payload. Wireshark sends a single
// byte (0 = false, non-zero = true); some builds send "true"/"false" text.
func boolPayload(p []byte) bool {
	if len(p) == 1 {
		return p[0] != 0
	}
	switch string(p) {
	case "true", "True", "1":
		return true
	default:
		return false
	}
}
