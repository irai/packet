package packet

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/irai/packet/raw"
)

var (
	zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	ip1     = net.IPv4(192, 168, 0, 1)
	ip2     = net.IPv4(192, 168, 0, 2)
	ip3     = net.IPv4(192, 168, 0, 3)
	ip4     = net.IPv4(192, 168, 0, 4)
	ip5     = net.IPv4(192, 168, 0, 5)
	mac1    = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x01}
	mac2    = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x02}
	mac3    = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x03}
	mac4    = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x04}
	mac5    = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x05}
)

func makeTestHandler() (h *Handler) {
	h = &Handler{}

	h.conn, _ = raw.TestNewBufferedConn()
	return h
}

func TestHandler_ListenAndServe(t *testing.T) {
	tests := []struct {
		name    string
		frame   []byte
		wantLen int
	}{
		{name: "invalid", wantLen: 0, frame: []byte{0, 2, 3, 4}},
	}
	Debug = true

	ctxt, cancel := context.WithCancel(context.Background())
	h := makeTestHandler()

	go func() {
		if err := h.ListenAndServe(ctxt); err != nil {
			t.Errorf("ListenAndServe terminated with error:%s", err)
		}
	}()

	time.Sleep(time.Millisecond * 50)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := h.conn.WriteTo(tt.frame, nil); err != nil {
				t.Errorf("%s: Handler.ListenAndServe() writeTo error: %s", tt.name, err)
			}
			time.Sleep(time.Millisecond * 50)
			if h.LANHosts.Len() != tt.wantLen {
				t.Errorf("%s: invalid LANHost table length want=%d got=%d", tt.name, tt.wantLen, h.LANHosts.Len())

			}
		})
	}
	cancel()
}
