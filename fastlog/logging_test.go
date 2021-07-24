package fastlog

import (
	"bytes"
	"net"
	"testing"
)

func TestLine_Write(t *testing.T) {
	mac2 := net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0xaf}
	ip := net.IPv4(192, 168, 0, 1)
	l := NewLine("ether", "")
	l.MAC("mac", mac2)
	l.IP("ip", ip)
	l.Int("int", 10)
	l.Uint8("uint8", 'A')
	// fmt.Printf("%s| len=%d\n", l.buffer[:l.index], l.index)
	l.Module("ip", "test ip")
	l.MAC("mac", mac2)
	l.IP("ip", ip)

	if !bytes.Equal(l.buffer[:l.index],
		[]byte(`ether : mac=00:02:03:04:05:af ip=192.168.0.1 int=10 uint8=65ip    : msg="test ip" mac=00:02:03:04:05:af ip=192.168.0.1`)) {
		t.Errorf("invalid buffer=[%s], len=%d", string(l.buffer[:l.index]), l.index)
	}

}

func TestLine_ByteArray(t *testing.T) {
	tests := []struct {
		name          string
		module        string
		msg           string
		payload       []byte
		wantBytes     []byte
		wantEndMarker bool
		wantLen       int
	}{
		{name: "ok", module: "module", msg: "", payload: make([]byte, 300), wantBytes: []byte(`module:`), wantLen: 917, wantEndMarker: true},
		{name: "truncated", module: "module", msg: "", payload: make([]byte, 500), wantBytes: []byte(`module:`), wantLen: 1023, wantEndMarker: false},
		{name: "boundary", module: "module", msg: "", payload: make([]byte, 500), wantBytes: []byte(`module:`), wantLen: 1023, wantEndMarker: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLine(tt.module, tt.msg)
			tt.payload[0] = 0xaa                 // just a marker
			tt.payload[len(tt.payload)-1] = 0xff // just a marker
			l = l.ByteArray("payload", tt.payload)
			if l.index != tt.wantLen {
				t.Errorf("ByteArray() invalid len got=%v, want=%v", l.index, tt.wantLen)
			}
			if !bytes.Contains(l.buffer[:l.index], tt.wantBytes) {
				t.Errorf("ByteArray() invalid buffer got=% x", l.buffer[:l.index])
			}
			if tt.wantEndMarker && !bytes.Equal(l.buffer[l.index-3:l.index], []byte("ff]")) {
				t.Errorf("ByteArray() invalid end marker got=%s", string(l.buffer[l.index-3:l.index]))
			}
			/**
			if !tt.wantEndMarker && !bytes.Equal(l.buffer[l.index-11:l.index], []byte("]TRUNCATED")) {
				t.Errorf("ByteArray() invalid truncated marker got=%s|", string(l.buffer[l.index-11:l.index]))
			}
			*/
			l.Write()
		})
	}
}
