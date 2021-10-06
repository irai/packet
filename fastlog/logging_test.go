package fastlog

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"testing"
)

func TestLine_PrintUint32(t *testing.T) {
	tests := []uint32{
		4294967295,
		65535,
		0,
		1,
		10,
		100,
		1000,
		10000,
		100000,
		1000000,
		10000000,
		100000000,
		1000000000,
		324,
		304,
		320,
	}

	for _, test := range tests {
		l := &Line{buffer: [2048]byte{}}
		l = l.printUint32(test)
		if want := fmt.Sprint(test); string(l.buffer[:l.index]) != want {
			t.Errorf("got printUint32(%d) got=%s, want=%s", test, l.buffer[:l.index], want)
		}
	}
}

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
		[]byte("ether : mac=00:02:03:04:05:af ip=192.168.0.1 int=10 uint8=65\nip    : \"test ip\" mac=00:02:03:04:05:af ip=192.168.0.1")) {
		t.Errorf("invalid buffer=[%s], len=%d", string(l.buffer[:l.index]), l.index)
	}

}

func TestLine_ByteArray(t *testing.T) {
	Std.Out = ioutil.Discard
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
		{name: "truncated", module: "module", msg: "", payload: make([]byte, 2500), wantBytes: []byte(`module:`), wantLen: 2047, wantEndMarker: false},
		{name: "boundary", module: "module", msg: "", payload: make([]byte, 2500), wantBytes: []byte(`module:`), wantLen: 2047, wantEndMarker: false},
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

func TestLine_appendIP6(t *testing.T) {
	tests := []struct {
		name   string
		wantIP string
	}{
		{name: "ok", wantIP: "2001:4479:1e00:8202:42:15ff:fee6:1008"},
		{name: "ok", wantIP: "2001:4479:1e00:8202:42:15ff:fee6:0"},
		{name: "empy", wantIP: "::"},
		{name: "one", wantIP: "::1"},
		{name: "middle", wantIP: "234::1"},
		{name: "middle", wantIP: "0:0:2::1"},
		{name: "middle", wantIP: "0:0:2::"},
		{name: "middle", wantIP: "fffd:1001:2002::2:1"},
		{name: "middle", wantIP: "0:1:2:3:4:5:6:7"},
		{name: "middle", wantIP: "0:1:2:3:4:5:6:7"},
		{name: "middle", wantIP: "0:1:2:3:4::"},
		{name: "middle", wantIP: "0:1:2002:3003:4004:5005:6006:7007"},
		{name: "middle", wantIP: "1:0:2002:3003:4004:5005:6006:7007"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLine("test", "")
			ip := net.ParseIP(tt.wantIP)
			l.appendIP6(ip)

			if txt := l.buffer[l.index-len(tt.wantIP) : l.index]; !bytes.Equal(txt, []byte(ip.String())) {
				t.Errorf("appendIP6() invalid IP got=%s want=%s|", string(txt), tt.wantIP)

			}

			l.appendIP6(nil) // test nil ip
		})
	}
}

type testType struct{}

func (t testType) FastLog(l *Line) *Line {
	return l
}
func (t testType) String() string {
	return "test"
}

func TestLine_Nil(t *testing.T) {
	l := NewLine("test", "")
	var line testType
	var ptr *testType
	l.Struct(nil)
	l.Struct(line)
	l.Struct(ptr)
	l.Stringer(nil)
	l.Stringer(line)
	l.Stringer(ptr)
}
