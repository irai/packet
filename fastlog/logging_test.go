package fastlog

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/netip"
	"testing"
	"time"
)

type simpleType struct{}

func (t simpleType) FastLog(l *Line) *Line {
	return l
}
func (t simpleType) String() string {
	return "simpleType"
}

type complexType struct {
	mac      net.HardwareAddr
	ip       net.IP
	str      string
	buffer   []byte
	ipArray  []net.IP
	strArray []string
	n        int
}

func (t complexType) FastLog(l *Line) *Line {
	l.MAC("mac", t.mac)
	l.IPSlice("ip", t.ip)
	l.String("str", t.str)
	l.ByteArray("buffer", t.buffer)
	l.IPArray("iparray", t.ipArray)
	l.StringArray("strarray", t.strArray)
	return l
}

func (t complexType) String() string {
	return fmt.Sprintf("mac=%s ip=%s str=%s buffer=%v array=%v", t.mac, t.ip, t.str, t.buffer, t.ipArray)
}

func TestLine_PrintUint32(t *testing.T) {
	l := &Line{buffer: [2048]byte{}}
	l = l.printInt(10)
	fmt.Println("value", l.buffer[l.index])
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
		l = l.printInt(test)
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
	l.IPSlice("ip", ip)
	l.Int("int", 10)
	l.Uint8("uint8", 'A')
	// fmt.Printf("%s| len=%d\n", l.buffer[:l.index], l.index)
	l.Module("ip", "test ip")
	l.MAC("mac", mac2)
	l.IPSlice("ip", ip)

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

func TestLine_Nil(t *testing.T) {
	l := NewLine("test", "")
	var line simpleType
	var ptr *simpleType
	l.Struct(nil)
	l.Struct(line)
	l.Struct(ptr)
	l.Stringer(nil)
	l.Stringer(line)
	l.Stringer(ptr)
}

/**
func TestLine_FastLogArray(t *testing.T) {
	tests := []struct {
		name    string
		entry   []testComplex
		wantLen int
	}{
		{name: "simple", wantLen: 171, entry: []testComplex{{str: "first str"}, {ip: net.IPv4(100, 100, 100, 100)}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := NewLine("test", "fastlog array").FastLogArray("entries", tt.entry).ToString()
			if n := len(str); n != tt.wantLen {
				fmt.Println("TEST fastlog", str)
				t.Errorf("%s: Line.FastLogArray() invalid len=%v, want %v", tt.name, n, tt.wantLen)
			}
		})
	}
}

**/

func Benchmark_Fastlog(b *testing.B) {
	// os.Stdout, _ = os.Open(os.DevNull)
	// os.Stderr, _ = os.Open(os.DevNull)
	now := time.Now()
	mac := net.HardwareAddr{0x00, 0xff, 0xaa, 0xbb, 0x55, 0x55}
	ipv4 := netip.AddrFrom4([4]byte{192, 168, 0, 1})
	ipv6 := netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x10})

	s := complexType{mac: mac, ip: net.IPv4zero, str: "my string"}

	Std.Out = ioutil.Discard
	b.Run("printf struct reference", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			fmt.Fprintf(Std.Out, "struct: %v\n", s)
		}
	})

	b.Run("fastlog struct reference", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			NewLine("test", "message").Struct(s).Write()
		}
	})

	// these methods have some allocation
	b.Run("some alloc", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			NewLine("test", "message").
				Duration("duration", time.Hour).
				Struct(s).
				Write()
		}
	})

	// printf
	b.Run("printf", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			fmt.Fprintf(Std.Out, "test: message int=%d name=%s uint16=%d uint32=%d uint8=%d ip=%s ipv6=%s newip=%s newip6=%s mac=%s time=%s\n",
				100, "my string", 1, 1, 111, net.IPv4zero, net.IPv6zero, ipv4, ipv6, mac, now)
		}
	})

	// No allocation
	b.Run("fastlog zero alloc", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			NewLine("test", "message").
				Int("int", 100).
				String("name", "my string").
				Uint16("uint16", 1).
				Uint32("uint32", 1).
				Uint8("uint8", 111).
				IPSlice("ip", net.IPv4zero).
				IPSlice("ipv6", net.IPv6zero).
				IP("newip", ipv4).
				IP("newip6", ipv6).
				MAC("mac", mac).
				ByteArray("array", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}).
				Time("time", now).
				Write()
		}
	})

	logger := New("test")
	b.Run("zero_alloc_initialised", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			logger.Msg("message").
				Int("int", 100).
				String("name", "my string").
				Uint16("uint16", 1).
				Uint32("uint32", 1).
				Uint8("uint8", 111).
				IPSlice("ip", net.IPv4zero).
				IPSlice("ipv6", net.IPv6zero).
				IP("newip", ipv4).
				IP("newip6", ipv6).
				MAC("mac", mac).
				ByteArray("array", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}).
				Time("time", now).
				Write()
		}
	})
}
