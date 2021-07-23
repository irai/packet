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
	l.Byte('-')
	l.Module("ip", "test ip")
	l.MAC("mac", mac2)
	l.IP("ip", ip)

	if !bytes.Equal(l.buffer[:l.index],
		[]byte(`ether : mac=00:02:03:04:05:af ip=192.168.0.1 int=10 uint8=65-ip    : msg="test ip" mac=00:02:03:04:05:af ip=192.168.0.1`)) {
		t.Errorf("invalid buffer=[%s], len=%d", string(l.buffer[:l.index]), l.index)
	}

}
