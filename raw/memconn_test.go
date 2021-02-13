package raw

import (
	"fmt"
	"net"
	"testing"
	"time"
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

func Test_bufferedPacketConn_ReadFrom(t *testing.T) {
	a, b := NewBufferedConn()

	sent := []byte("test")
	buffer := make([]byte, 32)
	count := 0

	go func(t *testing.T) {
		for {
			if _, _, err := b.ReadFrom(buffer); err != nil {
				panic(err)
			}
			count++
		}
	}(t)

	fmt.Println("going to write")
	a.WriteTo(sent, nil)
	a.WriteTo(sent, nil)
	a.WriteTo(sent, nil)
	time.Sleep(time.Millisecond * 5)
	if count != 3 {
		t.Fatal("error in read ", count)
	}

}
