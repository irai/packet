package model

import (
	"fmt"
	"net"
	"testing"
)

var count int
var (
	ip1  = net.IPv4(192, 168, 0, 1)
	mac1 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x01}
)

func BenchmarkAddr_Printf(t *testing.B) {
	count = 0
	for i := 0; i < t.N; i++ {
		addr := Addr{MAC: mac1, IP: ip1, Port: uint16(i)}
		s := fmt.Sprintf("mac=%s ip=%s port=%d", addr.MAC, addr.IP, addr.Port)
		if s != "" {
			count++
		}
	}
}

func BenchmarkAddr_Builder(t *testing.B) {
	count = 0
	for i := 0; i < t.N; i++ {
		addr := Addr{MAC: mac1, IP: ip1, Port: uint16(i)}
		s := addr.String()
		if s != "" {
			count++
		}
	}
}
