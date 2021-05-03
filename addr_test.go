package packet

import (
	"fmt"
	"testing"
)

var count int

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
