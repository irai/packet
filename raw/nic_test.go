package raw

import (
	"fmt"
	"net"
	"testing"
)

func TestLogic(t *testing.T) {

	fmt.Println("Hello, playground")

	ip := net.IPv4(192, 168, 1, 130)

	n := net.IPNet{IP: net.IPv4(192, 168, 1, 129), Mask: net.IPv4Mask(255, 255, 255, 255)}

	if !n.Contains(ip) {
		t.Error("does not contain")
	}
}
