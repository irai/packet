package packet

import (
	"fmt"
	"net"
	"testing"
)

func TestLogic(t *testing.T) {

	fmt.Println("Hello, playground")

	ip := net.IPv4(192, 168, 1, 130)

	n := net.IPNet{IP: net.IPv4(192, 168, 1, 129), Mask: net.IPv4Mask(255, 255, 255, 0)}

	if !n.Contains(ip) {
		t.Error("does not contain")
	}

	ip1 := net.ParseIP("192.168.0.1")
	if !ip1.Equal(net.IPv4(192, 168, 0, 1)) {
		t.Error("invalid ip match")
	}
	buf := []byte{192, 168, 0, 1}
	if !ip1.To4().Equal(net.ParseIP("192.168.0.1")) {
		t.Error("invalid ip match to4")
	}
	if !net.IP(buf).Equal(net.ParseIP("192.168.0.1")) {
		t.Error("invalid ip match 3")
	}
}

var ip4Test net.IP

func BenchmarkIPv6Allocation(t *testing.B) {
	for i := 0; i < t.N; i++ {
		buf := []byte{192, 168, 0, byte(i)}
		ip4Test = func(ip net.IP) net.IP {
			if ip.To4() != nil {
				return ip
			}
			ip = ip.To16()
			return ip
		}(net.IP(buf))
	}
}

func TestGetLinuxDefaultGateway(t *testing.T) {
	_, err := GetLinuxDefaultGateway()
	if err != nil {
		t.Errorf("GetLinuxDefaultGateway() error = %v", err)
		return
	}
}
