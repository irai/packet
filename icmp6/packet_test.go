package icmp6

import (
	"fmt"
	"testing"

	"inet.af/netaddr"
)

func Test_IP6Lib(t *testing.T) {

	ip, err := netaddr.ParseIP("2001:4479:1d01:2401::")

	if err != nil {
		t.Error("invalid IP ", err)
	}
	fmt.Println(ip)
}
