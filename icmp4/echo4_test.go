package icmp4

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/irai/packet/model"
)

func Benchmark_Ping256(b *testing.B) {
	tc := setupTestHandler()
	defer tc.Close()
	for i := 0; i < b.N; i++ {
		ping256(tc)
	}
}

func ping256(tc *testContext) {
	channel := make(chan net.IP, 20)
	srcIP := hostIP4
	for i := 1; i < 255; i++ {
		ip := model.CopyIP(srcIP).To4() // new buffer, we are sending this in the channel
		ip[3] = uint8(i)
		go func(ip net.IP) {
			if tc.h.Ping(hostAddr, model.Addr{IP: ip}, time.Second*2) != nil {
				channel <- net.IPv4zero
				return
			}
			channel <- ip
		}(ip)
		time.Sleep(time.Millisecond * 5)
	}
	for i := 1; i < 255; i++ {
		ip := <-channel
		if !ip.Equal(net.IPv4zero) {
			fmt.Printf("Found client ip=%s", ip)
		}
	}

}
