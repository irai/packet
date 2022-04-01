package packet

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
)

func TestIP4Checksum(t *testing.T) {
	// wikipedia example
	// https://en.wikipedia.org/wiki/IPv4_header_checksum
	packet := []byte{0x45, 0x00, 0x00, 0x73, 0, 0, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0, 0x01, 0xc0, 0xa8, 0, 0xc7}
	if IP4(packet).CalculateChecksum() != 0x61b8 {
		t.Errorf("check sum failed %x", IP4(packet).CalculateChecksum())
	}
}

var resultByte []byte

func Benchmark_packetAlloc(b *testing.B) {

	ether := Ether([]byte{})
	for i := 0; i < b.N; i++ {
		func() {
			buf := make([]byte, EthMaxSize)
			ether = EncodeEther(buf[:], syscall.ETH_P_IPV6, hostMAC, mac2)
			if ether.EtherType() == 0 {
				fmt.Println("test")
			}
		}()
	}
	resultByte = ether
}
func Benchmark_packetNoAlloc(b *testing.B) {

	ether := Ether([]byte{})
	var mutex sync.Mutex
	buf := make([]byte, EthMaxSize) // allocate in the stack
	for i := 0; i < b.N; i++ {
		func() {
			mutex.Lock()
			defer mutex.Unlock()
			ether = EncodeEther(buf[:], syscall.ETH_P_IPV6, hostMAC, mac2)
			if ether.EtherType() == 0 {
				fmt.Println("test")
			}
		}()
	}
}

func Benchmark_StdIP(b *testing.B) {
	b.Run("stdipv4", func(b *testing.B) {
		count := 0
		key := byte(0)
		ip1 := net.IPv4(192, 168, 0, 1)
		for i := 0; i < b.N; i++ {
			ip := net.IPv4(192, 168, 0, key)
			if ip.To4() != nil {
				count++
			}
			if ip.Equal(ip1) {
				count--
			}
		}
		fmt.Println(count)
	})
	b.Run("ipaddrv4", func(b *testing.B) {
		count := 0
		key := byte(0)
		ip2 := netip.AddrFrom4([4]byte{192, 168, 0, 1})
		for i := 0; i < b.N; i++ {
			ip := netip.AddrFrom4([4]byte{192, 168, 0, key})
			if ip.Is4() {
				count++
			}
			if ip == ip2 {
				count--
			}
		}
		fmt.Println(count)
	})
	b.Run("stdipv6", func(b *testing.B) {
		count := 0
		key := byte(0)
		ip1 := net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		for i := 0; i < b.N; i++ {
			ip := net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, key}
			if ip.To4() != nil {
				count++
			}
			if ip.Equal(ip1) {
				count--
			}
		}
		fmt.Println(count)
	})
	b.Run("ipaddrv6", func(b *testing.B) {
		count := 0
		key := byte(0)
		ip2 := netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		for i := 0; i < b.N; i++ {
			ip, _ := netip.AddrFromSlice([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, key})
			if ip.Is4() {
				count++
			}
			if ip == ip2 {
				count--
			}
		}
		fmt.Println(count)
	})
}
