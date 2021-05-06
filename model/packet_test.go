package model

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/net/ipv6"
	"inet.af/netaddr"
)

func TestIP4Checksum(t *testing.T) {
	// wikipedia example
	// https://en.wikipedia.org/wiki/IPv4_header_checksum
	packet := []byte{0x45, 0x00, 0x00, 0x73, 0, 0, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0, 0x01, 0xc0, 0xa8, 0, 0xc7}
	if IP4(packet).CalculateChecksum() != 0x61b8 {
		t.Errorf("check sum failed %x", IP4(packet).CalculateChecksum())
	}
}

func TestIP6MarshalBinary(t *testing.T) {
	const hopLimit = 1

	ip6 := IP6MarshalBinary(nil, hopLimit, ip6LLAHost, ip6LLA4)
	if len(ip6) != 40 {
		t.Fatal("invalid ip6 len", ip6)
	}

	// validate first with google ipv6
	header, err := ipv6.ParseHeader(ip6)
	if err != nil {
		t.Fatal("failed to parse ip6 header: ", err)
	}
	if header.Version != 0x06 {
		t.Fatalf("invalid version %v %+v", header.Version, header)
	}
	if header.HopLimit != 1 {
		t.Fatal("invalid hop limit ", header.HopLimit)
	}
	if header.NextHeader != 59 {
		t.Fatal("invalid next header ", header.NextHeader)
	}
	if !header.Src.Equal(ip6LLAHost) {
		t.Fatal("invalid src ip ", header.Src)
	}
	if !header.Dst.Equal(ip6LLA4) {
		t.Fatal("invalid dst ip ", header.Src)
	}

	// validate with our ipv6
	frame := IP6(ip6)
	if !frame.IsValid() {
		t.Fatalf("invalid frame %+v", frame)
	}
	if frame.Version() != 0x06 {
		t.Fatalf("invalid version %v %+v", frame.Version(), frame)
	}
	if frame.HopLimit() != 1 {
		t.Fatal("invalid hop limit ", frame.HopLimit())
	}
	if frame.NextHeader() != 59 {
		t.Fatal("invalid next header ", frame.NextHeader())
	}
	if !frame.Src().Equal(ip6LLAHost) {
		t.Fatal("invalid src ip ", frame.Src())
	}
	if !frame.Dst().Equal(ip6LLA4) {
		t.Fatal("invalid dst ip ", frame.Dst())
	}
}

func TestIP6Payload(t *testing.T) {
	var err error

	mypayload := []byte{0xf, 0xb, 0xa}

	buf := make([]byte, EthMaxSize) // allocate in the stack
	ether := EtherMarshalBinary(buf, syscall.ETH_P_IPV6, routerMAC, mac2)
	if len(ether) != 14 {
		t.Fatal("invalid ether len", len(ether))
	}
	ip6 := IP6MarshalBinary(ether.Payload(), 1, ip6LLAHost, ip6LLA2)
	if len(ip6) != 40 {
		t.Fatal("invalid ip6 len", len(ip6))
	}

	ip6, err = ip6.AppendPayload(mypayload, 25) // 25 as a test id
	if err != nil {
		t.Fatal("error ip6 append ", err)
	}
	if len(ip6) != 43 {
		t.Fatal("invalid ip6 len 2", ip6)
	}

	ether, _ = ether.AppendPayload(ip6)
	if len(ether) != 40+14+len(mypayload) {
		t.Fatal("invalid packet len ", len(ether))
	}

	// validate first with google ipv6
	header, err := ipv6.ParseHeader(ether.Payload())
	if err != nil {
		t.Fatal("failed to parse ip6 header: ", err)
	}
	if header.Version != 0x06 {
		t.Fatalf("invalid version %v %+v", header.Version, header)
	}
	if !header.Src.Equal(ip6LLAHost) {
		t.Fatal("invalid src ip ", header.Src)
	}
	if !header.Dst.Equal(ip6LLA2) {
		t.Fatal("invalid dst ip ", header.Src)
	}

}

var resultByte []byte

func Benchmark_packetAlloc(b *testing.B) {

	ether := Ether([]byte{})
	for i := 0; i < b.N; i++ {
		func() {
			buf := make([]byte, EthMaxSize)
			ether = EtherMarshalBinary(buf[:], syscall.ETH_P_IPV6, hostMAC, mac2)
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
			ether = EtherMarshalBinary(buf[:], syscall.ETH_P_IPV6, hostMAC, mac2)
			if ether.EtherType() == 0 {
				fmt.Println("test")
			}
		}()
	}
}

func Benchmark_Pool(b *testing.B) {
	var Buffer = sync.Pool{New: func() interface{} { return make([]byte, EthMaxSize) }}
	for i := 0; i < b.N; i++ {
		func() {
			buf := Buffer.Get().([]byte)
			defer Buffer.Put(buf)

			ether := EtherMarshalBinary(buf, syscall.ETH_P_IPV6, hostMAC, mac2)
			if ether.EtherType() == 0 {
				fmt.Println("test")
			}
		}()
	}
}

func Benchmark_StdIP(b *testing.B) {
	count := 0
	key := byte(0)
	ip2 := net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	for i := 0; i < b.N; i++ {
		ip := net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, key}
		if ip.To4() != nil {
			count++
		}
		if ip.Equal(ip2) {
			count--
		}
	}
	fmt.Println(count)
}
func Benchmark_NewIP(b *testing.B) {
	count := 0
	key := byte(0)
	ip2 := netaddr.IPv6Raw([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	for i := 0; i < b.N; i++ {
		ip := netaddr.IPv6Raw([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, key})
		if ip.Is4() {
			count++
		}
		if ip == ip2 {
			count--
		}
	}
	fmt.Println(count)
}
