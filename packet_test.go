package packet

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/net/ipv6"
)

var (
	zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	ip1     = net.IPv4(192, 168, 0, 1)
	ip2     = net.IPv4(192, 168, 0, 2)
	ip3     = net.IPv4(192, 168, 0, 3)
	ip4     = net.IPv4(192, 168, 0, 4)
	ip5     = net.IPv4(192, 168, 0, 5)

	hostMAC   = net.HardwareAddr{0x00, 0x55, 0x55, 0x55, 0x55, 0x55}
	routerMAC = net.HardwareAddr{0x00, 0x66, 0x66, 0x66, 0x66, 0x66}
	mac1      = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x01}
	mac2      = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x02}
	mac3      = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x03}
	mac4      = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x04}
	mac5      = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x05}

	ip6LLARouter = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6LLAHost   = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x10}
	ip6LLA1      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6LLA2      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	ip6LLA3      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03}
	ip6LLA4      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04}
	ip6LLA5      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05}
)

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

func Benchmark_EthBuffer(b *testing.B) {
	// This seems to be the faster approach for sequential access to buffer
	var buffer = EtherBuffer{}
	for i := 0; i < b.N; i++ {
		func() {
			ether := buffer.Alloc()
			defer buffer.Free()

			ether = EtherMarshalBinary(ether, syscall.ETH_P_IPV6, hostMAC, mac2)
			if ether.EtherType() == 0 {
				fmt.Println("test")
			}
		}()
	}
}
