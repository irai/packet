package packet

import (
	"syscall"
	"testing"

	"golang.org/x/net/ipv6"
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
	if len(ether) != 60 { // 40+14+len(mypayload)
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
