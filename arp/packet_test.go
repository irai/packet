package arp

import (
	"bytes"
	"net"
	"syscall"
	"testing"

	"github.com/irai/packet"
)

func newEtherPacket(hType uint16, srcMAC net.HardwareAddr, dstMAC net.HardwareAddr) packet.Ether {
	buf := make([]byte, packet.EthMaxSize) // allocate in the stack
	p := packet.EtherMarshalBinary(buf, hType, srcMAC, dstMAC)
	return p
}

func newPacket(op uint16, srcAddr packet.Addr, dstAddr packet.Addr) ARP {
	p, err := MarshalBinary(nil, op, srcAddr, dstAddr)
	if err != nil {
		panic(err)
	}
	return p
}

func TestMarshalUnmarshall(t *testing.T) {
	// marshall
	buf := make([]byte, packet.EthMaxSize) // allocate in the stack
	ether := packet.EtherMarshalBinary(buf, syscall.ETH_P_ARP, mac1, mac2)
	arpFrame, err := MarshalBinary(ether.Payload(), OperationRequest, addr1, addr2)
	if err != nil {
		t.Errorf("error in marshall binary: %s", err)
	}
	if len(ether) != 14 {
		t.Errorf("invalid ether len=%d", len(ether))
	}
	if len(arpFrame) != 28 {
		t.Errorf("invalid arp len=%d", len(arpFrame))
	}

	// unmarschall
	ether.SetPayload(arpFrame)
	n := len(ether)
	ether = packet.Ether(ether[:n])
	arpFrame = ARP(ether.Payload())
	if err := ether.IsValid(); err != nil {
		t.Errorf("invalid ether=%s", ether)
	}
	if err := arpFrame.IsValid(); err != nil {
		t.Errorf("invalid arp=%s", err)
	}

}

func TestMarshalBinary(t *testing.T) {
	tests := []struct {
		name      string
		wantErr   bool
		proto     uint16
		operation uint16
		srcMAC    net.HardwareAddr
		srcIP     net.IP
		dstMAC    net.HardwareAddr
		dstIP     net.IP
	}{
		{name: "reply", wantErr: false, proto: syscall.ETH_P_ARP, operation: OperationReply, srcMAC: mac1, srcIP: ip1, dstMAC: mac2, dstIP: ip2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf, err := MarshalBinary(nil, tt.operation, packet.Addr{MAC: tt.srcMAC, IP: tt.srcIP}, packet.Addr{MAC: tt.dstMAC, IP: tt.dstIP})
			if (err != nil) != tt.wantErr {
				t.Errorf("%s: MarshalBinary() error = %v, wantErr %v", tt.name, err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			p := ARP(buf)
			if err := p.IsValid(); err != nil {
				t.Errorf("%s: invalid arp err=%s", tt.name, err)
			}
			if p.Operation() != tt.operation {
				t.Errorf("%s: invalid operation=%d want=%d", tt.name, p.Operation(), tt.operation)
			}
			if !bytes.Equal(p.SrcMAC(), tt.srcMAC) || !bytes.Equal(p.DstMAC(), tt.dstMAC) {
				t.Errorf("%s: invalid srcMAC=%s wantSrcMAC=%s dstMAC=%s wantDstMAC=%s", tt.name, p.SrcMAC(), tt.srcMAC, p.DstMAC(), tt.dstMAC)
			}
			if !p.SrcIP().Equal(tt.srcIP) || !p.DstIP().Equal(tt.dstIP) {
				t.Errorf("%s: invalid srcIP=%s wantSrcIP=%s dstIP=%s wantDstIP=%s", tt.name, p.SrcIP(), tt.srcIP, p.DstIP(), tt.dstIP)
			}
		})
	}
}
