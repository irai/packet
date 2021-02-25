package arp

import (
	"bytes"
	"net"
	"syscall"
	"testing"

	"github.com/irai/packet/raw"
)

func tFrame(proto uint16, operation uint16, srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) []byte {
	b, _ := ARPMarshalBinary(nil, operation, srcMAC, srcIP, dstMAC, dstIP)
	return b
}

func TestMarshalUnmarshall(t *testing.T) {
	// marshall
	buf := make([]byte, raw.EthMaxSize) // allocate in the stack
	ether := raw.EtherMarshalBinary(buf, syscall.ETH_P_ARP, mac1, mac2)
	arpFrame, err := ARPMarshalBinary(ether.Payload(), OperationRequest, mac1, ip1, mac2, ip2)
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
	n := len(ether) + len(arpFrame)
	ether = raw.Ether(ether[:n])
	arpFrame = ARP(ether.Payload())
	if !ether.IsValid() {
		t.Errorf("invalid ether=%s", ether)
	}
	if !arpFrame.IsValid() {
		t.Errorf("invalid arp=%s", arpFrame)
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
			buf, err := ARPMarshalBinary(nil, tt.operation, tt.srcMAC, tt.srcIP, tt.dstMAC, tt.dstIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("%s: MarshalBinary() error = %v, wantErr %v", tt.name, err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			p := ARP(buf)
			if !p.IsValid() {
				t.Errorf("%s: invalid arp frame=%s", tt.name, p)
			}
			if p.Operation() != tt.operation {
				t.Errorf("%s: invalid operation=%d want=%d", tt.name, p.Operation(), tt.operation)
			}
			if !bytes.Equal(p.SrcMAC(), tt.srcMAC) || !bytes.Equal(p.DstMAC(), tt.dstMAC) {
				t.Errorf("%s: invalid srcMAC=%s wantSrcMAC=%s dstMAC=%s wantDstMAC=%s", tt.name, p.SrcMAC(), tt.srcMAC, p.DstMAC(), tt.dstMAC)
			}
			if !bytes.Equal(p.SrcIP(), tt.srcIP) || !bytes.Equal(p.DstIP(), tt.dstIP) {
				t.Errorf("%s: invalid srcIP=%s wantSrcIP=%s dstIP=%s wantDstIP=%s", tt.name, p.SrcIP(), tt.srcIP, p.DstIP(), tt.dstIP)
			}
		})
	}
}
