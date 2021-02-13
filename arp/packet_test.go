package arp

import (
	"bytes"
	"net"
	"syscall"
	"testing"
)

func tFrame(proto uint16, operation uint16, srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) []byte {
	b, _ := ARPMarshalBinary(nil, operation, srcMAC, srcIP, dstMAC, dstIP)
	return b
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
