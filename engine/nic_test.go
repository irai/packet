package engine

import (
	"bytes"
	"net"
	"testing"
)

func TestSegmentLAN(t *testing.T) {
	tests := []struct {
		name            string
		routerIP        net.IPNet
		wantNetfilterIP net.IPNet
		wantErr         bool
	}{
		{name: "192.168.1.0", wantErr: false,
			routerIP:        net.IPNet{IP: net.IPv4(192, 168, 1, 0), Mask: net.IPv4Mask(255, 255, 255, 0)},
			wantNetfilterIP: net.IPNet{IP: net.IPv4(192, 168, 1, 129), Mask: net.IPv4Mask(255, 255, 255, 128)}},
		{name: "192.168.1.1", wantErr: false,
			routerIP:        net.IPNet{IP: net.IPv4(192, 168, 1, 1), Mask: net.IPv4Mask(255, 255, 255, 0)},
			wantNetfilterIP: net.IPNet{IP: net.IPv4(192, 168, 1, 129), Mask: net.IPv4Mask(255, 255, 255, 128)}},
		{name: "192.168.1.127", wantErr: false,
			routerIP:        net.IPNet{IP: net.IPv4(192, 168, 1, 127), Mask: net.IPv4Mask(255, 255, 255, 0)},
			wantNetfilterIP: net.IPNet{IP: net.IPv4(192, 168, 1, 129), Mask: net.IPv4Mask(255, 255, 255, 128)}},
		{name: "192.168.1.128", wantErr: false,
			routerIP:        net.IPNet{IP: net.IPv4(192, 168, 1, 128), Mask: net.IPv4Mask(255, 255, 255, 0)},
			wantNetfilterIP: net.IPNet{IP: net.IPv4(192, 168, 1, 1), Mask: net.IPv4Mask(255, 255, 255, 128)}},
		{name: "192.168.1.255", wantErr: false,
			routerIP:        net.IPNet{IP: net.IPv4(192, 168, 1, 255), Mask: net.IPv4Mask(255, 255, 255, 0)},
			wantNetfilterIP: net.IPNet{IP: net.IPv4(192, 168, 1, 1), Mask: net.IPv4Mask(255, 255, 255, 128)}},
		{name: "too small", wantErr: true,
			routerIP:        net.IPNet{IP: net.IPv4(192, 168, 1, 10), Mask: net.IPv4Mask(255, 255, 255, 128)},
			wantNetfilterIP: net.IPNet{IP: net.IPv4(192, 168, 1, 10), Mask: net.IPv4Mask(255, 255, 255, 64)}},
		{name: "too big", wantErr: false,
			routerIP:        net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.IPv4Mask(255, 255, 0, 0)},
			wantNetfilterIP: net.IPNet{IP: net.IPv4(10, 0, 0, 129), Mask: net.IPv4Mask(255, 255, 255, 128)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNetfilterIP, err := SegmentLAN("",
				net.IPNet{IP: net.IPv4(192, 168, 1, 100), Mask: net.IPv4Mask(255, 255, 255, 0)},
				net.IPv4(192, 168, 1, 100),
				tt.routerIP.IP)
			if (err != nil) != tt.wantErr {
				t.Errorf("SegmentLAN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if !gotNetfilterIP.IP.Equal(tt.wantNetfilterIP.IP) || !bytes.Equal(gotNetfilterIP.Mask, tt.wantNetfilterIP.Mask) {
				t.Errorf("SegmentLAN() = %v, want %v", gotNetfilterIP, tt.wantNetfilterIP)
			}
		})
	}
}
