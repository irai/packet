package dhcp4

import (
	"context"
	"net"
	"testing"
	"time"
)

func Test_ServerIsReacheable(t *testing.T) {
	type args struct {
		ctx     context.Context
		address string
	}
	tests := []struct {
		name    string
		ip      net.IP
		wantErr error
	}{
		{name: "google", ip: net.IPv4(8, 8, 8, 8), wantErr: nil},
		{name: "192.168.0.1", ip: net.IPv4(192, 168, 0, 1), wantErr: nil},
		// TODO: Add test cases.
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ServerIsReacheable(ctx, tt.ip)
			if err != tt.wantErr {
				t.Errorf("resolveDNS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
	cancel()
}
