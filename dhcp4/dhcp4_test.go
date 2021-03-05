package dhcp4

import (
	"net"
	"reflect"
	"testing"

	"github.com/irai/packet"
)

func TestAttach(t *testing.T) {
	type args struct {
		engine      *packet.Handler
		netfilterIP net.IPNet
		dnsServer   net.IP
		filename    string
	}
	tests := []struct {
		name        string
		args        args
		wantHandler *Handler
		wantErr     bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHandler, err := Attach(tt.args.engine, tt.args.netfilterIP, tt.args.dnsServer, tt.args.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("Attach() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotHandler, tt.wantHandler) {
				t.Errorf("Attach() = %v, want %v", gotHandler, tt.wantHandler)
			}
		})
	}
}
