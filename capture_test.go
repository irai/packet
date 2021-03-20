package packet

import (
	"testing"
)

func TestHandler_Capture(t *testing.T) {
	tests := []struct {
		name    string
		addr    Addr
		wantErr bool
	}{
		{name: "newmac", addr: Addr{MAC: mac1, IP: ip1}, wantErr: false},

		// TODO: Add test cases.
	}

	tc := setupTestHandler()
	defer tc.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tc.engine.Capture(tt.addr.MAC); (err != nil) != tt.wantErr {
				t.Errorf("Handler.Capture() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
