package packet

import (
	"fmt"
	"testing"
)

// Each of these; repeated 4 times with 2 sec interval - one per port perhaps?
// RRCP frame type=0x8899 src=b0:da:f9:4c:c4:4f dst=ff:ff:ff:ff:ff:ff len=60 payload="23 a0 7a 2a fc 9b 62 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
// RRCP frame type=0x8899 src=b0:da:f9:4c:c4:4f dst=ff:ff:ff:ff:ff:ff len=60 payload="23 0a 8e 67 f0 33 76 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
// RRCP frame type=0x8899 src=b0:da:f9:4c:c4:4f dst=ff:ff:ff:ff:ff:ff len=60 payload="23 93 06 dc 5c 83 1b 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
// RRCP frame type=0x8899 src=b0:da:f9:4c:c4:4f dst=ff:ff:ff:ff:ff:ff len=60 payload="23 b0 fb c0 5a b1 c7 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
// RRCP frame type=0x8899 src=b0:da:f9:4c:c4:4f dst=ff:ff:ff:ff:ff:ff len=60 payload="23 d4 cd a8 d4 d3 16 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
// RRCP frame type=0x8899 src=b0:da:f9:4c:c4:4f dst=ff:ff:ff:ff:ff:ff len=60 payload="23 35 2f 01 fd 38 70 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
// RRCP frame type=0x8899 src=b0:da:f9:4c:c4:4f dst=ff:ff:ff:ff:ff:ff len=60 payload="23 a6 20 28 c6 c5 59 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
// RRCP frame type=0x8899 src=b0:da:f9:4c:c4:4f dst=ff:ff:ff:ff:ff:ff len=60 payload="23 44 67 b5 f3 70 51 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
// RRCP frame type=0x8899 src=b0:da:f9:4c:c4:4f dst=ff:ff:ff:ff:ff:ff len=60 payload="23 45 73 66 6f a3 96 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
// RRCP frame type=0x8899 src=b0:da:f9:4c:c4:4f dst=ff:ff:ff:ff:ff:ff len=60 payload="23 1e 86 fb 1f 4e f2 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
//
// hex representations
//   0    1    2    3    4    5    6    7    8    9   A     B    C   D    E    F
// 0000 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111
// binary from second byte after 0x23
//  a     0     7    a     2    a
// 1010 0000, 0111 1010, 0010 1010
// 0000 1010, 1000 1110, 0110 0111
// 1001 0011, 0000 0110, 1101 1100
// 1011 0000, 1111 1011, 1100 0000
// 1101 0001, 1100 1101, 1010 1000

func TestRRCP_IsValid(t *testing.T) {
	tests := []struct {
		name    string
		p       []byte
		wantErr error
	}{
		{name: "rrcp1", wantErr: nil,
			p: []byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x55, 0x55, 0x55, 0x55, 0x55, 0x88, 0x99, //ether packet
				0x23, 0xd0, 0x44, 0xa2, 0x2e, 0xc3, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rrcp := RRCP(tt.p)
			if got := rrcp.IsValid(); got != tt.wantErr {
				t.Errorf("RRCP.IsValid() = %v, want %v", got, tt.wantErr)
			}
			fmt.Println(rrcp)
		})
	}
}
