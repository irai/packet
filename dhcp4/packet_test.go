package dhcp4

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestMarshall(t *testing.T) {
	tests := []struct {
		name      string
		opcode    OpCode
		mt        MessageType
		chAddr    net.HardwareAddr
		ciAddr    net.IP
		yiAddr    net.IP
		xid       []byte
		broadcast bool
		options   Options
		wantErr   bool
	}{
		{name: "simple", opcode: BootRequest, mt: Request, chAddr: mac0, ciAddr: ip1, yiAddr: nil, xid: []byte{1, 1, 1, 1}, broadcast: true, wantErr: false,
			options: Options{
				OptionSubnetMask:       []byte{255, 255, 255, 0}, // must occur before router
				OptionRouter:           ip5.To4(),
				OptionDomainNameServer: ip4.To4(),
				OptionDHCPMessageType:  []byte{byte(Request)},
			},
		},
	}
	buf := make([]byte, 1500)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dhcp := Marshall(buf, tt.opcode, tt.mt, tt.chAddr, tt.ciAddr, tt.yiAddr, tt.xid, tt.broadcast, tt.options, tt.options[OptionParameterRequestList])
			if (dhcp == nil) != tt.wantErr {
				t.Errorf("Marshall() = %v, want %v", dhcp, tt.wantErr)
			}
			if dhcp == nil {
				return
			}
			if err := dhcp.IsValid(); err != nil {
				t.Errorf("Marshall() = invalid dhcp error %v", err)
			}
			if v := dhcp.XId(); !bytes.Equal(v, tt.xid) {
				t.Errorf("%s: Marshall() = invalid xid got=%v, want=%v", tt.name, v, tt.xid)
			}
			if v := dhcp.CHAddr(); !bytes.Equal(v, tt.chAddr) {
				t.Errorf("%s: Marshall() = invalid chaddr got=%v, want=%v", tt.name, v, tt.chAddr)
			}
			if v := dhcp.CIAddr(); tt.ciAddr != nil && !v.Equal(tt.ciAddr) {
				t.Errorf("%s: Marshall() = invalid ciaddr got=%v, want=%v", tt.name, v, tt.ciAddr)
			}
			if v := dhcp.YIAddr(); tt.yiAddr != nil && !v.Equal(tt.yiAddr) {
				t.Errorf("%s: Marshall() = invalid yiaddr got=%v, want=%v", tt.name, v, tt.yiAddr)
			}
			if v := dhcp.Broadcast(); v != tt.broadcast {
				t.Errorf("%s: Marshall() = invalid broadcast got=%v, want=%v, flags=0x%x", tt.name, v, tt.broadcast, dhcp.Flags())
			}
			fmt.Println("dhcp packet ", dhcp, dhcp.ParseOptions())
		})
	}
}

func TestMarshallChangeToReply(t *testing.T) {
	type ts struct {
		name      string
		opcode    OpCode
		mt        MessageType
		chAddr    net.HardwareAddr
		ciAddr    net.IP
		yiAddr    net.IP
		xid       []byte
		broadcast bool
		options   Options
		wantErr   bool
	}
	buf := make([]byte, 1500)
	tt := ts{name: "changetoreply", opcode: BootRequest, mt: Discover, chAddr: mac1, ciAddr: nil, yiAddr: nil, xid: []byte{1, 1, 1, 1}, broadcast: true, wantErr: false, options: nil}
	dhcp := Marshall(buf, tt.opcode, tt.mt, tt.chAddr, tt.ciAddr, tt.yiAddr, tt.xid, tt.broadcast, tt.options, tt.options[OptionParameterRequestList])
	if err := dhcp.IsValid(); err != nil {
		t.Errorf("Marshall() = invalid dhcp error %v", err)
	}
	if v := dhcp.XId(); !bytes.Equal(v, tt.xid) {
		t.Errorf("%s: Marshall() = invalid xid got=%v, want=%v", tt.name, v, tt.xid)
	}
	if v := dhcp.CHAddr(); !bytes.Equal(v, tt.chAddr) {
		t.Errorf("%s: Marshall() = invalid chaddr got=%v, want=%v", tt.name, v, tt.chAddr)
	}
	if v := dhcp.CIAddr(); tt.ciAddr != nil && !v.Equal(tt.ciAddr) {
		t.Errorf("%s: Marshall() = invalid ciaddr got=%v, want=%v", tt.name, v, tt.ciAddr)
	}
	if v := dhcp.YIAddr(); tt.yiAddr != nil && !v.Equal(tt.yiAddr) {
		t.Errorf("%s: Marshall() = invalid yiaddr got=%v, want=%v", tt.name, v, tt.yiAddr)
	}
	if v := dhcp.Broadcast(); v != tt.broadcast {
		t.Errorf("%s: Marshall() = invalid broadcast got=%v, want=%v, flags=0x%x", tt.name, v, tt.broadcast, dhcp.Flags())
	}

	options := Options{
		OptionSubnetMask:         []byte{255, 255, 255, 0}, // must occur before router
		OptionRouter:             ip5.To4(),
		OptionDomainNameServer:   ip4.To4(),
		OptionServerIdentifier:   hostIP4,
		OptionDHCPMessageType:    []byte{byte(Request)},
		OptionIPAddressLeaseTime: optionsLeaseTime(time.Second * 10),
	}
	dhcp = Marshall(dhcp, BootReply, Offer, nil, nil, ip3, nil, false, options, options[OptionParameterRequestList])
	if err := dhcp.IsValid(); err != nil {
		t.Errorf("Marshall() = invalid dhcp error %v", err)
	}
	if v := dhcp.XId(); !bytes.Equal(v, tt.xid) {
		t.Errorf("%s: Marshall() = invalid xid got=%v, want=%v", tt.name, v, tt.xid)
	}
	if v := dhcp.CHAddr(); !bytes.Equal(v, tt.chAddr) {
		t.Errorf("%s: Marshall() = invalid chaddr got=%v, want=%v", tt.name, v, tt.chAddr)
	}
	if v := dhcp.CIAddr(); tt.ciAddr != nil && !v.Equal(tt.ciAddr) {
		t.Errorf("%s: Marshall() = invalid ciaddr got=%v, want=%v", tt.name, v, tt.ciAddr)
	}
	if v := dhcp.YIAddr(); !v.Equal(ip3) {
		t.Errorf("%s: Marshall() = invalid yiaddr got=%v, want=%v", tt.name, v, tt.yiAddr)
	}
	if v := dhcp.Broadcast(); v != false {
		t.Errorf("%s: Marshall() = invalid broadcast got=%v, want=%v, flags=0x%x", tt.name, v, tt.broadcast, dhcp.Flags())
	}

	// must receive three options at least
	options = dhcp.ParseOptions()
	if !bytes.Equal(options[OptionDHCPMessageType], []byte{byte(Offer)}) || !bytes.Equal(options[OptionIPAddressLeaseTime], []byte{0, 0, 0, 10}) || !bytes.Equal(options[OptionServerIdentifier], hostIP4) {
		t.Errorf("%s: Marshall() = invalid options got=%v", tt.name, options)
	}

}
