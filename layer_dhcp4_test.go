package packet

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestMarshall(t *testing.T) {
	tests := []struct {
		name      string
		opcode    DHCP4OpCode
		mt        DHCP4MessageType
		chAddr    net.HardwareAddr
		ciAddr    netip.Addr
		yiAddr    netip.Addr
		xid       []byte
		broadcast bool
		options   DHCP4Options
		wantErr   bool
	}{
		{name: "simple", opcode: DHCP4BootRequest, mt: DHCP4Request, chAddr: mac1, ciAddr: ip1, yiAddr: netip.Addr{}, xid: []byte{1, 1, 1, 1}, broadcast: true, wantErr: false,
			options: DHCP4Options{
				DHCP4OptionSubnetMask:       []byte{255, 255, 255, 0}, // must occur before router
				DHCP4OptionRouter:           ip5.AsSlice(),
				DHCP4OptionDomainNameServer: ip4.AsSlice(),
				DHCP4OptionDHCPMessageType:  []byte{byte(DHCP4Request)},
			},
		},
	}
	buf := make([]byte, 1500)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dhcp := EncodeDHCP4(buf, tt.opcode, tt.mt, tt.chAddr, tt.ciAddr, tt.yiAddr, tt.xid, tt.broadcast, tt.options, tt.options[DHCP4OptionParameterRequestList])
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
			if v := dhcp.CIAddr(); tt.ciAddr.IsValid() && v != tt.ciAddr {
				t.Errorf("%s: Marshall() = invalid ciaddr got=%v, want=%v", tt.name, v, tt.ciAddr)
			}
			if v := dhcp.YIAddr(); tt.yiAddr.IsValid() && v != tt.yiAddr {
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
		opcode    DHCP4OpCode
		mt        DHCP4MessageType
		chAddr    net.HardwareAddr
		ciAddr    netip.Addr
		yiAddr    netip.Addr
		xid       []byte
		broadcast bool
		options   DHCP4Options
		wantErr   bool
	}
	buf := make([]byte, 1500)
	tt := ts{name: "changetoreply", opcode: DHCP4BootRequest, mt: DHCP4Discover, chAddr: mac1, ciAddr: netip.Addr{}, yiAddr: netip.Addr{}, xid: []byte{1, 1, 1, 1}, broadcast: true, wantErr: false, options: nil}
	dhcp := EncodeDHCP4(buf, tt.opcode, tt.mt, tt.chAddr, tt.ciAddr, tt.yiAddr, tt.xid, tt.broadcast, tt.options, tt.options[DHCP4OptionParameterRequestList])
	if err := dhcp.IsValid(); err != nil {
		t.Errorf("Marshall() = invalid dhcp error %v", err)
	}
	if v := dhcp.XId(); !bytes.Equal(v, tt.xid) {
		t.Errorf("%s: Marshall() = invalid xid got=%v, want=%v", tt.name, v, tt.xid)
	}
	if v := dhcp.CHAddr(); !bytes.Equal(v, tt.chAddr) {
		t.Errorf("%s: Marshall() = invalid chaddr got=%v, want=%v", tt.name, v, tt.chAddr)
	}
	if v := dhcp.CIAddr(); tt.ciAddr.IsValid() && v != tt.ciAddr {
		t.Errorf("%s: Marshall() = invalid ciaddr got=%v, want=%v", tt.name, v, tt.ciAddr)
	}
	if v := dhcp.YIAddr(); tt.yiAddr.IsValid() && v != tt.yiAddr {
		t.Errorf("%s: Marshall() = invalid yiaddr got=%v, want=%v", tt.name, v, tt.yiAddr)
	}
	if v := dhcp.Broadcast(); v != tt.broadcast {
		t.Errorf("%s: Marshall() = invalid broadcast got=%v, want=%v, flags=0x%x", tt.name, v, tt.broadcast, dhcp.Flags())
	}

	options := DHCP4Options{
		DHCP4OptionSubnetMask:         []byte{255, 255, 255, 0}, // must occur before router
		DHCP4OptionRouter:             ip5.AsSlice(),
		DHCP4OptionDomainNameServer:   ip4.AsSlice(),
		DHCP4OptionServerIdentifier:   hostIP4.AsSlice(),
		DHCP4OptionDHCPMessageType:    []byte{byte(DHCP4Request)},
		DHCP4OptionIPAddressLeaseTime: OptionsLeaseTime(time.Second * 10),
	}
	dhcp = EncodeDHCP4(dhcp, DHCP4BootReply, DHCP4Offer, nil, netip.Addr{}, ip3, nil, false, options, options[DHCP4OptionParameterRequestList])
	if err := dhcp.IsValid(); err != nil {
		t.Errorf("Marshall() = invalid dhcp error %v", err)
	}
	if v := dhcp.XId(); !bytes.Equal(v, tt.xid) {
		t.Errorf("%s: Marshall() = invalid xid got=%v, want=%v", tt.name, v, tt.xid)
	}
	if v := dhcp.CHAddr(); !bytes.Equal(v, tt.chAddr) {
		t.Errorf("%s: Marshall() = invalid chaddr got=%v, want=%v", tt.name, v, tt.chAddr)
	}
	if v := dhcp.CIAddr(); tt.ciAddr.IsValid() && v != tt.ciAddr {
		t.Errorf("%s: Marshall() = invalid ciaddr got=%v, want=%v", tt.name, v, tt.ciAddr)
	}
	if v := dhcp.YIAddr(); v != ip3 {
		t.Errorf("%s: Marshall() = invalid yiaddr got=%v, want=%v", tt.name, v, tt.yiAddr)
	}
	if v := dhcp.Broadcast(); v != false {
		t.Errorf("%s: Marshall() = invalid broadcast got=%v, want=%v, flags=0x%x", tt.name, v, tt.broadcast, dhcp.Flags())
	}

	// must receive three options at least
	options = dhcp.ParseOptions()
	if !bytes.Equal(options[DHCP4OptionDHCPMessageType], []byte{byte(DHCP4Offer)}) ||
		!bytes.Equal(options[DHCP4OptionIPAddressLeaseTime], []byte{0, 0, 0, 10}) ||
		!bytes.Equal(options[DHCP4OptionServerIdentifier], hostIP4.AsSlice()) {
		t.Errorf("%s: Marshall() = invalid options got=%v", tt.name, options)
	}

}
