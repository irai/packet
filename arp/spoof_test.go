package arp

import (
	"testing"
	"time"

	"github.com/irai/packet"
)

func TestHandler_ForceIPChange(t *testing.T) {
	//Debug = true
	// log.SetLevel(log.DebugLevel)
	tc := setupTestHandler(t)
	defer tc.Close()

	packet.Debug = true

	e2, _ := tc.arp.table.upsert(StateNormal, mac2, ip2)
	e2.Online = true
	tc.arp.table.updateIP(e2, ip3)
	tc.arp.table.updateIP(e2, ip4)
	tc.arp.ForceIPChange(e2.MAC, true)

	if e := tc.arp.table.findByMAC(mac2); e == nil || e.State != StateHunt || !e.Online {
		t.Fatalf("Test_ForceIPChange entry2 state=%s, online=%v", e.State, e.Online)
	}

	tests := []struct {
		name    string
		packet  ARP
		wantErr error
		wantLen int
		wantIPs int
	}{
		{"request3", newPacket(OperationRequest, mac2, ip4, zeroMAC, ip4), nil, 4, 3},
		{"request4", newPacket(OperationRequest, mac2, ip4, zeroMAC, ip4), nil, 4, 3},
		{"request5", newPacket(OperationRequest, mac2, ip5, zeroMAC, ip5), nil, 4, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tc.client.WriteTo(tt.packet, nil); err != tt.wantErr {
				t.Errorf("TestHandler_ForceIPChange:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			time.Sleep(time.Millisecond * 10)
			if len(tc.arp.table.macTable) != tt.wantLen {
				tc.arp.PrintTable()
				t.Errorf("TestHandler_ForceIPChange:%s table len = %v, wantLen %v", tt.name, len(tc.arp.table.macTable), tt.wantLen)
			}
			if tt.wantIPs != 0 {
				e := tc.arp.table.findByMAC(tt.packet.SrcMAC())
				if e == nil || len(e.IPs()) != tt.wantIPs {
					t.Errorf("TestHandler_ForceIPChange:%s table IP entry=%+v, wantLen %v", tt.name, e, tt.wantLen)
				}
			}
		})
	}

	if entry := tc.arp.table.findVirtualIP(ip2); entry == nil {
		t.Errorf("TestHandler_ForceIPChange invalid virtual ip2")
	}
	if entry := tc.arp.table.findVirtualIP(ip3); entry == nil {
		t.Errorf("TestHandler_ForceIPChange invalid virtual ip3")
	}
	if entry := tc.arp.table.findVirtualIP(ip4); entry == nil {
		t.Errorf("TestHandler_ForceIPChange invalid virtual ip4")
	}
	if entry := tc.arp.table.findVirtualIP(ip5); entry != nil {
		t.Errorf("TestHandler_ForceIPChange invalid virtual ip5")
	}
	if entry := tc.arp.table.findByIP(ip5); entry == nil || entry.State != StateNormal || len(entry.IPs()) != 4 {
		tc.arp.PrintTable()
		t.Errorf("TestHandler_ForceIPChange invalid virtual ip52 entry=%+v", entry)
	}
}
