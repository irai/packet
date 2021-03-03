package arp

/***
func Test_Spoof_ForceIPChange(t *testing.T) {
	//Debug = true
	// log.SetLevel(log.DebugLevel)
	tc := setupTestHandler(t)
	defer tc.Close()

	packet.Debug = true

	e2, _ := tc.arp.virtual.upsert(StateNormal, mac2, ip2)
	tc.arp.virtual.updateIP(e2, ip3)
	tc.arp.virtual.updateIP(e2, ip4)
	tc.arp.startSpoof(e2.MAC)

	tc.arp.Lock()
	if e := tc.arp.virtual.findByMAC(mac2); e == nil || e.State != StateHunt {
		t.Fatalf("Test_ForceIPChange entry2 state=%s", e.State)
	}
	tc.arp.Unlock()

	tests := []struct {
		name    string
		ether   packet.Ether
		arp     ARP
		wantErr error
		wantLen int
		wantIPs int
	}{
		{name: "requestMAC2-IP4",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip4, zeroMAC, ip4),
			wantErr: nil, wantLen: 4, wantIPs: 3},
		{name: "requestMAC2-IP4-2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip4, zeroMAC, ip4),
			wantErr: nil, wantLen: 4, wantIPs: 3},
		{name: "requestMAC2-iP5",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip5, zeroMAC, ip5),
			wantErr: nil, wantLen: 4, wantIPs: 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ether, err := tt.ether.AppendPayload(tt.arp)
			if err != nil {
				panic(err)
			}
			if _, err := tc.outConn.WriteTo(ether, nil); err != tt.wantErr {
				t.Errorf("TestHandler_ForceIPChange:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			time.Sleep(time.Millisecond * 10)

			tc.arp.Lock()
			defer tc.arp.Unlock()

			if len(tc.arp.virtual.macTable) != tt.wantLen {
				tc.arp.PrintTable()
				t.Errorf("TestHandler_ForceIPChange:%s table len = %v, wantLen %v", tt.name, len(tc.arp.virtual.macTable), tt.wantLen)
			}
			if tt.wantIPs != 0 {
				e := tc.arp.virtual.findByMAC(tt.arp.SrcMAC())
				if e == nil || len(e.IPs()) != tt.wantIPs {
					t.Errorf("TestHandler_ForceIPChange:%s table IP entry=%+v, wantLen %v", tt.name, e, tt.wantLen)
				}
			}
		})
	}

	tc.arp.Lock()
	defer tc.arp.Unlock()

	if entry := tc.arp.virtual.findVirtualIP(ip2); entry == nil {
		t.Errorf("TestHandler_ForceIPChange invalid virtual ip2")
	}
	if entry := tc.arp.virtual.findVirtualIP(ip3); entry == nil {
		t.Errorf("TestHandler_ForceIPChange invalid virtual ip3")
	}
	if entry := tc.arp.virtual.findVirtualIP(ip4); entry == nil {
		t.Errorf("TestHandler_ForceIPChange invalid virtual ip4")
	}
	if entry := tc.arp.virtual.findVirtualIP(ip5); entry != nil {
		t.Errorf("TestHandler_ForceIPChange invalid virtual ip5")
	}
	if entry := tc.arp.virtual.findByIP(ip5); entry == nil || entry.State != StateNormal || len(entry.IPs()) != 4 {
		tc.arp.PrintTable()
		t.Errorf("TestHandler_ForceIPChange invalid virtual ip52 entry=%+v", entry)
	}
}
***/
