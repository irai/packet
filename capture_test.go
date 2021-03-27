package packet

import (
	"testing"
	"time"
)

func TestHandler_Capture(t *testing.T) {
	addr1 := Addr{MAC: mac1, IP: ip1}
	addr2 := Addr{MAC: mac1, IP: ip2} // same mac
	addr3 := Addr{MAC: mac1, IP: ip3} // same mac
	tests := []struct {
		name          string
		operation     string
		addr          Addr
		dhcp4Stage    HuntStage
		icmp4Stage    HuntStage
		wantErr       bool
		wantCaptured  bool
		wantOnline    bool
		wantMACOnline bool
		wantStage     HuntStage
	}{
		// Simple
		{name: "1-ip1-capture", operation: "capture", addr: addr1, wantErr: false,
			wantCaptured: true, wantOnline: false, wantStage: StageNormal, wantMACOnline: false}, // we are offline so want stage normal
		{name: "1-ip1-online", operation: "online", addr: addr1, wantErr: false,
			wantCaptured: true, wantOnline: true, wantStage: StageHunt, wantMACOnline: true},
		{name: "1-ip1-release", operation: "release", addr: addr1, wantErr: false,
			wantCaptured: false, wantOnline: true, wantStage: StageNormal, wantMACOnline: true},

		// online and offline
		{name: "2-ip1-capture", operation: "capture", addr: addr1, wantErr: false,
			wantCaptured: true, wantOnline: true, wantStage: StageHunt, wantMACOnline: true},
		{name: "2-ip1-online", operation: "online", addr: addr1, wantErr: false,
			wantCaptured: true, wantOnline: true, wantStage: StageHunt, wantMACOnline: true},
		{name: "2-ip1-offline", operation: "offline", addr: addr1, wantErr: false,
			wantCaptured: true, wantOnline: false, wantStage: StageNormal, wantMACOnline: true},
		{name: "2-ip1-online", operation: "online", addr: addr1, wantErr: false,
			wantCaptured: true, wantOnline: true, wantStage: StageHunt, wantMACOnline: true},
		{name: "2-ip1-release", operation: "release", addr: addr1, wantErr: false,
			wantCaptured: false, wantOnline: true, wantStage: StageNormal, wantMACOnline: true},

		// Two IP4s
		{name: "3-ip1-capture", operation: "capture", addr: addr1, wantErr: false,
			wantCaptured: true, wantOnline: true, wantStage: StageHunt, wantMACOnline: true},
		{name: "3-ip1-online", operation: "online", addr: addr1, wantErr: false,
			wantCaptured: true, wantOnline: true, wantStage: StageHunt, wantMACOnline: true},
		{name: "3-ip2-online", operation: "online", addr: addr2, wantErr: false,
			wantCaptured: true, wantOnline: true, wantStage: StageHunt, wantMACOnline: true},
		{name: "3-ip1-offline", operation: "offline", addr: addr1, wantErr: false,
			wantCaptured: true, wantOnline: false, wantStage: StageNormal, wantMACOnline: true},
		{name: "3-ip2-check", operation: "check", addr: addr2, wantErr: false,
			wantCaptured: true, wantOnline: true, wantStage: StageHunt, wantMACOnline: true},
		{name: "3-ip1-online", operation: "online", addr: addr1, wantErr: false,
			wantCaptured: true, wantOnline: true, wantStage: StageHunt, wantMACOnline: true},
		{name: "3-ip2-check2", operation: "check", addr: addr2, wantErr: false,
			wantCaptured: true, wantOnline: false, wantStage: StageNormal, wantMACOnline: true},
		{name: "3-ip1-release", operation: "release", addr: addr1, wantErr: false,
			wantCaptured: false, wantOnline: true, wantStage: StageNormal, wantMACOnline: true},

		// Single IP - icmp4 and dhcp transition
		{name: "4-ip3-capture", operation: "capture", addr: addr3, wantErr: false,
			wantCaptured: true, wantOnline: false, wantStage: StageNormal, wantMACOnline: true},
		{name: "4-ip3-online", operation: "online", addr: addr3, wantErr: false,
			wantCaptured: true, wantOnline: true, wantStage: StageHunt, wantMACOnline: true},
		{name: "4-ip3-transition", operation: "transition", addr: addr3, wantErr: false, dhcp4Stage: StageRedirected, icmp4Stage: StageNoChange,
			wantCaptured: true, wantOnline: true, wantStage: StageRedirected, wantMACOnline: true},
		{name: "4-ip3-offline", operation: "offline", addr: addr3, wantErr: false,
			wantCaptured: true, wantOnline: false, wantStage: StageNormal, wantMACOnline: true},
		{name: "4-ip3-online", operation: "online", addr: addr3, wantErr: false,
			wantCaptured: true, wantOnline: true, wantStage: StageHunt, wantMACOnline: true},
		{name: "4-ip3-release", operation: "release", addr: addr3, wantErr: false,
			wantCaptured: false, wantOnline: true, wantStage: StageNormal, wantMACOnline: true},
	}

	Debug = true

	tc := setupTestHandler()
	defer tc.Close()

	// two hosts, same MAC
	tc.engine.FindOrCreateHost(addr1.MAC, addr1.IP)
	tc.engine.FindOrCreateHost(addr2.MAC, addr2.IP) // same mac as addr1
	tc.engine.FindOrCreateHost(addr3.MAC, addr3.IP) // same mac as addr1
	// host.dhcp4Store.HuntStage = StageRedirected                // fix stage to redirected to pass test 4

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.operation {
			case "online":
				host := tc.engine.MustFindIP(tt.addr.IP)
				tc.engine.lockAndSetOnline(host, false)
				time.Sleep(time.Millisecond * 3)
			case "offline":
				host := tc.engine.MustFindIP(tt.addr.IP)
				tc.engine.lockAndSetOffline(host)
				time.Sleep(time.Millisecond * 3)
			case "capture":
				if err := tc.engine.Capture(tt.addr.MAC); (err != nil) != tt.wantErr {
					t.Errorf("Handler.Capture() error = %v, wantErr %v", err, tt.wantErr)
				}
				time.Sleep(time.Millisecond * 3)
			case "release":
				if err := tc.engine.Release(tt.addr.MAC); (err != nil) != tt.wantErr {
					t.Errorf("Handler.Capture() error = %v, wantErr %v", err, tt.wantErr)
				}
				time.Sleep(time.Millisecond * 3)
			case "transition":
				host := tc.engine.MustFindIP(tt.addr.IP)
				tc.engine.lockAndTransitionHuntStage(host, tt.dhcp4Stage, tt.icmp4Stage)
				time.Sleep(time.Millisecond * 3)
			case "check":
				// do nothing; just check fields
			default:
				t.Errorf("invalid option")
				return
			}

			host := tc.engine.MustFindIP(tt.addr.IP)
			host.Row.RLock()
			if host.MACEntry.Captured != tt.wantCaptured {
				t.Errorf("Handler.Capture() invalid capture state got=%v, want=%v", host.MACEntry.Captured, tt.wantCaptured)
				tc.engine.printHostTable()
			}
			if host.huntStage != tt.wantStage {
				t.Errorf("Handler.Capture() invalid stage got=%v, want=%v", host.huntStage, tt.wantStage)
				tc.engine.printHostTable()
			}
			if host.Online != tt.wantOnline {
				t.Errorf("Handler.Capture() invalid online got=%v, want=%v", host.Online, tt.wantOnline)
			}
			if host.MACEntry.Online != tt.wantMACOnline {
				t.Errorf("Handler.Capture() invalid online MAC got=%v, want=%v", host.MACEntry.Online, tt.wantMACOnline)
			}
			host.Row.RUnlock()
		})
	}
	tc.engine.PrintTable()
}
