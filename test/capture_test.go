package test

import (
	"net"
	"testing"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/dhcp4"
)

func TestHandler_captureNormal(t *testing.T) {
	tc := NewTestContext()
	defer tc.Close()

	// log.SetLevel(log.DebugLevel)
	dhcp4.Debug = false
	packet.Debug = true
	arp.Debug = true

	tests := []TestEvent{}

	// MAC1 - capture after dhcp - ip1
	addr := packet.Addr{MAC: MAC1}
	tests = append(tests, NewHostEvents(addr, "mac1", 1, 1)...)
	tests = append(tests, TestEvent{name: "capture-" + addr.MAC.String(), hostTableInc: 0, macTableInc: 0, responsePos: 0, responseTableInc: -1, // -1 means don't count
		waitTimeAfter: time.Millisecond * 10,
		action:        "capture", srcAddr: packet.Addr{MAC: addr.MAC, IP: net.IPv4zero},
	})
	tests = append(tests, NewHostEvents(addr, "mac1", 1, 0)...) // get a second IP with captured net - ip 192.168.0.130

	// MAC2 - capture before dhcp discover - ip 192.168.0.131
	addr = packet.Addr{MAC: MAC2}
	tests = append(tests, TestEvent{name: "capture-" + addr.MAC.String(), hostTableInc: 0, macTableInc: 0, responsePos: 0, responseTableInc: -1, // -1 means don't count
		action: "capture", srcAddr: packet.Addr{MAC: addr.MAC, IP: net.IPv4zero},
	})
	tests = append(tests, NewHostEvents(addr, "mac2", 1, 0)...)

	// capture MAC1 again - ip 192.168.0.130
	addr = packet.Addr{MAC: MAC1}
	tests = append(tests, TestEvent{name: "capture-" + addr.MAC.String(), hostTableInc: 0, macTableInc: 0, responsePos: 0, responseTableInc: -1, // -1 means don't count
		waitTimeAfter: time.Millisecond * 10,
		action:        "capture", srcAddr: packet.Addr{MAC: addr.MAC, IP: net.IPv4zero},
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})
	}
	checkOnlineCount(t, tc, 4, 1)
	checkCaptureCount(t, tc, 3, 2)

	t.Run("stage check", func(t *testing.T) {
		// initial ip must be set to offline and stage normal
		if host := tc.Engine.Session().FindIP(net.IPv4(192, 168, 0, 1)); host == nil || host.Online != false || host.HuntStage != packet.StageNormal {
			tc.Engine.PrintTable()
			t.Fatalf("unexpected host variables %s ", host)
		}
		// captured ip must be set to online and stage redirected
		if host := tc.Engine.Session().FindIP(net.IPv4(192, 168, 0, 130)); host == nil || host.Online != true || host.HuntStage != packet.StageRedirected {
			tc.Engine.PrintTable()
			t.Fatalf("unexpected host variables %s ", host)
		}
	})
}

func TestHandler_captureDHCP(t *testing.T) {
	tc := NewTestContext()
	defer tc.Close()

	// log.SetLevel(log.DebugLevel)
	dhcp4.Debug = false
	packet.Debug = true
	arp.Debug = true

	tests := []TestEvent{}

	// MAC1 - capture after dhcp
	addr := packet.Addr{MAC: MAC1}
	tests = append(tests, NewHostEvents(addr, "mac1", 1, 1)...)
	tests = append(tests, TestEvent{name: "capture-" + addr.MAC.String(), hostTableInc: 0, macTableInc: 0, responsePos: 0, responseTableInc: -1, // -1 means don't count
		waitTimeAfter: time.Millisecond * 10,
		action:        "capture", srcAddr: packet.Addr{MAC: addr.MAC, IP: net.IPv4zero},
	})

	// simulate another host - request a different IP
	tests = append(tests, []TestEvent{
		{name: "discover2-" + addr.MAC.String(), action: "dhcp4Discover", hostTableInc: 0, macTableInc: 0, responsePos: -1, responseTableInc: -1,
			srcAddr:       packet.Addr{MAC: addr.MAC, IP: net.IPv4zero},
			wantHost:      nil, // don't validate host
			waitTimeAfter: time.Millisecond * 10,
		},
		{name: "request2-" + addr.MAC.String(), action: "dhcp4Request", hostTableInc: 1, macTableInc: 0, responsePos: -1, responseTableInc: -1,
			srcAddr:       packet.Addr{MAC: addr.MAC, IP: IP5}, // request different IP
			wantHost:      nil,
			waitTimeAfter: time.Millisecond * 20,
		},
		{name: "arp-probe2-" + addr.MAC.String(), action: "arpProbe", hostTableInc: 0, macTableInc: 0, responsePos: -1, responseTableInc: 0,
			srcAddr:       packet.Addr{MAC: addr.MAC, IP: IP5},
			wantHost:      nil,
			waitTimeAfter: time.Millisecond * 10,
		},
	}...)

	// request again - get 192.168.0.130
	tests = append(tests, NewHostEvents(addr, "mac1", 1, 0)...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})

	}
	checkOnlineCount(t, tc, 3, 2)
	checkCaptureCount(t, tc, 3, 1)

	t.Run("stage check", func(t *testing.T) {
		// initial ip must be set to offline and stage normal
		if host := tc.Engine.Session().FindIP(net.IPv4(192, 168, 0, 1)); host == nil || host.Online != false || host.HuntStage != packet.StageNormal {
			tc.Engine.PrintTable()
			t.Fatalf("unexpected host variables %s ", host)
		}
		// captured ip must be set to online and stage redirected
		if host := tc.Engine.Session().FindIP(net.IPv4(192, 168, 0, 131)); host == nil || host.Online != true || host.HuntStage != packet.StageRedirected {
			tc.Engine.PrintTable()
			t.Fatalf("unexpected host variables %s ", host)
		}
	})
}
