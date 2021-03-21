package test

import (
	"net"
	"testing"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/dhcp4"
	log "github.com/sirupsen/logrus"
)

func TestHandler_capture(t *testing.T) {
	tc := NewTestContext()
	defer tc.Close()

	log.SetLevel(log.DebugLevel)
	dhcp4.Debug = true
	packet.Debug = true
	arp.Debug = true

	tests := []TestEvent{}

	// MAC1
	addr := packet.Addr{MAC: MAC1}
	tests = append(tests, NewHostEvents(addr, 1, 1)...)
	tests = append(tests, TestEvent{name: "capture-" + addr.MAC.String(), hostTableInc: 0, macTableInc: 0, responsePos: 0, responseTableInc: 0,
		waitTimeAfter: time.Millisecond * 30,
		action:        "capture", srcAddr: packet.Addr{MAC: addr.MAC, IP: net.IPv4zero},
	})
	tests = append(tests, NewHostEvents(addr, 1, 1)...) // get a second IP with captured net

	/***
	// MAC2
	addr = packet.Addr{MAC: MAC2}
	tests = append(tests, TestEvent{name: "capture-" + addr.MAC.String(),
		action: "capture", srcAddr: packet.Addr{MAC: addr.MAC, IP: net.IPv4zero},
	})
	tests = append(tests, NewHostEvents(addr, 2, 2)...)
	***/

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})

	}
	// checkOnlineCount(t, tc, 3, 0)
	// checkCaptureCount(t, tc, 2, 2)
}
