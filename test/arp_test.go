package test

import (
	"net"
	"testing"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/dhcp4"
	"github.com/irai/packet/model"
	log "github.com/sirupsen/logrus"
)

func TestHandler_arpcapture(t *testing.T) {
	tc := NewTestContext()
	defer tc.Close()

	log.SetLevel(log.DebugLevel)
	dhcp4.Debug = true
	packet.Debug = true
	arp.Debug = true

	// MAC1
	addr := model.Addr{MAC: MAC1, IP: IP1}
	tests := []TestEvent{
		{name: "capture-" + addr.MAC.String(), hostTableInc: 0, macTableInc: 0, responsePos: 0, responseTableInc: 0,
			action: "capture", srcAddr: model.Addr{MAC: addr.MAC, IP: net.IPv4zero},
			waitTimeAfter: time.Millisecond * 30,
		},
		{name: "arp-announcement-" + addr.MAC.String(),
			action: "arpAnnouncement", hostTableInc: 1, macTableInc: 0, responsePos: -1, responseTableInc: -1,
			srcAddr:       model.Addr{MAC: addr.MAC, IP: IP1}, // set IP to zero to use savedIP
			wantHost:      &model.Host{IP: IP1, Online: true},
			waitTimeAfter: time.Millisecond * 10,
		},
	}
	addr = model.Addr{MAC: MAC2}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})

	}
	checkOnlineCount(t, tc, 3, 0)
	checkCaptureCount(t, tc, 1, 1)
}
