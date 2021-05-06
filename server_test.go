package packet

import (
	"fmt"
	"testing"

	"github.com/irai/packet/model"
)

func setupTestHandler() *Handler {
	h := &Handler{}
	h.session = &model.Session{HostTable: model.NewHostTable(), MACTable: model.NewMACTable()}
	return h
}

func TestHandler_findOrCreateHostDupIP(t *testing.T) {
	engine := setupTestHandler()

	Debug = true

	// First create host with two IPs - IP3 and IP2 and set online
	host1, _ := engine.session.FindOrCreateHost(mac1, ip3)
	engine.lockAndSetOnline(host1, true)
	host1, _ = engine.session.FindOrCreateHost(mac1, ip2)
	host1.DHCP4Name = "mac1" // test that name will clear - this was a previous bug
	engine.lockAndSetOnline(host1, true)

	// set host offline
	engine.lockAndSetOnline(host1, false)
	if err := engine.Capture(mac1); err != nil {
		t.Fatal(err)
	}
	if !host1.MACEntry.Captured {
		engine.session.PrintTable()
		t.Fatal("host not capture")
	}

	// new mac, same IP - Duplicated IP on network
	host2, _ := engine.session.FindOrCreateHost(mac2, ip2)
	if host2.MACEntry.Captured { // mac should not be captured
		engine.session.PrintTable()
		t.Fatal("host not capture")
	}
	if host2.DHCP4Name != "" {
		t.Fatal("invalid host name")
	}

	// there must be two macs
	if n := len(engine.session.MACTable.Table); n != 2 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid mac table len=%d", n))
	}

	// The must only be two hosts for IP2
	if n := len(engine.session.HostTable.Table); n != 2 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table len=%d ", n))
	}

	// second IPs
	host1, _ = engine.session.FindOrCreateHost(mac2, ip2)
	if host1.MACEntry.Captured { // mac should not be captured
		t.Fatal("host not capture")
	}
}
