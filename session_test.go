package packet

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/signal"
	"testing"
	"time"
)

func TestSession_SetOnline(t *testing.T) {
	session := setupTestHandler()
	// first host
	host1, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip1})
	session.SetOnline(Frame{Host: host1})

	// second host
	host2, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip2})
	session.SetOnline(Frame{Host: host2})

	// must get have 3 notifications - online, offline, online
	for i := 0; i < 3; i++ {
		select {
		case <-session.C:
		case <-time.After(time.Second):
			t.Fatal("did not receive notification number", i)
		}
	}
}

func TestHandler_SignalNICStopped(t *testing.T) {
	Debug = true
	nicInfo := NICInfo{
		RouterAddr4: Addr{MAC: routerMAC, IP: routerIP4},
		HostAddr4:   Addr{MAC: hostMAC, IP: hostIP4},
		HomeLAN4:    homeLAN,
	}
	inConn, _ := TestNewBufferedConn()

	c := make(chan os.Signal, 1)
	signal.Notify(c)

	keep := monitorNICFrequency
	defer func() { monitorNICFrequency = keep }()
	monitorNICFrequency = time.Millisecond * 3

	session, err := Config{Conn: inConn, NICInfo: &nicInfo}.NewSession()
	if err != nil {
		t.Fatal("engine did not stop as expected", err)
	}

	select {
	case <-time.After(time.Millisecond * 5):
		t.Error("engine did not stop as expected")
		fmt.Println(session.NICInfo)
	case <-c:
		fmt.Printf("got signal")
		fmt.Println(session.NICInfo)
	}
}

func TestHandler_Offline(t *testing.T) {
	ip6LLA1 := net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6GUA1 := net.IP{0x20, 0x01, 0x44, 0x79, 0x1d, 0x01, 0x24, 0x01, 0x7c, 0xf2, 0x4f, 0x73, 0xf8, 0xc1, 0x00, 0x01}
	ip6GUA2 := net.IP{0x20, 0x01, 0x44, 0x79, 0x1d, 0x01, 0x24, 0x01, 0x7c, 0xf2, 0x4f, 0x73, 0xf8, 0xc1, 0x00, 0x02}
	ip6GUA3 := net.IP{0x20, 0x01, 0x44, 0x79, 0x1d, 0x01, 0x24, 0x01, 0x7c, 0xf2, 0x4f, 0x73, 0xf8, 0xc1, 0x00, 0x03}

	session := setupTestHandler()
	Debug = true

	// First create host with two IPs - IP3 and IP2 and set online
	host1, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip3})
	session.SetOnline(Frame{Host: host1})
	host2, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip2})
	session.SetOnline(Frame{Host: host2})

	// create ipv6 hosts
	host3, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip6LLA1})
	session.SetOnline(Frame{Host: host3})
	host4, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip6GUA1})
	session.SetOnline(Frame{Host: host4})
	host5, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip6GUA2})
	session.SetOnline(Frame{Host: host5})
	host6, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip6GUA3})
	session.SetOnline(Frame{Host: host6})

	if n := len(session.HostTable.Table); n != 8 {
		session.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table len=%d ", n))
	}

	// capture
	if err := session.Capture(mac1); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond * 3)

	// set hosts offline
	session.SetOffline(host1)
	session.SetOffline(host2)
	session.SetOffline(host3)
	session.SetOffline(host4)
	session.SetOffline(host5)
	session.SetOffline(host6)

	if n := len(session.HostTable.Table); n != 8 {
		session.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table 2 len=%d ", n))
	}

	session.purge(time.Now().Add(time.Hour))
	if n := len(session.HostTable.Table); n != 2 {
		session.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table 2 len=%d ", n))
	}
	session.PrintTable()
}

func TestHandler_findOrCreateHostDupIP(t *testing.T) {
	session := setupTestHandler()

	Debug = false

	// First create host with two IPs - IP3 and IP2 and set online
	host1, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip3})
	session.SetOnline(Frame{Host: host1})
	host2, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip2})
	session.SetOnline(Frame{Host: host2})

	// test that name will clear - this was a previous bug
	session.DHCPUpdate(host2.Addr.MAC, host2.Addr.IP, NameEntry{Type: "dhcp", Name: "mac1"})

	// set host offline
	session.SetOffline(host2)
	if err := session.Capture(mac1); err != nil {
		t.Fatal(err)
	}
	if !host2.MACEntry.Captured {
		session.PrintTable()
		t.Fatal("host not capture")
	}

	// new mac, same IP - Duplicated IP on network
	host3, _ := session.findOrCreateHostWithLock(Addr{MAC: mac2, IP: ip2})
	session.SetOnline(Frame{Host: host3})
	if host3.MACEntry.Captured { // mac should not be captured
		session.PrintTable()
		t.Fatal("host is captured incorrectly")
	}

	// name stay with the original mac1, but should not copy to mac2
	if host2.DHCP4Name.Name != "mac1" || host3.DHCP4Name.Name != "" {
		session.PrintTable()
		t.Fatal("invalid host name")
	}

	// there must be four macs
	if n := len(session.MACTable.Table); n != 4 {
		session.PrintTable()
		t.Fatal(fmt.Sprintf("invalid mac table len=%d", n))
	}

	// The must only be four hosts for IP2
	if n := len(session.HostTable.Table); n != 4 {
		session.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table len=%d ", n))
	}

	// second IPs
	host3, _ = session.findOrCreateHostWithLock(Addr{MAC: mac2, IP: ip2})
	if host3.MACEntry.Captured { // mac should not be captured
		t.Fatal("host should not be capture")
	}

	if !host2.MACEntry.Captured {
		t.Fatal("host should be captured")
	}
}

func TestSession_DHCPUpdate(t *testing.T) {
	session := setupTestHandler()

	Debug = false

	// First create host with two IPs - IP3 and IP2 and set online
	host1, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip1})
	session.SetOnline(Frame{Host: host1})

	if err := session.Capture(mac3); err != nil { // will create another mac entry
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		wantErr   bool
		addr      Addr
		dhcpName  string
		wantAddr  Addr
		wantName  string
		hostTable int
		macTable  int
	}{
		{name: "mac1_existinghost", wantErr: false, addr: Addr{MAC: mac1, IP: ip1}, dhcpName: "mac1",
			wantName: "mac1", wantAddr: Addr{MAC: mac1, IP: ip1}, hostTable: 3, macTable: 4},
		{name: "mac2_newhost", wantErr: false, addr: Addr{MAC: mac2, IP: ip2}, dhcpName: "mac2",
			wantName: "mac2", wantAddr: Addr{MAC: mac2, IP: ip2}, hostTable: 4, macTable: 5},
		{name: "mac3_newcapturedhost", wantErr: false, addr: Addr{MAC: mac3, IP: ip3}, dhcpName: "mac3",
			wantName: "mac3", wantAddr: Addr{MAC: mac3, IP: ip3}, hostTable: 5, macTable: 5},
		{name: "mac1_dup", wantErr: false, addr: Addr{MAC: mac1, IP: ip1}, dhcpName: "mac1",
			wantName: "mac1", wantAddr: Addr{MAC: mac1, IP: ip1}, hostTable: 5, macTable: 5},
		{name: "mac3_dup", wantErr: false, addr: Addr{MAC: mac3, IP: ip3}, dhcpName: "mac3",
			wantName: "mac3", wantAddr: Addr{MAC: mac3, IP: ip3}, hostTable: 5, macTable: 5},
		{name: "mac3_newip", wantErr: false, addr: Addr{MAC: mac3, IP: ip4}, dhcpName: "mac3",
			wantName: "mac3", wantAddr: Addr{MAC: mac3, IP: ip4}, hostTable: 6, macTable: 5},
		{name: "mac4_conflictip", wantErr: false, addr: Addr{MAC: mac4, IP: ip4}, dhcpName: "mac4",
			wantName: "mac4", wantAddr: Addr{MAC: mac4, IP: ip4}, hostTable: 6, macTable: 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := session.DHCPUpdate(tt.addr.MAC, tt.addr.IP, NameEntry{Type: "dhcp", Name: tt.dhcpName}); (err != nil) != tt.wantErr {
				t.Fatalf("%s: Session.DHCPUpdate() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}

			host := session.FindIP(tt.wantAddr.IP)
			if host == nil || !bytes.Equal(host.MACEntry.MAC, tt.wantAddr.MAC) || !bytes.Equal(host.Addr.MAC, tt.wantAddr.MAC) {
				t.Fatalf("%s: Session.DHCPUpdate() nil or invalid host mac %v", tt.name, host)
			}
			if host.DHCP4Name.Name != tt.wantName {
				t.Errorf("%s: Session.DHCPUpdate() invalid host name=%v, want=%v", tt.name, host.DHCP4Name.Name, tt.wantName)
			}
			if n := len(session.HostTable.Table); n != tt.hostTable {
				t.Errorf("%s: Session.DHCPUpdate() invalid hosttable len=%v, want=%v", tt.name, n, tt.hostTable)
			}
			if n := len(session.MACTable.Table); n != tt.macTable {
				t.Errorf("%s: Session.DHCPUpdate() invalid mactable len=%v, want=%v", tt.name, n, tt.macTable)
			}
		})
	}
}
