package dhcp4

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/irai/packet"
)

func Test_requestSimple(t *testing.T) {
	packet.DebugIP4 = false
	packet.Debug = true
	Debug = true
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()

	tests := []struct {
		name           string
		wantResponse   bool
		tableLen       int
		allocatedCount int
		discoverCount  int
		freeCount      int
		srcAddr        packet.Addr
		dstAddr        packet.Addr
	}{
		{name: "request-mac1", wantResponse: true, tableLen: 1, allocatedCount: 1, freeCount: 0, discoverCount: 0,
			srcAddr: packet.Addr{MAC: mac1},
		},
		{name: "request-mac2", wantResponse: true, tableLen: 2, allocatedCount: 2, freeCount: 0, discoverCount: 0,
			srcAddr: packet.Addr{MAC: mac2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newDHCPHost(t, tc, tt.srcAddr.MAC, tt.name)

			if n := len(tc.h.table); n != tt.tableLen {
				tc.h.printTable()
				t.Errorf("DHCPHandler.handleDiscover() invalid lease table len=%d want=%d", n, tt.tableLen)
			}
			checkLeaseTable(t, tc, tt.allocatedCount, tt.discoverCount, tt.freeCount)
			select {
			case <-time.After(time.Millisecond * 200):
				t.Error("timeout")
			case notification := <-tc.session.C:
				if !notification.Online {
					tc.session.PrintTable()
					t.Error("invalid notification", notification)
				}
			}
		})
	}
}

func Test_requestCaptured(t *testing.T) {
	packet.DebugIP4 = false
	packet.Debug = true
	Debug = false
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()

	t.Run("host1", func(t *testing.T) {
		hostName := "host1"
		addr := packet.Addr{MAC: mac1}
		ip := net.IPv4(192, 168, 0, 130)
		tc.session.Capture(addr.MAC)
		newDHCPHost(t, tc, addr.MAC, hostName)
		if lease := tc.h.findByMAC(addr.MAC); lease == nil || !lease.Addr.IP.Equal(ip) || lease.Name != hostName || lease.State != StateAllocated ||
			lease.subnet != tc.h.net2 {
			tc.h.PrintTable()
			t.Error("invalid lease", lease)
		}
		if host := tc.session.FindIP(ip); host == nil || host.DHCP4Name.Name != hostName || !host.Online || !bytes.Equal(host.MACEntry.MAC, addr.MAC) || !host.MACEntry.Captured {
			tc.session.PrintTable()
			t.Error("invalid host", host)
		}
		select {
		case <-time.After(time.Millisecond * 200):
			t.Error("timeout")
		case notification := <-tc.session.C:
			if !notification.Addr.IP.Equal(ip) || !notification.Online {
				t.Error("invalid online notification", notification)
			}
		}
	})

	t.Run("host2", func(t *testing.T) {
		hostName := "host2"
		addr := packet.Addr{MAC: mac2}
		newDHCPHost(t, tc, addr.MAC, hostName)
		ip := net.IPv4(192, 168, 0, 131)
		tc.session.Capture(addr.MAC)
		newDHCPHost(t, tc, addr.MAC, hostName)
		if lease := tc.h.findByMAC(addr.MAC); lease == nil || !lease.Addr.IP.Equal(ip) || lease.Name != hostName || lease.State != StateAllocated ||
			lease.subnet != tc.h.net2 {
			tc.h.PrintTable()
			t.Error("invalid lease", lease)
		}
		if host := tc.session.FindIP(ip); host == nil || host.DHCP4Name.Name != hostName || !host.Online || !bytes.Equal(host.MACEntry.MAC, addr.MAC) || !host.MACEntry.Captured {
			tc.session.PrintTable()
			t.Error("invalid host", host)
		}

		// wait for three notifications
		select {
		case <-time.After(time.Millisecond * 200):
			t.Error("timeout")
		case notification := <-tc.session.C:
			if !notification.Addr.IP.Equal(net.IPv4(192, 168, 0, 1)) || !notification.Online {
				t.Error("invalid online notification 1", notification)
			}
		}
		select {
		case <-time.After(time.Millisecond * 200):
			t.Fatal("timeout")
		case notification := <-tc.session.C:
			if !notification.Addr.IP.Equal(net.IPv4(192, 168, 0, 1)) || notification.Online {
				t.Error("invalid offline notification", notification)
			}
		}
		select {
		case <-time.After(time.Millisecond * 200):
			t.Fatal("timeout")
		case notification := <-tc.session.C:
			if !notification.Addr.IP.Equal(net.IPv4(192, 168, 0, 131)) || !notification.Online {
				t.Error("invalid online notification 2", notification)
			}
		}
	})
}

func Test_requestExhaust(t *testing.T) {

	packet.Debug = false
	Debug = false
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()

	exhaustAllIPs(t, tc, mac1)

	// send one last discover
	tc.IPOffer = nil
	tc.xid++
	xid := []byte(fmt.Sprintf("%d", tc.xid))
	mac5 = net.HardwareAddr{0x00, 0xff, 0xaa, 0xbb, 0x05, 0x05} // new mac
	srcAddr := packet.Addr{MAC: mac5, IP: net.IPv4zero, Port: DHCP4ClientPort}
	// dstAddr := packet.Addr{MAC: packet.EthernetBroadcast, IP: net.IPv4zero, Port: DHCP4ServerPort}
	ether := newDHCP4DiscoverFrame(srcAddr, "onelastname", xid)
	frame, err := tc.session.Parse(ether)
	if err != nil {
		panic(err)
	}
	err = tc.h.ProcessPacket(frame)
	if err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
	}
	time.Sleep(time.Millisecond * 10)

	if tc.IPOffer != nil {
		t.Errorf("DHCPHandler.handleDiscover() unexpected IP offer ip=%s", tc.IPOffer)
	}
}

func Test_requestAnotherHost(t *testing.T) {
	Debug = false
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()

	tc.IPOffer = nil
	tc.xid++
	xid := []byte(fmt.Sprintf("%d", tc.xid))
	mac5 = net.HardwareAddr{0x00, 0xff, 0xaa, 0xbb, 0x05, 0x05} // new mac
	srcAddr := packet.Addr{MAC: mac5, IP: net.IPv4zero, Port: DHCP4ClientPort}
	dstAddr := packet.Addr{MAC: packet.EthernetBroadcast, IP: net.IPv4zero, Port: DHCP4ServerPort}

	// first discover packet
	ether := newDHCP4DiscoverFrame(srcAddr, "host name", xid)
	frame, err := tc.session.Parse(ether)
	if err != nil {
		panic(err)
	}
	if err := tc.h.ProcessPacket(frame); err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
	}
	select {
	case <-tc.notifyReply:
	case <-time.After(time.Millisecond * 10):
		t.Fatal("failed to receive reply")
	}
	checkLeaseTable(t, tc, 0, 1, 0)

	// request for another host
	ether = newDHCP4RequestFrame(srcAddr, dstAddr, "host name", routerIP4, ip3, xid)
	frame, err = tc.session.Parse(ether)
	if err != nil {
		panic(err)
	}
	if err = tc.h.ProcessPacket(frame); err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
	}
	select {
	case <-tc.notifyReply:
		t.Fatal("invalid  reply")
	case <-time.After(time.Millisecond * 10):
	}
	checkLeaseTable(t, tc, 0, 1, 0)

	// new discover - captured host
	ether = newDHCP4DiscoverFrame(srcAddr, "host name", xid)
	frame, err = tc.session.Parse(ether)
	if err != nil {
		panic(err)
	}
	if err := tc.h.ProcessPacket(frame); err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
	}
	select {
	case <-tc.notifyReply:
	case <-time.After(time.Millisecond * 10):
		t.Fatal("failed to receive reply")
	}
	checkLeaseTable(t, tc, 0, 1, 0)

	// request for another server - captured host
	ether = newDHCP4RequestFrame(srcAddr, dstAddr, "host name", routerIP4, ip3, xid)
	frame, err = tc.session.Parse(ether)
	if err != nil {
		panic(err)
	}
	if err = tc.h.ProcessPacket(frame); err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
	}
	select {
	case <-tc.notifyReply:
		t.Fatal("failed to receive reply")
	case <-time.After(time.Millisecond * 10):
	}
	checkLeaseTable(t, tc, 0, 1, 0)
}

func exhaustAllIPs(t *testing.T, tc *testContext, mac net.HardwareAddr) {
	// will skip x.0, hostIP, routerIP and x.255
	for i := 0; i < 252; i++ {
		mac[5] = byte(i)
		newDHCPHost(t, tc, mac, mac.String())
	}
	checkLeaseTable(t, tc, 252, 0, 0)
}
