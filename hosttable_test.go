package packet

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

var (
	ip1 = netip.MustParseAddr("192.168.0.1")
	ip2 = netip.MustParseAddr("192.168.0.2")
	ip3 = netip.MustParseAddr("192.168.0.3")
	ip4 = netip.MustParseAddr("192.168.0.4")
	ip5 = netip.MustParseAddr("192.168.0.5")

	localIP  = netip.MustParseAddr("169.254.0.10")
	localIP2 = netip.MustParseAddr("169.254.0.11")

	hostMAC   = net.HardwareAddr{0x00, 0x55, 0x55, 0x55, 0x55, 0x55}
	hostIP4   = netip.MustParseAddr("192.168.0.129")
	routerMAC = net.HardwareAddr{0x00, 0x66, 0x66, 0x66, 0x66, 0x66}
	routerIP4 = netip.MustParseAddr("192.168.0.11")
	homeLAN   = netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 0, 0}), 24)

	mac1 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x01}
	mac2 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x02}
	mac3 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x03}
	mac4 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x04}
	mac5 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x05}

	addr1 = Addr{MAC: mac1, IP: ip1}
	addr2 = Addr{MAC: mac2, IP: ip2}
	addr3 = Addr{MAC: mac3, IP: ip3}
	addr4 = Addr{MAC: mac4, IP: ip4}

	// ip6LLARouter = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6LLAHost = netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x10})
	// ip6LLA1      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6LLA2 = netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02})
	// ip6LLA3      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03}
	ip6LLA4 = netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04})
	// ip6LLA5      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05}

	hostAddr   = Addr{MAC: hostMAC, IP: hostIP4}
	routerAddr = Addr{MAC: routerMAC, IP: routerIP4}

	// dnsIP4 = net.IPv4(8, 8, 8, 8)
)

func newTestHost(session *Session, srcAddr Addr) Frame {
	// create an arp reply packet
	p := make([]byte, EthMaxSize)
	ether := EncodeEther(p, syscall.ETH_P_IP, srcAddr.MAC, EthBroadcast)
	if srcAddr.IP.Is4() {
		ip4 := EncodeIP4(ether.Payload(), 255, srcAddr.IP, IP4Broadcast)
		ether, _ = ether.SetPayload(ip4)
	} else {
		ether = EncodeEther(p, syscall.ETH_P_IPV6, srcAddr.MAC, EthBroadcast)
		ip6 := EncodeIP6(ether.Payload(), 255, srcAddr.IP, IP6AllNodesMulticast)
		ether, _ = ether.SetPayload(ip6)
	}
	frame, err := session.Parse(ether)
	if err != nil {
		panic(err)
	}
	if srcAddr.IP != IPv4zero && frame.Host == nil {
		panic("invalid nil test host")
	}
	return frame
}

func TestHandler_CreateDelete(t *testing.T) {
	engine, _ := testSession()
	newTestHost(engine, addr1)
	if n := len(engine.MACTable.Table); n != 3 {
		t.Error("invalid mac table len", n)
	}
	if n := len(engine.HostTable.Table); n != 3 {
		t.Error("invalid host table len", n)
	}
	engine.deleteHost(addr1.IP)
	if n := len(engine.MACTable.Table); n != 2 {
		t.Error("invalid mac table len", n)
	}
	if n := len(engine.HostTable.Table); n != 2 {
		t.Error("invalid host table delete len", n)
	}
}

func TestHandler_findOrCreateHostTestCopyIPMAC(t *testing.T) {
	bufIP := netip.AddrFrom4([4]byte{192, 168, 1, 1})

	bufMAC := []byte{1, 1, 1, 2, 2, 2}
	mac := net.HardwareAddr{1, 1, 1, 2, 2, 2}

	session, _ := testSession()

	host, _ := session.findOrCreateHostWithLock(Addr{MAC: net.HardwareAddr(bufMAC), IP: bufIP})
	bufMAC[0] = 0x00
	if host.Addr.IP != bufIP {
		session.printHostTable()
		t.Error("findOrCreateHost wrong IP", host, host.MACEntry)
	}
	if !bytes.Equal(mac, host.MACEntry.MAC) {
		t.Error("findOrCreateHost wrong MAC", host, host.MACEntry)
	}

	bufMAC = []byte{1, 1, 1, 2, 2, 2}
	bufIP6 := netip.AddrFrom16([16]byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01})

	host, _ = session.findOrCreateHostWithLock(Addr{MAC: net.HardwareAddr(bufMAC), IP: bufIP6})
	bufMAC[0] = 0x00
	if host.Addr.IP != bufIP6 {
		t.Error("findOrCreateHost wrong IP", host, host.MACEntry)
	}
	if !bytes.Equal(mac, host.MACEntry.MAC) {
		t.Error("findOrCreateHost wrong MAC", host, host.MACEntry)
	}

	if n := len(session.HostTable.Table); n != 4 {
		session.printHostTable()
		t.Errorf("findOrCreateHost invalid len=%d want=%d ", n, 4)
	}
}

func Benchmark_findOrCreateHost(b *testing.B) {
	engine, _ := testSession()

	// running benchmark on WSL 2 - 64 hosts
	// March 21   Benchmark_findOrCreateHost-8   	 7555534	       141 ns/op	       0 B/op	       0 allocs/op
	// Aug 22                                        22853504	        56.53 ns/op	       0 B/op	       0 allocs/op
	mac := net.HardwareAddr{0x00, 0xff, 0xaa, 0xbb, 0x55, 0x55}
	for i := 0; i < b.N; i++ {
		ip := netip.AddrFrom4([4]byte{192, 168, 0, byte(i % 64)})
		mac[5] = byte(i % 64)
		host, _ := engine.findOrCreateHostWithLock(Addr{MAC: mac, IP: ip})
		if host.Addr.IP == IPv4zero || !host.Addr.IP.IsValid() {
			fmt.Println("invalid host", host.Addr)
		}
	}
}
func TestSession_findOrCreateHostWithLock(t *testing.T) {
	engine, _ := testSession()
	h1, _ := engine.Parse(mustHex(testARPRequest))
	h2, _ := engine.Parse(testicmp6RourterSolicitation)
	future := time.Now().Add(time.Minute * 40)
	h1.Host.LastSeen = future
	h1.Host.MACEntry.LastSeen = future
	h2.Host.LastSeen = future
	h2.Host.MACEntry.LastSeen = future

	// ensure last seen is updated
	h1, _ = engine.Parse(mustHex(testARPRequest))
	if !h1.Host.LastSeen.Before(future) || h1.Host.MACEntry.LastSeen != h1.Host.LastSeen {
		t.Error("invalid host1 last seen time")
	}
	h2, _ = engine.Parse(testicmp6RourterSolicitation)
	if !h2.Host.LastSeen.Before(future) || h2.Host.MACEntry.LastSeen != h2.Host.LastSeen {
		t.Error("invalid host2 last seen time")
	}
}

func TestHost_UpdateMDNSName(t *testing.T) {
	session, _ := testSession()
	host1, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip1})
	session.notify(Frame{Host: host1}) // first notification
	name := NameEntry{Type: "MDNS", Name: "abc", Model: "android"}
	host1.UpdateMDNSName(name)
	session.notify(Frame{Host: host1}) // change of name notification
	var notification Notification
	for i := 0; i < 2; i++ { // must get have 2 notifications - online and change of name
		select {
		case notification = <-session.C:
		case <-time.After(time.Second):
			t.Fatal("did not receive notification number", i)
		}
	}
	if notification.MDNSName.Name != name.Name || notification.MDNSName.Model != name.Model {
		t.Error("unexpected name", notification.MDNSName)
	}
}

func TestHost_UpdateLLMNRName(t *testing.T) {
	session, _ := testSession()
	host1, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip1})
	session.notify(Frame{Host: host1}) // first notification
	name := NameEntry{Type: "LLMNR", Name: "abc", Model: "android"}
	host1.UpdateLLMNRName(name)
	session.notify(Frame{Host: host1}) // change of name notification
	var notification Notification
	for i := 0; i < 2; i++ { // must get have 2 notifications - online and change of name
		select {
		case notification = <-session.C:
		case <-time.After(time.Second):
			t.Fatal("did not receive notification number", i)
		}
	}
	if notification.LLMNRName.Name != name.Name || notification.LLMNRName.Model != name.Model {
		t.Error("unexpected name", notification.LLMNRName)
	}
}

func TestHost_UpdateSSDPName(t *testing.T) {
	session, _ := testSession()
	host1, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip1})
	session.notify(Frame{Host: host1}) // first notification
	name := NameEntry{Type: "SSDP", Name: "abc", Model: "android"}
	host1.UpdateSSDPName(name)
	session.notify(Frame{Host: host1}) // change of name notification
	var notification Notification
	for i := 0; i < 2; i++ { // must get have 2 notifications - online and change of name
		select {
		case notification = <-session.C:
		case <-time.After(time.Second):
			t.Fatal("did not receive notification number", i)
		}
	}
	if notification.SSDPName.Name != name.Name || notification.SSDPName.Model != name.Model {
		t.Error("unexpected name", notification.SSDPName)
	}
}

func TestHost_UpdateNBNSName(t *testing.T) {
	session, _ := testSession()
	host1, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip1})
	session.notify(Frame{Host: host1}) // first notification
	name := NameEntry{Type: "NBNS", Name: "abc", Model: "android"}
	host1.UpdateNBNSName(name)
	session.notify(Frame{Host: host1}) // change of name notification
	var notification Notification
	for i := 0; i < 2; i++ { // must get have 2 notifications - online and change of name
		select {
		case notification = <-session.C:
		case <-time.After(time.Second):
			t.Fatal("did not receive notification number", i)
		}
	}
	if notification.NBNSName.Name != name.Name || notification.NBNSName.Model != name.Model {
		t.Error("unexpected name", notification.NBNSName)
	}
}
