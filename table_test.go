package packet

import (
	"bytes"
	"net"
	"testing"
)

func TestHandler_findOrCreateHostTestCopyIPMAC(t *testing.T) {
	bufIP := []byte{192, 168, 1, 1}
	ip := net.IPv4(192, 168, 1, 1)

	bufMAC := []byte{1, 1, 1, 2, 2, 2}
	mac := net.HardwareAddr{1, 1, 1, 2, 2, 2}

	tc := setupTestHandler()
	defer tc.Close()

	host, _ := tc.packet.findOrCreateHost(net.HardwareAddr(bufMAC), net.IP(bufIP))

	bufIP[0] = 0xff
	bufMAC[0] = 0x00

	// must update host and mac entry ip
	if !host.IP.Equal(ip) || !host.MACEntry.IP4.Equal(ip) {
		t.Error("findOrCreateHost wrong IP", host, host.MACEntry)
	}
	if !bytes.Equal(mac, host.MACEntry.MAC) {
		t.Error("findOrCreateHost wrong MAC", host, host.MACEntry)
	}

	bufMAC = []byte{1, 1, 1, 2, 2, 2}
	bufIP6 := []byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6 := net.IP{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}

	host, _ = tc.packet.findOrCreateHost(net.HardwareAddr(bufMAC), net.IP(bufIP6))
	bufIP6[8] = 0xff
	bufMAC[0] = 0x00
	if !host.IP.Equal(ip6) || !host.MACEntry.IP6.Equal(ip6) {
		t.Error("findOrCreateHost wrong IP", host, host.MACEntry)
	}
	if !bytes.Equal(mac, host.MACEntry.MAC) {
		t.Error("findOrCreateHost wrong MAC", host, host.MACEntry)
	}

	if len(tc.packet.LANHosts.Table) != 2 {
		tc.h.printHostTable()
		t.Error("findOrCreateHost invalid leng ")
	}
}
