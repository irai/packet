package icmp6

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/irai/packet/raw"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

type icmpEntry struct {
	msgRecv *icmp.Message
	expire  time.Time
}

var icmpTable = struct {
	echoIdentifier uint16
	mutex          sync.Mutex
	cond           *sync.Cond
	table          map[uint16]*icmpEntry
}{
	echoIdentifier: 5000,
	table:          make(map[uint16]*icmpEntry),
}

func init() {
	icmpTable.cond = sync.NewCond(&icmpTable.mutex)
}

// SendEchoRequest transmit an icmp echo request
// Do not wait for response
func (h *Handler) SendEchoRequest(dstIP net.IP, id uint16, seq uint16) error {

	/**
	e := h.LANHosts.FindIP(dstIP)
	if e == nil {
		return raw.ErrNotFound
	}
	***/

	icmpMessage := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(id),
			Seq:  int(seq),
			Data: []byte("HELLO-R-U-THERE"),
		},
	}

	p, err := icmpMessage.Marshal(nil)
	if err != nil {
		return err
	}

	return h.sendICMP6Packet(h.ifi.HardwareAddr, h.LLA().IP, EthAllNodesMulticast, dstIP, p)
}

// Ping send a ping request and wait for a reply
func (h *Handler) Ping(src net.IP, dst net.IP, timeout time.Duration) (err error) {

	icmpTable.cond.L.Lock()
	msg := icmpEntry{expire: time.Now().Add(timeout)}
	id := icmpTable.echoIdentifier
	icmpTable.echoIdentifier++
	icmpTable.table[id] = &msg
	icmpTable.cond.L.Unlock()

	c, err := icmp.ListenPacket("ip6:ipv6-icmp", src.String()+"%eth0")
	if err != nil {
		return err
	}
	defer c.Close()

	wm := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return err
	}
	if _, err := c.WriteTo(wb, &net.IPAddr{IP: dst, Zone: "eth0"}); err != nil {
		return err
	}

	return nil

	icmpTable.cond.L.Lock()
	for msg.msgRecv == nil && msg.expire.After(time.Now()) {
		icmpTable.cond.Wait()
	}
	delete(icmpTable.table, id)
	icmpTable.cond.L.Unlock()

	if msg.msgRecv == nil {
		return fmt.Errorf("ping timeout ip= %v id=%v", dst, id)
	}

	return nil
}

func (h *Handler) sendICMP6Packet(srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP, b []byte) error {

	hopLimit := uint8(64)
	if dstIP.IsLinkLocalUnicast() || dstIP.IsLinkLocalMulticast() {
		hopLimit = 1
	}

	ether := raw.EtherMarshalBinary(nil, syscall.ETH_P_IPV6, srcMAC, dstMAC)
	ip6 := raw.IP6MarshalBinary(ether.Payload(), hopLimit, srcIP, dstIP)
	ip6, _ = ip6.AppendPayload(b, syscall.IPPROTO_ICMPV6)
	ether, _ = ether.SetPayload(ip6)

	// Calculate checksum of the pseudo header
	// The ICMPv6 checksum takes into account a pseudoheader of 40 bytes, which is a derivative of the real IPv6 header
	// which is composed as follows (in order):
	//   - 16 bytes for the source address
	//   - 16 bytes for the destination address
	//   - 4 bytes high endian payload length (the same value as in the IPv6 header)
	//   - 3 bytes zero
	//   - 1 byte nextheader (so, 58 decimal)
	psh := make([]byte, 40+len(b))
	copy(psh[0:16], ip6.Src())
	copy(psh[16:32], ip6.Dst())
	binary.BigEndian.PutUint32(psh[32:36], uint32(len(b)))
	psh[39] = 58
	copy(psh[40:], b)
	ICMP6(ip6.Payload()).SetChecksum(raw.Checksum(psh))

	fmt.Println("DEBUG ether:", ether, len(ether), len(b))
	fmt.Println("DEBUG ip6  :", raw.IP6(ether.Payload()))
	icmp6 := ICMP6(raw.IP6(ether.Payload()).Payload())
	fmt.Println("DEBUG icmp :", icmp6, len(icmp6))
	fmt.Println("DEBUG ether:", ether, len(ether), len(b))
	if _, err := h.conn.WriteTo(ether, &raw.Addr{MAC: dstMAC}); err != nil {
		log.Error("icmp failed to write ", err)
		return err
	}

	return nil
}
