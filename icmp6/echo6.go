package icmp6

import (
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

const (
	icmpv4EchoRequest = 8
	icmpv4EchoReply   = 0
	icmpv6EchoRequest = 128
	icmpv6EchoReply   = 129
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

// SendEcho transmit an icmp echo request
// Do not wait for response
func (h *Handler) SendEcho(srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP, id uint16, seq uint16) error {

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

	return h.sendICMP6Packet(srcMAC, srcIP, dstMAC, dstIP, p)
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
	ether.SetPayload(ip6)
	if _, err := h.conn.WriteTo(ether, nil); err != nil {
		log.Error("icmp failed to write ", err)
		return err
	}

	return nil
}
