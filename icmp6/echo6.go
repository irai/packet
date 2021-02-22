package icmp6

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

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

	return h.sendPacket(h.ifi.HardwareAddr, h.LLA().IP, EthAllNodesMulticast, dstIP, p)
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
