package icmp6

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/irai/packet"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

type icmpEntry struct {
	msgRecv packet.ICMPEcho
	expire  time.Time
}

var icmpTable = struct {
	mutex sync.Mutex
	cond  *sync.Cond
	table map[uint16]*icmpEntry
}{
	table: make(map[uint16]*icmpEntry),
}

func init() {
	icmpTable.cond = sync.NewCond(&icmpTable.mutex)
}

// SendEchoRequest transmit an icmp6 echo request and do not wait for response
func (h *Handler) SendEchoRequest(srcAddr packet.Addr, dstAddr packet.Addr, id uint16, seq uint16) error {
	if !packet.IsIP6(srcAddr.IP) || !packet.IsIP6(dstAddr.IP) {
		return packet.ErrInvalidIP4
	}
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

	return h.sendPacket(srcAddr, dstAddr, p)
}

// Ping send a ping request and wait for a reply
func (h *Handler) Ping(dstAddr packet.Addr, timeout time.Duration) (err error) {
	if timeout <= 0 || timeout > time.Second*10 {
		timeout = time.Second * 2
	}
	icmpTable.cond.L.Lock()
	msg := icmpEntry{expire: time.Now().Add(timeout)}
	id := uint16(time.Now().Nanosecond())
	seq := uint16(1)
	icmpTable.table[id] = &msg
	icmpTable.cond.L.Unlock()

	if err = h.SendEchoRequest(packet.Addr{MAC: h.engine.NICInfo.HostMAC, IP: h.engine.NICInfo.HostLLA.IP}, dstAddr, id, seq); err != nil {
		// fmt.Println("error sending ping packet", err)
		return err
	}

	// wait with mutex locked
	icmpTable.cond.L.Lock()
	for msg.msgRecv == nil && msg.expire.After(time.Now()) {
		go func() { time.Sleep(timeout); icmpTable.cond.Broadcast() }() // wake up in timeout if not before
		icmpTable.cond.Wait()
	}
	delete(icmpTable.table, id)
	icmpTable.cond.L.Unlock()

	if msg.msgRecv == nil {
		return packet.ErrTimeout
	}

	return nil
}

// Ping send a ping request and wait for a reply
func (h *Handler) PING(src net.IP, dst net.IP, timeout time.Duration) (err error) {

	icmpTable.cond.L.Lock()
	msg := icmpEntry{expire: time.Now().Add(timeout)}
	id := uint16(time.Now().Nanosecond())
	seq := uint16(1)
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
			ID: int(id), Seq: int(seq),
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
