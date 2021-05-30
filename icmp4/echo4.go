package icmp4

import (
	"bytes"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/irai/packet"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	icmpv4EchoRequest = 8
	icmpv4EchoReply   = 0
	icmpv6EchoRequest = 128
	icmpv6EchoReply   = 129
)

type icmpEntry struct {
	msgRecv bool
	expire  time.Time
	wakeup  chan bool
}

var icmpTable = struct {
	sync.Mutex
	table map[uint16]*icmpEntry // must use pointer because of channel in struct
}{
	table: make(map[uint16]*icmpEntry),
}

// SendEchoRequest transmit an icmp echo request
// Do not wait for response
func (h *Handler) SendEchoRequest(srcAddr packet.Addr, dstAddr packet.Addr, id uint16, seq uint16) error {
	if srcAddr.IP.To4() == nil || dstAddr.IP.To4() == nil {
		return packet.ErrInvalidIP
	}
	icmpMessage := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
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

	if Debug {
		fmt.Printf("icmp4: echo request %s\n", packet.ICMPEcho(p))
	}
	return h.sendPacket(srcAddr, dstAddr, p)
}

func echoNotify(id uint16) {
	icmpTable.Lock()
	if len(icmpTable.table) <= 0 {
		icmpTable.Unlock()
		return
	}

	if entry, ok := icmpTable.table[id]; ok {
		entry.msgRecv = true
		entry.wakeup <- true
	}
	icmpTable.Unlock()
}

// Ping send a ping request and wait for a reply
func (h *Handler) Ping(srcAddr packet.Addr, dstAddr packet.Addr, timeout time.Duration) (err error) {
	if timeout <= 0 || timeout > time.Second*10 {
		timeout = time.Second * 2
	}

	msg := icmpEntry{expire: time.Now().Add(timeout), wakeup: make(chan bool)}
	id := uint16(time.Now().Nanosecond())
	seq := uint16(1)

	icmpTable.Lock()
	icmpTable.table[id] = &msg
	icmpTable.Unlock()

	if err = h.SendEchoRequest(srcAddr, dstAddr, id, seq); err != nil {
		return err
	}

	for {
		icmpTable.Lock()
		if msg.msgRecv || msg.expire.Before(time.Now()) {
			break
		}
		icmpTable.Unlock()
		select {
		case <-msg.wakeup:
		case <-time.After(timeout):
		}
	}

	// loop finishes with lock
	delete(icmpTable.table, id)
	icmpTable.Unlock()

	if !msg.msgRecv {
		return packet.ErrTimeout
	}

	return nil
}

// CheckAddr validates the default route is pointing to us by pinging
// client using home router IP as source IP. The reply will come to us
// when the default route on client is netfilter. If not, the ping
// reply will not be received.
//
// Note: the reply will also come to us if the client is undergoing
// an arp attack (hunt).
func (h *Handler) CheckAddr(addr packet.Addr) (packet.HuntStage, error) {
	// Test if client is online first
	// If client does not respond to echo, there is little we can test
	if err := h.Ping(packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostIP4.IP}, addr, time.Second*2); err != nil {
		fmt.Printf("icmp4 : not responding to ping ip=%s mac=%s\n", addr.IP, addr.MAC)
		return packet.StageNormal, packet.ErrTimeout
	}

	// first attempt
	err := h.Ping(packet.Addr{MAC: h.session.NICInfo.RouterMAC, IP: h.session.NICInfo.RouterIP4.IP}, addr, time.Second*2)
	if err == nil {
		return packet.StageRedirected, nil
	}

	// second attempt
	err = h.Ping(packet.Addr{MAC: h.session.NICInfo.RouterMAC, IP: h.session.NICInfo.RouterIP4.IP}, addr, time.Second*2)
	if err == nil {
		return packet.StageRedirected, nil
	}

	return packet.StageHunt, packet.ErrNotRedirected
}

// ExecPing execute /usr/bin/ping
//
// This is usefull when engine is not yet running and you need to populate the local arp/ndp cache
// If passing an IPv6 LLA, then must pass the scope as in "fe80::1%eth0"
func ExecPing(ip string) (err error) {
	// -w deadline - wait 1 second
	// -i frequency - one request each 0,2 seconds
	// -c count - how many replies to receive before returning (in conjuction with -w)
	cmd := exec.Command("/usr/bin/ping", ip, "-w", "1", "-i", "0.2", "-c", "1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err = cmd.Run(); err != nil {
		fmt.Printf("packet: failed to ping ip=%s error=%s\n", ip, err)
	}
	fmt.Printf("ping: %q\n", stdout.String())
	// fmt.Printf("errs: %q\n", stderr.String())
	return err
}
