package engine

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/dhcp4"
	"github.com/irai/packet/dns"
	"github.com/irai/packet/fastlog"
	"github.com/irai/packet/icmp"
)

const module = "engine"

// buffer holds a raw Ethernet network packet
type buffer struct {
	b [packet.EthMaxSize]byte // buffer
	n int                     // buffer len
}

// Handler implements network handler
type Handler struct {
	session      *packet.Session // store shared session values
	HandlerIP4   packet.PacketProcessor
	HandlerIP6   packet.PacketProcessor
	ICMP4Handler icmp.ICMP4Handler
	ICMP6Handler icmp.ICMP6Handler
	DHCP4Handler dhcp4.DHCP4Handler
	ARPHandler   arp.ARPHandler
	DNSHandler   *dns.DNSHandler
	closed       bool      // set to true when handler is closed
	closeChan    chan bool // close goroutines channel
	dnsChannel   chan dns.DNSEntry
}

// NewEngine creates an packet handler with config values
func NewEngine(session *packet.Session) (h *Handler, err error) {
	h = &Handler{closeChan: make(chan bool)}
	h.dnsChannel = make(chan dns.DNSEntry, 128) // plenty of capacity to prevent blocking
	h.session = session

	// no plugins to start
	h.ARPHandler = arp.ARPNOOP{}
	h.HandlerIP4 = packet.PacketNOOP{}
	h.HandlerIP6 = packet.PacketNOOP{}
	h.ICMP4Handler = icmp.ICMP4NOOP{}
	h.ICMP6Handler = icmp.ICMP6NOOP{}
	h.DHCP4Handler = dhcp4.PacketNOOP{}

	// default DNS handler
	h.DNSHandler, _ = dns.New(h.session)

	return h, nil
}

func (h *Handler) Session() *packet.Session {
	return h.session
}

// Close closes the underlying sockets
func (h *Handler) Close() error {
	if packet.Debug {
		fmt.Println("packet: close() called. closing....")
	}
	h.closed = true

	// Don't close external channels as they will result in a loop in the caller.
	//   i.e. a goroutine waiting on x <-nofificationEngine will return continuosly if the channel is closed

	// close the internal channel to terminate internal goroutines
	close(h.closeChan)
	return nil
}

func (h *Handler) AttachARP(p arp.ARPHandler) {
	h.ARPHandler = p
}

func (h *Handler) DetachARP() error {
	if err := h.ARPHandler.Close(); err != nil {
		return err
	}
	h.ARPHandler = arp.ARPNOOP{}
	return nil
}

func (h *Handler) AttachICMP4(p icmp.ICMP4Handler) {
	h.ICMP4Handler = p
}
func (h *Handler) DetachICMP4() error {
	if err := h.ICMP4Handler.Stop(); err != nil {
		return err
	}
	h.ICMP4Handler = icmp.ICMP4NOOP{}
	return nil
}

func (h *Handler) AttachICMP6(p icmp.ICMP6Handler) {
	h.ICMP6Handler = p
}
func (h *Handler) DetachICMP6() error {
	if err := h.ICMP6Handler.Close(); err != nil {
		return err
	}
	h.ICMP6Handler = icmp.ICMP6NOOP{}
	return nil
}
func (h *Handler) AttachDHCP4(p dhcp4.DHCP4Handler) {
	h.DHCP4Handler = p
}
func (h *Handler) DetachDHCP4() error {
	if err := h.DHCP4Handler.Close(); err != nil {
		return err
	}
	h.DHCP4Handler = dhcp4.PacketNOOP{}
	return nil
}

func (h *Handler) setupConn() (conn net.PacketConn, err error) {
	conn, err = packet.NewServerConn(h.session.NICInfo.IFI, syscall.ETH_P_ALL, packet.SocketConfig{Filter: nil, Promiscuous: true})
	if err != nil {
		return nil, fmt.Errorf("packet.ListenPacket error: %w", err)
	}
	// don't timeout during write
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return conn, nil
}

// PrintTable logs the table to standard out
func (h *Handler) PrintTable() {
	h.session.PrintTable()
}

func (h *Handler) startPlugins() error {
	time.Sleep(time.Second * 1) // wait for reader to start

	if err := h.HandlerIP4.Start(); err != nil {
		fmt.Println("error: in IP4 start:", err)
	}
	if err := h.HandlerIP6.Start(); err != nil {
		fmt.Println("error: in IP6 start:", err)
	}
	if err := h.ICMP4Handler.Start(); err != nil {
		fmt.Println("error: in ICMP4 start:", err)
	}
	if err := h.ICMP6Handler.Start(); err != nil {
		fmt.Println("error: in ICMP6 start:", err)
	}
	if err := h.session.ARPScan(); err != nil {
		fmt.Println("error: in ARP scan:", err)
	}
	/**
	if err := h.DHCP4Handler.Start(); err != nil {
		fmt.Println("error: in DHCP4 start:", err)
	}
	*/

	h.DNSHandler.Start()

	return nil
}

func (h *Handler) stopPlugins() error {
	if err := h.HandlerIP4.Stop(); err != nil {
		fmt.Println("error: in IP4 stop:", err)
	}
	if err := h.HandlerIP6.Stop(); err != nil {
		fmt.Println("error: in IP6 stop:", err)
	}
	if err := h.ICMP4Handler.Stop(); err != nil {
		fmt.Println("error: in ICMP4 stop:", err)
	}
	if err := h.ICMP6Handler.Close(); err != nil {
		fmt.Println("error: in ICMP6 stop:", err)
	}
	if err := h.ARPHandler.Close(); err != nil {
		fmt.Println("error: in ARP stop:", err)
	}
	if err := h.DHCP4Handler.Close(); err != nil {
		fmt.Println("error: in DHCP4 close:", err)
	}
	return nil
}

func (h *Handler) FindIP6Router(ip net.IP) icmp.Router {
	return h.ICMP6Handler.FindRouter(ip)
}

var stpCount int
var stpNextLog time.Time

// ListenAndServe listen for raw packets and invoke hooks as required
func (h *Handler) ListenAndServe(ctxt context.Context) (err error) {

	// start all plugins with delay
	go h.startPlugins()
	defer h.stopPlugins()

	// minute ticker
	go h.minuteLoop()

	// Implement a single worker pattern to process packets async to the reader. This pattern
	// ensure we are reading packets as fast as possible despite the processing time of the worker.
	//
	// A single worker will ensure packets are processed in order received but
	// queue must be sufficiently large to accommodate the worker occasionally taking too long.
	const packetQueueLen = 512
	var packetBuf = sync.Pool{New: func() interface{} { return new(buffer) }}
	packetQueue := make(chan *buffer, packetQueueLen)
	go func() {
		for {
			buf, ok := <-packetQueue
			if !ok {
				fastlog.NewLine(module, "packet worker goroutine terminating")
				return
			}
			ether := packet.Ether(buf.b[:buf.n])
			h.processPacket(ether)
			packetBuf.Put(buf)
		}
	}()

	/**
	// Setup a nic monitoring goroutine to ensure we always receive IP packets.
	// If the switch port is disabled or the the nic stops receiving packets for any reason,
	// our best option is to stop the engine and likely restart.
	//
	var ipHeartBeat uint32 // ipHeartBeat is set to 1 when we receive an IP packet.
	go func() {
		for {
			time.Sleep(monitorNICFrequency)
			if atomic.LoadUint32(&ipHeartBeat) == 0 {
				fmt.Printf("fatal: failed to receive ip packets in duration=%s - sending sigterm time=%v\n", monitorNICFrequency, time.Now())
				// Send sigterm to terminate process
				syscall.Kill(os.Getpid(), syscall.SIGTERM)
			}
			atomic.StoreUint32(&ipHeartBeat, 0)
		}
	}()
	**/

	for {
		buf := packetBuf.Get().(*buffer)
		/*
			if err = h.session.Conn.SetReadDeadline(time.Now().Add(time.Second * 2)); err != nil {
				if h.closed { // closed by call to h.Close()?
					close(packetQueue)
					return nil
				}
				return fmt.Errorf("setReadDeadline error: %w", err)
			}
		*/

		buf.n, _, err = h.session.ReadFrom(buf.b[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			if h.closed { // closed by call to h.Close()?
				return nil
			}
			return fmt.Errorf("read error: %w", err)
		}

		ether := packet.Ether(buf.b[:buf.n])
		if err := ether.IsValid(); err != nil {
			fastlog.NewLine(module, "invalid ethernet packet").ByteArray("frame", ether).Write()
			continue
		}

		// Ignore packets sent via our interface
		// If we don't have this, then we received all forwarded packets with client IPs containing our host mac
		//
		// TODO: should this be in the bpf rules?
		if bytes.Equal(ether.Src(), h.session.NICInfo.HostAddr4.MAC) {
			continue
		}

		// Only interested in unicast ethernet
		if !packet.IsUnicastMAC(ether.Src()) {
			continue
		}

		if len(packetQueue) >= packetQueueLen {
			// Send sigterm to terminate process
			fastlog.NewLine(module, "error packet queue exceeded maximum limit - deadlock?").Write()
			syscall.Kill(os.Getpid(), syscall.SIGTERM)
			packetBuf.Put(buf)
			return packet.ErrNoReader
		}

		if len(packetQueue) > 32 {
			fastlog.NewLine(module, "packet queue").Int("len", len(packetQueue)).Write()
		}

		/**
		if ether.EtherType() == syscall.ETH_P_IP || ether.EtherType() == syscall.ETH_P_IPV6 {
			atomic.StoreUint32(&ipHeartBeat, 1)
		}
		**/

		// wakeup worker
		packetQueue <- buf
	}
}
