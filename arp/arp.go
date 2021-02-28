package arp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"log"

	"github.com/irai/packet/raw"
)

// Config holds configuration parameters
//
// Set FullNetworkScanInterval = 0 to avoid network scan
type Config struct {
	FullNetworkScanInterval time.Duration `yaml:"-"` // Set it to zero if no scan required
	ProbeInterval           time.Duration `yaml:"-"` // how often to probe if IP is online
	OfflineDeadline         time.Duration `yaml:"-"` // mark offline if more than OfflineInte
	PurgeDeadline           time.Duration `yaml:"-"`
}

func (c Config) String() string {
	return fmt.Sprintf("scan=%v probe=%s offline=%v purge=%v",
		c.FullNetworkScanInterval, c.ProbeInterval, c.OfflineDeadline, c.PurgeDeadline)
}

type Data struct {
	IPArray [nIPs]IPEntry
	State   arpState
	ClaimIP bool // if true, will claim the target IP; likely to force the target IP to stop working
}

// must implement interface
var _ raw.PacketProcessor = &Handler{}

// Handler stores instance variables
type Handler struct {
	conn     net.PacketConn
	LANHosts *raw.HostTable
	virtual  *arpTable
	NICInfo  *raw.NICInfo
	config   Config
	sync.RWMutex
	notification chan<- MACEntry // notification channel for state change
	wg           sync.WaitGroup
}

var (
	// Debug - set Debug to true to see debugging messages
	Debug bool
)

// New creates an ARP handler for a given connection
func New(info *raw.NICInfo, conn net.PacketConn, table *raw.HostTable, config Config) (h *Handler, err error) {
	h = &Handler{}
	// h.table, _ = loadARPProcTable() // load linux proc table
	h.LANHosts = table
	h.virtual = newARPTable()
	h.NICInfo = info
	if h.NICInfo.HostIP4.IP = info.HostIP4.IP.To4(); h.NICInfo.HostIP4.IP == nil {
		return nil, raw.ErrInvalidIP4
	}
	h.config.FullNetworkScanInterval = config.FullNetworkScanInterval
	h.config.ProbeInterval = config.ProbeInterval
	h.config.OfflineDeadline = config.OfflineDeadline
	h.config.PurgeDeadline = config.PurgeDeadline
	h.conn = conn

	if h.NICInfo.HomeLAN4.IP == nil && h.NICInfo.HomeLAN4.IP.IsUnspecified() {
		return nil, raw.ErrInvalidIP4
	}

	if h.config.FullNetworkScanInterval <= 0 || h.config.FullNetworkScanInterval > time.Hour*12 {
		h.config.FullNetworkScanInterval = time.Minute * 60
	}
	if h.config.ProbeInterval <= 0 || h.config.ProbeInterval > time.Minute*10 {
		h.config.ProbeInterval = time.Minute * 2
	}
	if h.config.OfflineDeadline <= h.config.ProbeInterval {
		h.config.OfflineDeadline = h.config.ProbeInterval * 2
	}
	if h.config.PurgeDeadline <= h.config.OfflineDeadline {
		h.config.PurgeDeadline = time.Minute * 61
	}

	if Debug {
		log.Printf("arp Config %s", h.config)
		h.PrintTable()
	}

	return h, nil
}

// StartHunt implements PacketProcessor interface
func (h *Handler) StartHunt(mac net.HardwareAddr) error {
	return h.StartSpoofMAC(mac)
}

// StopHunt implements PacketProcessor interface
func (h *Handler) StopHunt(mac net.HardwareAddr) error {
	return h.StopSpoofMAC(mac)
}

// Stop implements PacketProcessor interface
func (h *Handler) Stop() error {
	return nil
}

// PrintTable print the ARP table to stdout.
func (h *Handler) PrintTable() {
	h.virtual.printTable()
}

// Close will terminate the ListenAndServer goroutine as well as all other pending goroutines.
func (h *Handler) End() {
	// Don't close the socket - it is shared with packet
}

// Start start background processes
func (h *Handler) Start() error {

	ctx := context.Background()
	if h.config.FullNetworkScanInterval != 0 {
		// continuosly scan for network devices
		go func() {
			h.wg.Add(1)
			if err := h.scanLoop(ctx, h.config.FullNetworkScanInterval); err != nil {
				log.Print("arp goroutine scanLoop terminated unexpectedly", err)
				h.conn.Close() // force error in main loop
			}
			h.wg.Done()
			if Debug {
				log.Print("arp goroutine scanLoop ended")
			}
		}()
	}

	// Do a full scan on start
	if h.config.FullNetworkScanInterval != 0 && h.NICInfo.HomeLAN4.IP.To4() != nil {
		go func() {
			h.wg.Add(1)
			if err := h.ScanNetwork(ctx, h.NICInfo.HomeLAN4); err != nil {
				log.Print("arp ListenAndServer scanNetwork terminated unexpectedly", err)
				h.conn.Close() // force error in main loop
			}
			h.wg.Done()
			if Debug {
				log.Print("arp goroutine scanNetwork ended normally")
			}
		}()
	}

	return nil
}

const (
	request = iota
	reply
	announcement
	gratuitous
	probe
)

// ProcessPacket handles an incoming ARP packet
//
// Virtual MACs
// A virtual MAC is a fake mac address used when claiming an existing IP during spoofing.
// ListenAndServe will send ARP reply on behalf of virtual MACs
//
// ARP: packet types
//      note that RFC 3927 specifies 00:00:00:00:00:00 for Request TargetMAC
// +============+===+===========+===========+============+============+===================+===========+
// | Type       | op| EthDstMAC | EthSRCMAC | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
// +============+===+===========+===========+============+============+===================+===========+
// | request    | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  targetIP |
// | reply      | 2 | clientMAC | targetMAC | targetMAC  | targetIP   | clientMAC         |  clientIP |
// | gratuitous | 2 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
// | ACD probe  | 1 | broadcast | clientMAC | clientMAC  | 0x00       | 0x00              |  targetIP |
// | ACD announ | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
// +============+===+===========+===========+============+============+===================+===========+
func (h *Handler) ProcessPacket(host *raw.Host, b []byte) (*raw.Host, error) {

	ether := raw.Ether(b)
	frame := ARP(ether.Payload())
	if !frame.IsValid() {
		return host, raw.ErrParseMessage
	}

	// skip link local packets
	if frame.SrcIP().IsLinkLocalUnicast() || frame.DstIP().IsLinkLocalUnicast() {
		if Debug {
			log.Printf("arp skipping link local packet smac=%v sip=%v tmac=%v tip=%v", frame.SrcMAC(), frame.SrcIP(), frame.DstMAC(), frame.DstIP())
		}
		return host, nil
	}

	var operation int
	switch {
	case frame.Operation() == OperationReply:
		operation = reply
	case frame.Operation() == OperationRequest:
		switch {
		case frame.SrcIP().Equal(frame.DstIP()):
			operation = announcement
		case frame.SrcIP().Equal(net.IPv4zero):
			operation = probe
		default:
			operation = request
		}
	default:
		log.Printf("arp invalid operation: %s", frame)
		return host, nil
	}

	switch operation {
	case request:
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| EthDstMAC | EthSRCMAC | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | request    | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  targetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Debug {
			fmt.Println("ether:", ether)
			fmt.Printf("arp  : who is %s: %s\n", frame.DstIP(), frame)
		}
		// if targetIP is a virtual host, we are claiming the ip; reply and return
		h.RLock()
		if target := h.virtual.findVirtualIP(frame.DstIP()); target != nil {
			mac := target.MAC
			h.RUnlock()
			if Debug {
				log.Printf("arp ip=%s is virtual - send reply smac=%v", frame.DstIP(), mac)
			}
			h.reply(frame.SrcMAC(), mac, frame.DstIP(), EthernetBroadcast, frame.DstIP())
			return host, nil
		}
		h.RUnlock()

	case probe:
		// We are not interested in probe ACD (Address Conflict Detection) packets
		// if this is a probe, the sender IP will be zeros; do nothing as the sender IP is not valid yet.
		//
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| dstMAC    | srcMAC    | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | ACD probe  | 1 | broadcast | clientMAC | clientMAC  | 0x00       | 0x00              |  targetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Debug {
			fmt.Println("ether:", ether)
			fmt.Printf("arp  : probe recvd: %s\n", frame)
		}

		// don't continue
		return host, nil

	case announcement:
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| dstMAC    | srcMAC    | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | ACD announ | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Debug {
			fmt.Println("ether:", ether)
			fmt.Printf("arp  : announcement recvd: %s\n", frame)
		}
		// if targetIP is a virtual host, we are claiming the ip; reply and return
		h.RLock()
		if target := h.virtual.findVirtualIP(frame.DstIP()); target != nil {
			mac := target.MAC
			h.RUnlock()
			if Debug {
				log.Printf("arp ip=%s is virtual - send reply smac=%v", frame.DstIP(), mac)
			}
			h.reply(frame.SrcMAC(), mac, frame.DstIP(), EthernetBroadcast, frame.DstIP())
			return host, nil
		}
		h.RUnlock()

	default:
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| EthDstMAC | EthSRCMAC | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | reply      | 2 | clientMAC | targetMAC | targetMAC  | targetIP   | clientMAC         |  clientIP |
		// | gratuitous | 2 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Debug {
			fmt.Println("ether:", ether)
			fmt.Printf("arp  : reply recvd: %s\n", frame)
		}
	}

	// If new client, then create a MACEntry in table
	if host == nil && h.NICInfo.HostIP4.Contains(frame.SrcIP()) {
		host, _ = h.LANHosts.FindOrCreateHost(frame.SrcMAC(), frame.SrcIP())
	}
	return host, nil
}
