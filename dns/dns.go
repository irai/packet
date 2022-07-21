package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
)

const module = "dns"

var Debug bool
var Logger = fastlog.New(module)

type DNSHandler struct {
	session   *packet.Session
	DNSTable  map[string]DNSEntry // store dns records
	mutex     sync.RWMutex
	mconn4    *net.UDPConn
	mconn6    *net.UDPConn
	ssdpconn4 *net.UDPConn
	mdnsCache map[string]cache
}

func New(session *packet.Session) (h *DNSHandler, err error) {
	h = new(DNSHandler)
	h.session = session
	h.DNSTable = make(map[string]DNSEntry, 256)
	h.mdnsCache = make(map[string]cache)

	// Resgiter for MDNS multicast
	if h.mconn4, err = net.ListenMulticastUDP("udp4", nil, &net.UDPAddr{IP: mdnsIPv4Addr.IP.AsSlice(), Port: int(mdnsIPv4Addr.Port)}); err != nil {
		return nil, fmt.Errorf("failed to bind to multicast udp4 port: %w", err)
	}
	if h.mconn6, err = net.ListenMulticastUDP("udp6", nil, &net.UDPAddr{IP: mdnsIPv6Addr.IP.AsSlice(), Port: int(mdnsIPv6Addr.Port)}); err != nil {
		log.Printf("MDNS: Failed to bind to udp6 port: %v", err)
	}

	// Register for ssdp multicast
	if h.ssdpconn4, err = net.ListenMulticastUDP("udp4", nil, &net.UDPAddr{IP: ssdpIPv4Addr.IP.AsSlice(), Port: int(ssdpIPv4Addr.Port)}); err != nil {
		return nil, fmt.Errorf("failed to bind to ssdp ipv4 port: %w", err)
	}
	return h, nil
}

func (h *DNSHandler) Close() error {
	h.DNSTable = nil
	h.mdnsCache = nil
	return nil
}

func (h *DNSHandler) Start() error {
	if err := h.SendNBNSNodeStatus(); err != nil {
		return err
	}
	return nil
}

// reverseDNS query the PTR record for ip
// return ErrNotFound if there is no PTR record
func ReverseDNS(ip netip.Addr) error {
	if Debug {
		fmt.Printf("dns   : reverse lookup for ip=%s\n", ip)
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, net.JoinHostPort(packet.DNSv4CloudFlare1.String(), "53")) //CloudFlare
		},
	}

	names, err := resolver.LookupAddr(context.TODO(), ip.String())
	if err != nil {
		// errors.As(err, &dnsErr) - as not implemented yet
		dnsErr, ok := err.(*net.DNSError)
		if ok && dnsErr.IsNotFound {
			if Debug {
				fmt.Printf("dns   : reverse lookup not found for ip=%s: %s %+v\n", ip, err, *dnsErr)
			}
			return packet.ErrNotFound
		}
		return err
	}
	if Debug {
		Logger.Msg("reverse dns ok").String("ip", ip.String()).StringArray("names", names).Write()
	}
	return nil
}

// ProcessDNS parse the DNS packet and record in DNS cache table.
//
// It returns a copy of the DNSEntry that is free from race conditions. The caller has a unique copy.
//
func (h *DNSHandler) ProcessDNS(frame packet.Frame) (e DNSEntry, err error) {
	p := DNS(frame.Payload())
	if err := p.IsValid(); err != nil {
		return DNSEntry{}, err
	}

	// buffer for doing name decoding.  We use a single reusable buffer to avoid
	// constant allocation of small byte slices during dns name parsing.
	buffer := make([]byte, 0, 64) // allocate enough to minimise allocation
	var question Question

	index := 12
	question, index, err = decodeQuestion(p, index, buffer)
	if err != nil {
		return DNSEntry{}, err
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	e, found := h.DNSTable[string(question.Name)] // lookup directly from []byte to avoid allocation
	if !found {
		e = newDNSEntry()
		e.Name = string(question.Name)
		e.IP4Records = make(map[netip.Addr]IPResourceRecord)
		e.IP6Records = make(map[netip.Addr]IPResourceRecord)
		e.CNameRecords = make(map[string]NameResourceRecord)
		e.PTRRecords = make(map[string]IPResourceRecord)
	}

	var updated bool
	if _, updated, err = e.decodeAnswers(p, index, buffer); err != nil {
		return DNSEntry{}, err
	}
	if updated {
		if Debug {
			Logger.Msg("entry").Struct(e).Write()
		}
		h.DNSTable[e.Name] = e
		return e.copy(), nil // return a copy to avoid race on maps
	}
	return DNSEntry{}, nil
}
