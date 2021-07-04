package packet

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	mdnsIPv4Addr = Addr{MAC: EthBroadcast, IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	mdnsIPv6Addr = Addr{MAC: EthBroadcast, IP: net.ParseIP("ff02::fb"), Port: 5353}

	// ErrInvalidChannel nil channel passed for notification
	ErrInvalidChannel = errors.New("invalid channel")
)

type serviceDef struct {
	service       string
	enabled       bool
	defaultModel  string
	authoritative bool
	keyName       string
}

var serviceTableMutex sync.RWMutex

// full IANA list here:
//
// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
//
// Bonjour
// see spec http://devimages.apple.com/opensource/BonjourPrinting.pdf
var serviceTable = []serviceDef{
	{"_http._tcp.local.", false, "Network server", false, ""},
	{"_workstation._tcp.local.", false, "", false, ""},
	{"_ipp._tcp.local.", false, "printer", true, "ty"},
	{"_ipps._tcp.local.", false, "printer", true, "ty"},
	{"_printer._tcp.local.", false, "printer", true, "ty"},
	{"_pdl-datastream._tcp.local.", false, "printer", false, "ty"},
	{"_privet._tcp.local.", false, "printer", false, "ty"},
	{"_scanner._tcp.local.", false, "scanner", false, "ty"},
	{"_uscan._tcp.local.", false, "scanner", false, "ty"},
	{"_uscans._tcp.local.", false, "scanner", false, "ty"},
	{"_smb._tcp.local.", false, "", false, "model"},
	{"_device-info._udp.local.", false, "computer", false, "model"},
	{"_device-info._tcp.local.", false, "computer", false, "model"},
	{"_netbios-ns._udp.local.", false, "", false, ""},
	{"_spotify-connect._tcp.local.", false, "Spotify speaker", false, ""},
	{"_sonos._tcp.local.", false, "Sonos speaker", true, ""},
	{"_snmp._udp.local.", false, "", false, ""},
	{"_music._tcp.local.", false, "", false, ""},
	{"_raop._tcp.local.", false, "Apple device", false, ""},           // Remote Audio Output Protocol (AirTunes) - Apple
	{"_apple-mobdev2._tcp.local.", false, "Apple device", false, ""},  // Apple Mobile Device Protocol - Apple
	{"_airplay._tcp.local.", false, "Apple TV", true, "model"},        //Protocol for streaming of audio/video content - Apple
	{"_touch-able._tcp.local.", false, "Apple device", false, "DvTy"}, //iPhone and iPod touch Remote Controllable - Apple
	{"_nvstream._tcp.local.", false, "", false, ""},
	{"_googlecast._tcp.local.", false, "Chromecast", true, "md"},
	{"_googlezone._tcp.local.", false, "Google device", false, ""},
	{"_sleep-proxy._udp.local.", false, "Apple", false, ""},
	{"_xbox._tcp.local.", false, "xbox", true, ""},
	{"_xbox._udp.local.", false, "xbox", true, ""},
	{"_psams._tcp.local.", false, "playstation", true, ""}, // play station
	{"_psams._udp.local.", false, "playstation", true, ""}, // play station
}

// PrintServices log the services table
func PrintServices() {
	for i := range serviceTable {
		fmt.Printf("service=%v poll=%v\n", serviceTable[i].service, serviceTable[i].enabled)
	}
}

func findServiceIndex(service string) int {
	serviceTableMutex.RLock()
	defer serviceTableMutex.RUnlock()

	for i := range serviceTable {
		if strings.Contains(service, serviceTable[i].service) {
			return i
		}
	}
	return -1
}

func enableService(service string) int {
	serviceTableMutex.Lock()
	defer serviceTableMutex.Unlock()

	for i := range serviceTable {
		if serviceTable[i].service == service {
			if !serviceTable[i].enabled {
				serviceTable[i].enabled = true
				return 1
			}
			return 0
		}
	}

	s := serviceDef{service: service, enabled: true}
	serviceTable = append(serviceTable, s)
	if Debug {
		fmt.Print("mdns  : enabled new mdns service=%s\n", s.service)
	}
	return 1
}

// SendQuery is used to send a multicast a query
func (h *Session) SendMDNSQuery(service string) (err error) {
	return h.sendMDNSQuery(h.NICInfo.HostAddr4, mdnsIPv4Addr, service)
}

func (h *Session) sendMDNSQuery(srcAddr Addr, dstAddr Addr, service string) (err error) {
	ether := Ether(make([]byte, EthMaxSize)) // Ping is called many times concurrently by client

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Questions: []dnsmessage.Question{
			{
				Name:  mustNewName(service),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	buf, err := msg.Pack()
	if err != nil {
		return err
	}

	// IP4
	if srcAddr.IP.To4() != nil {
		ether = EtherMarshalBinary(ether, syscall.ETH_P_IP, srcAddr.MAC, dstAddr.MAC)
		ip4 := IP4MarshalBinary(ether.Payload(), 50, srcAddr.IP, dstAddr.IP)
		if ip4, err = ip4.AppendPayload(buf, syscall.IPPROTO_ICMP); err != nil {
			return err
		}
		if ether, err = ether.SetPayload(ip4); err != nil {
			return err
		}
		if _, err := h.Conn.WriteTo(ether, &dstAddr); err != nil {
			fmt.Printf("mdns  : error failed to write %s\n", err)
		}
		return err
	}

	// IP6
	ether = EtherMarshalBinary(ether, syscall.ETH_P_IPV6, srcAddr.MAC, dstAddr.MAC)
	ip6 := IP6MarshalBinary(ether.Payload(), 10, srcAddr.IP, dstAddr.IP)
	ip6, _ = ip6.AppendPayload(buf, syscall.IPPROTO_ICMPV6)
	ether, _ = ether.SetPayload(ip6)
	if _, err := h.Conn.WriteTo(ether, &dstAddr); err != nil {
		fmt.Printf("mdns  : error failed to write %s\n", err)
	}
	return err

}

// QueryAll send a mdns discovery packet plus a mdns query for each active service on the LAN
func (h *Session) QueryAll() error {

	// Do a round of service discovery
	// The listener will pickup responses and call enableService for each
	if err := h.SendMDNSQuery("_services._dns-sd._udp.local."); err != nil {
		return fmt.Errorf("mdns  : query fail _services._dns-sd._udp.local.: %w\n", err)

	}
	time.Sleep(time.Millisecond * 5)

	serviceTableMutex.Lock()
	for i := range serviceTable {
		if err := h.SendMDNSQuery(serviceTable[i].service); err != nil {
			return fmt.Errorf("mdns  : error query fail %s: %w\n", serviceTable[i].service, err)
		}
		time.Sleep(time.Millisecond * 5)
	}
	serviceTableMutex.Unlock()
	return nil
}

/*
// TODO: do we need to register in the multicast group?
func NewHandler(nic string) (c *Handler, err error) {

		if client.mconn4, err = net.ListenMulticastUDP("udp4", nil, mdnsIPv4Addr); err != nil {
			return nil, fmt.Errorf("failed to bind to multicast udp4 port: %w", err)
		}
		if client.mconn6, err = net.ListenMulticastUDP("udp6", nil, mdnsIPv6Addr); err != nil {
			log.Printf("MDNS: Failed to bind to udp6 port: %v", err)
		}
	panic("should not call this")

	return nil, nil
}
*/

type HostName struct {
	Name       string
	Addr       Addr
	Attributes map[string]string
}

func (h *Session) ProcessMDNS(host *Host, ether Ether, payload []byte) (hosts []HostName, err error) {
	var p dnsmessage.Parser
	if _, err := p.Start(payload); err != nil {
		panic(err)
	}

	// Not interested in questions
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}

	for {
		hdr, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}

		if hdr.Class != dnsmessage.ClassINET {
			fmt.Printf("mdns  : error invalid header class %+v\n", hdr)
			continue
		}

		switch hdr.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, HostName{Name: hdr.Name.String(), Addr: Addr{IP: r.A[:]}})
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, HostName{Name: hdr.Name.String(), Addr: Addr{IP: r.AAAA[:]}})
		case dnsmessage.TypePTR: // Reverse DNS lookup (opposite of A record)
			r, err := p.PTRResource()
			if err != nil {
				return nil, err
			}
			if Debug {
				fmt.Printf("mdns  : PTR name=%s ptr=%s\n", hdr.Name, r.PTR)
			}

			// if Name is a service discover then this is a pointer to a
			// service this client provides.
			//
			// An example from a Sonos Play3 speaker
			//     dns.PTR name=_services._dns-sd._udp.local. ptr=_spotify-connect._tcp.local."
			// Example spotify ptr answer
			//     dns.PTR name=_spotify-connect._tcp.local. ptr=sonosB8E9372ACF56._spotify-connect._tcp.local.

			// TODO: do we want to capture other MDNS services
			/**
			if hdr.Name.String() == "_services._dns-sd._udp.local." {
				if enableService(r.PTR.String()) > 0 {
					if Debug {
						fmt.Printf("mdns  : send query ptr=%s\n", r.PTR)
					}
					h.SendMDNSQuery(r.PTR.String())
				}
				break
			}
			**/
		case dnsmessage.TypeSRV:
			// Service record :
			//    _service._proto.name. TTL class SRV priority weight port target
			// example:
			//	  dns.SRV name=sonosB8E9372ACF56._spotify-connect._tcp.local. target=sonosB8E9372ACF56.local. port=1400
			r, err := p.SRVResource()
			if err != nil {
				return nil, err
			}
			if Debug {
				fmt.Printf("mdns  : SRV name=%s target=%s port=%d\n", hdr.Name, r.Target, r.Port)
			}

			// r.Target is the host name and Hdr.Name contains the FQN
			// entry.addSRV(rr.Hdr.Name, rr.Target, rr.Port)

		case dnsmessage.TypeTXT:
			r, err := p.TXTResource()
			if err != nil {
				return nil, err
			}
			if Debug {
				fmt.Printf("mdns  : TXT name=%s txt=%s", hdr.Name, r.TXT)
			}

			// Pull out the txt
			//   dns.TXT name=sonosB8E9372ACF56._spotify-connect._tcp.local. txt=[VERSION=1.0 CPath=/spotifyzc]"
			// entry.addTXT(hdr.Name, r.TXT)

		default:
			fmt.Printf("mdns  : error type unexpected %+v", hdr)
		}
	}

	return hosts, nil
}

func mustNewName(name string) dnsmessage.Name {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		panic(err)
	}
	return n
}

func ExampleParser() {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Questions: []dnsmessage.Question{
			{
				Name:  mustNewName("foo.bar.example.com."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
			{
				Name:  mustNewName("bar.example.com."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  mustNewName("foo.bar.example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
			},
			{
				Header: dnsmessage.ResourceHeader{
					Name:  mustNewName("bar.example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 2}},
			},
		},
	}

	buf, err := msg.Pack()
	if err != nil {
		panic(err)
	}

	wantName := "bar.example.com."

	var p dnsmessage.Parser
	if _, err := p.Start(buf); err != nil {
		panic(err)
	}

	for {
		q, err := p.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			panic(err)
		}

		if q.Name.String() != wantName {
			continue
		}

		fmt.Println("Found question for name", wantName)
		if err := p.SkipAllQuestions(); err != nil {
			panic(err)
		}
		break
	}

	var gotIPs []net.IP
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			panic(err)
		}

		if (h.Type != dnsmessage.TypeA && h.Type != dnsmessage.TypeAAAA) || h.Class != dnsmessage.ClassINET {
			continue
		}

		if !strings.EqualFold(h.Name.String(), wantName) {
			if err := p.SkipAnswer(); err != nil {
				panic(err)
			}
			continue
		}

		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				panic(err)
			}
			gotIPs = append(gotIPs, r.A[:])
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				panic(err)
			}
			gotIPs = append(gotIPs, r.AAAA[:])
		}
	}

	fmt.Printf("Found A/AAAA records for name %s: %v\n", wantName, gotIPs)

	// Output:
	// Found question for name bar.example.com.
	// Found A/AAAA records for name bar.example.com.: [127.0.0.2]
}
