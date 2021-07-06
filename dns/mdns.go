package dns

import (
	"fmt"
	"net"
	"syscall"

	"github.com/irai/packet"
	"golang.org/x/net/dns/dnsmessage"
)

// MDNS RFC
//    see https://datatracker.ietf.org/doc/html/rfc6762
//
//    One of the motivations for DNS-based Service Discovery is to enable a
//    visiting client (e.g., a Wi-Fi-equipped [IEEEW] laptop computer,
//    tablet, or mobile telephone) arriving on a new network to discover
//    what services are available on that network, without any manual
//    configuration.
//
//    This discovery is performed using DNS queries, using Unicast or
//    Multicast DNS.  Five special RR names are reserved for this purpose:
//
//     b._dns-sd._udp.<domain>.
//    db._dns-sd._udp.<domain>.
//     r._dns-sd._udp.<domain>.
//    dr._dns-sd._udp.<domain>.
//    lb._dns-sd._udp.<domain>.
//
// TODO: investigate mdns domain resolution
//    For example, if a host has the address 192.168.12.34, with
//    the subnet mask 255.255.0.0, then the 'base' address of the subnet is
//    192.168.0.0, and to discover the recommended automatic browsing
//    domain(s) for devices on this subnet, the host issues a DNS PTR query
//    for the name "lb._dns-sd._udp.0.0.168.192.in-addr.arpa."
//
// Service Discovery RFC
//    see https://datatracker.ietf.org/doc/html/rfc6763
//
// Given a type of service that a client is looking for, and a domain in which the client is
// looking for that service, this mechanism allows clients to discover a
// list of named instances of that desired service, using standard DNS
// queries.  This mechanism is referred to as DNS-based Service Discovery, or DNS-SD.
const MDNSServiceDiscovery = "_services._dns-sd._udp.local."

var (
	// Any DNS query for a name ending with ".local." MUST be sent to the
	// mDNS IPv4 link-local multicast address 224.0.0.251 (or its IPv6 equivalent FF02::FB).
	mdnsIPv4Addr = packet.Addr{MAC: packet.EthBroadcast, IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	mdnsIPv6Addr = packet.Addr{MAC: packet.EthBroadcast, IP: net.ParseIP("ff02::fb"), Port: 5353}

	// TODO: do we need LLMNR?
	// Link Local Multicast Name Resolution
	// https://datatracker.ietf.org/doc/html/rfc4795
	//
	// LLMNR queries are sent to and received on port 5355.  The IPv4 link-
	// scope multicast address a given responder listens to, and to which a
	// sender sends queries, is 224.0.0.252.  The IPv6 link-scope multicast
	// address a given responder listens to, and to which a sender sends all
	// queries, is FF02:0:0:0:0:0:1:3.
	//
	// Windows hosts will query a name on startup to prevent duplicates on the LAN
	// https://docs.microsoft.com/en-us/previous-versions//bb878128(v=technet.10)?redirectedfrom=MSDN
	llmnrIPv4Addr = packet.Addr{MAC: packet.EthBroadcast, IP: net.IPv4(224, 0, 0, 251), Port: 5355}
	llmnrIPv6Addr = packet.Addr{MAC: packet.EthBroadcast, IP: net.ParseIP("FF02:0:0:0:0:0:1:3"), Port: 5355}
)

type serviceDef struct {
	service       string
	enabled       bool
	defaultModel  string
	authoritative bool
	keyName       string
}

// see full service list here:
// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml
// previous: http://dns-sd.org/ServiceTypes.html
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

// SendMDNSQuery send a multicast DNS query
func (h *DNSHandler) SendMDNSQuery(name string) (err error) {
	return h.sendMDNSQuery(h.session.NICInfo.HostAddr4, mdnsIPv4Addr, name)
}

// SendLLMNRQuery send a multicast LLMNR query
func (h *DNSHandler) SendLLMNRQuery(name string) (err error) {
	return h.sendMDNSQuery(h.session.NICInfo.HostAddr4, llmnrIPv4Addr, name)
}

func (h *DNSHandler) sendMDNSQuery(srcAddr packet.Addr, dstAddr packet.Addr, name string) (err error) {

	// Multicast DNS does not share this property that qtype "ANY" and
	// qclass "ANY" queries return some undefined subset of the matching
	// records.  When responding to queries using qtype "ANY" (255) and/or
	// qclass "ANY" (255), a Multicast DNS responder MUST respond with *ALL*
	// of its records that match the query.
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: false},
		Questions: []dnsmessage.Question{
			{
				Name:  mustNewName(name),
				Type:  dnsmessage.TypeALL,
				Class: dnsmessage.ClassANY,
			},
		},
		Answers:     []dnsmessage.Resource{},
		Authorities: []dnsmessage.Resource{},
		Additionals: []dnsmessage.Resource{},
	}
	buf, err := msg.Pack()
	if err != nil {
		return err
	}

	ether := packet.Ether(make([]byte, packet.EthMaxSize))

	//  The source UDP port in all Multicast DNS responses MUST be 5353 (the
	//  well-known port assigned to mDNS).  Multicast DNS implementations
	//  MUST silently ignore any Multicast DNS responses they receive where
	//  the source UDP port is not 5353.
	//
	//  The destination UDP port in all Multicast DNS responses MUST be 5353,
	//  and the destination address MUST be the mDNS IPv4 link-local
	//  multicast address 224.0.0.251 or its IPv6 equivalent FF02::FB, except
	//  when generating a reply to a query that explicitly requested a
	//  unicast response

	// IP4
	if srcAddr.IP.To4() != nil {
		ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_IP, srcAddr.MAC, dstAddr.MAC)
		ip4 := packet.IP4MarshalBinary(ether.Payload(), 255, srcAddr.IP, dstAddr.IP)
		udp := packet.UDPMarshalBinary(ip4.Payload(), dstAddr.Port, dstAddr.Port) // same port number for src and dst
		if udp, err = udp.AppendPayload(buf); err != nil {
			return err
		}
		ip4 = ip4.SetPayload(udp, syscall.IPPROTO_UDP)
		if ether, err = ether.SetPayload(ip4); err != nil {
			return err
		}
		if _, err := h.session.Conn.WriteTo(ether, &dstAddr); err != nil {
			fmt.Printf("mdns  : error failed to write %s\n", err)
		}
		return err
	}

	// IP6
	ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_IPV6, srcAddr.MAC, dstAddr.MAC)
	ip6 := packet.IP6MarshalBinary(ether.Payload(), 255, srcAddr.IP, dstAddr.IP)
	udp := packet.UDPMarshalBinary(ip6.Payload(), dstAddr.Port, dstAddr.Port) // same port number for src and dst
	if udp, err = udp.AppendPayload(buf); err != nil {
		return err
	}
	ip6 = ip6.SetPayload(udp, syscall.IPPROTO_UDP)
	ether, _ = ether.SetPayload(ip6)
	if _, err := h.session.Conn.WriteTo(ether, &dstAddr); err != nil {
		fmt.Printf("mdns  : error failed to write %s\n", err)
	}
	return err
}

type HostName struct {
	Name       string
	Addr       packet.Addr
	Attributes map[string]string
}

func (h *DNSHandler) ProcessMDNS(host *packet.Host, ether packet.Ether, payload []byte) (hosts []HostName, err error) {
	var p dnsmessage.Parser
	dnsHeader, err := p.Start(payload)
	if err != nil {
		panic(err)
	}
	if Debug {
		fmt.Printf("mdns  : header %+v\n", dnsHeader)
	}
	if !dnsHeader.Response {
		return
	}

	//  Multicast DNS responses MUST NOT contain any questions in the
	//  Question Section.  Any questions in the Question Section of a
	//  received Multicast DNS response MUST be silently ignored.  Multicast
	//  DNS queriers receiving Multicast DNS responses do not care what
	//  question elicited the response; they care only that the information
	//  in the response is true and accurate.
	//    see https://datatracker.ietf.org/doc/html/rfc6762 section 6
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}

	section := "answer"
	for {
		var hdr dnsmessage.ResourceHeader
		switch section {
		case "answer":
			hdr, err = p.AnswerHeader()
			if err == dnsmessage.ErrSectionDone {
				section = "authority"
				continue
			}
		case "authority":
			hdr, err = p.AuthorityHeader()
			if err == dnsmessage.ErrSectionDone {
				section = "additional"
				continue
			}
		case "additional":
			hdr, err = p.AdditionalHeader()
			if err == dnsmessage.ErrSectionDone {
				return hosts, nil
			}
		}
		if err != nil {
			return nil, err
		}

		switch hdr.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, err
			}
			entry := HostName{Name: hdr.Name.String(), Addr: packet.Addr{IP: packet.CopyIP(r.A[:])}}
			hosts = append(hosts, entry)
			if Debug {
				fmt.Printf("mdns  : A record name=%s %s\n", entry.Name, entry.Addr)
			}

		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, err
			}
			entry := HostName{Name: hdr.Name.String(), Addr: packet.Addr{IP: packet.CopyIP(r.AAAA[:])}}
			hosts = append(hosts, entry)
			if Debug {
				fmt.Printf("mdns  : AAAA record name=%s %s\n", entry.Name, entry.Addr)
			}

		case dnsmessage.TypePTR:
			r, err := p.PTRResource()
			if err != nil {
				fmt.Printf("mdns  : error invalid PTR resource name=%s error=[%s]\n", hdr.Name, err)
				p.SkipAnswer()
				continue
			}
			if Debug {
				fmt.Printf("mdns  : PTR name=%s %s\n", hdr.Name, r.PTR)
			}

		case dnsmessage.TypeSRV:
			// Service record :
			//    _service._proto.name. TTL class SRV priority weight port target
			// example:
			//	  dns.SRV name=sonosB8E9372ACF56._spotify-connect._tcp.local. target=sonosB8E9372ACF56.local. port=1400
			r, err := p.SRVResource()
			if err != nil {
				fmt.Printf("mdns  : error invalid SRV resource name=%s error=[%s]\n", hdr.Name, err)
				p.SkipAnswer()
				continue
			}
			if Debug {
				fmt.Printf("mdns  : SRV name=%s target=%s port=%d\n", hdr.Name, r.Target, r.Port)
			}

		case dnsmessage.TypeTXT:
			r, err := p.TXTResource()
			if err != nil {
				fmt.Printf("mdns  : error invalid TXT resource name=%s error=[%s]\n", hdr.Name, err)
				p.SkipAnswer()
				continue
			}
			if Debug {
				fmt.Printf("mdns  : TXT name=%s txt=%s\n", hdr.Name, r.TXT)
			}

			// Pull out the txt
			//   dns.TXT name=sonosB8E9372ACF56._spotify-connect._tcp.local. txt=[VERSION=1.0 CPath=/spotifyzc]"
			// entry.addTXT(hdr.Name, r.TXT)

		default:
			fmt.Printf("mdns  : error unexpected resource type %+v\n", hdr)
			p.SkipAnswer()
		}
	}
}

func mustNewName(name string) dnsmessage.Name {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		panic(err)
	}
	return n
}
