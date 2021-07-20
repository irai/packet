package dns

import (
	"fmt"
	"net"
	"strings"
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

	// TODO: do we need LLMNR? perhaps useful when a new windows machine is pluggedin?

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
	// https://docs.microsoft.com/en-us/previous-versions//bb878128(v=technet.10)
	llmnrIPv4Addr = packet.Addr{MAC: packet.EthBroadcast, IP: net.IPv4(224, 0, 0, 251), Port: 5355}
	llmnrIPv6Addr = packet.Addr{MAC: packet.EthBroadcast, IP: net.ParseIP("FF02:0:0:0:0:0:1:3"), Port: 5355}
)

// SendMDNSQuery send a multicast DNS query
func (h *DNSHandler) SendMDNSQuery(name string) (err error) {
	// When responding to queries using qtype "ANY" (255) and/or
	// qclass "ANY" (255), a Multicast DNS responder MUST respond with *ALL*
	// of its records that match the query.
	return h.sendMDNSQuery(h.session.NICInfo.HostAddr4, mdnsIPv4Addr, dnsmessage.TypeALL, name)
}

// SendLLMNRQuery send a multicast LLMNR query
func (h *DNSHandler) SendLLMNRQuery(name string) (err error) {
	return h.sendMDNSQuery(h.session.NICInfo.HostAddr4, llmnrIPv4Addr, dnsmessage.TypePTR, name)
}

func (h *DNSHandler) sendMDNSQuery(srcAddr packet.Addr, dstAddr packet.Addr, mtype dnsmessage.Type, name string) (err error) {
	// TODO: mdns request unicast for response messages to minimise traffic. How???
	//    To avoid large floods of potentially unnecessary responses in these
	//    cases, Multicast DNS defines the top bit in the class field of a DNS
	//    question as the unicast-response bit.  When this bit is set in a
	//    question, it indicates that the querier is willing to accept unicast
	//    replies in response to this specific query, as well as the usual
	//    multicast responses.
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

	buffer := h.session.EtherPool.Get().(*[packet.EthMaxSize]byte) // reuse buffers
	defer h.session.EtherPool.Put(buffer)
	ether := packet.Ether(buf[:])
	// ether := packet.Ether(make([]byte, packet.EthMaxSize))

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

var macEntryInvalid = packet.MACEntry{}

func (h *DNSHandler) ProcessMDNS(host *packet.Host, ether packet.Ether, payload []byte) (ipv4 packet.Host, ipv6 packet.Host, err error) {
	var p dnsmessage.Parser
	dnsHeader, err := p.Start(payload)
	if err != nil {
		panic(err)
	}
	if Debug {
		fmt.Printf("mdns  : new packet %s %+v\n", host, dnsHeader)
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
		return ipv4, ipv6, err
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
				return ipv4, ipv6, nil
			}
		}
		if err != nil {
			return ipv4, ipv6, err
		}

		switch hdr.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return ipv4, ipv6, err
			}
			ipv4.MDNSName = strings.TrimSuffix(hdr.Name.String(), ".local.")
			ipv4.Addr.MAC = packet.CopyMAC(ether.Src())
			ipv4.Addr.IP = packet.CopyIP(r.A[:])
			ipv4.MACEntry = &macEntryInvalid // host must have a mac entry
			if Debug {
				fmt.Printf("mdns  : A record name=%s %s\n", ipv4.MDNSName, ipv4.Addr)
			}

		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return ipv4, ipv6, err
			}
			ipv6.MDNSName = strings.TrimSuffix(hdr.Name.String(), ".local.")
			ipv6.Addr.MAC = packet.CopyMAC(ether.Src())
			ipv6.Addr.IP = packet.CopyIP(r.AAAA[:])
			ipv6.MACEntry = &macEntryInvalid // host must have a mac entry
			if Debug {
				fmt.Printf("mdns  : AAAA record name=%s %s\n", ipv6.MDNSName, ipv6.Addr)
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
				// Don't log if compressed error.
				// It is invalid to compress SRV name but some do. In particular Google Chromecast.
				// This polutes the log with constant errors for each SRV.
				// see https://github.com/golang/go/issues/10622
				if err.Error() != "compressed name in SRV resource data" || Debug {
					fmt.Printf("mdns  : error invalid SRV resource name=%s error=[%s]\n", hdr.Name, err)
				}
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
			if model := parseTXT(r.TXT); model != "" {
				ipv4.Model = model
				ipv6.Model = model
			}
			if Debug {
				fmt.Printf("mdns  : TXT name=%s txt=%s model=%s\n", hdr.Name, r.TXT, ipv4.Model)
			}

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
