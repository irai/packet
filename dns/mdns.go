package dns

import (
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
	"golang.org/x/net/dns/dnsmessage"
)

// MDNS RFC
//    see https://datatracker.ietf.org/doc/html/rfc6762
//    see Apple bonjour - https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/NetServices/Introduction.html
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

const moduleMDNS = "mdns"

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
	return h.sendMDNS(buf, srcAddr, dstAddr)
}

func (h *DNSHandler) sendMDNS(buf []byte, srcAddr packet.Addr, dstAddr packet.Addr) (err error) {
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
		ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_IP, h.session.NICInfo.HostAddr4.MAC, dstAddr.MAC)
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
			fastlog.NewLine(moduleMDNS, "failed to write").Error(err).Write()
		}
		return err
	}

	// IP6
	ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_IPV6, h.session.NICInfo.HostAddr4.MAC, dstAddr.MAC)
	ip6 := packet.IP6MarshalBinary(ether.Payload(), 255, srcAddr.IP, dstAddr.IP)
	udp := packet.UDPMarshalBinary(ip6.Payload(), dstAddr.Port, dstAddr.Port) // same port number for src and dst
	if udp, err = udp.AppendPayload(buf); err != nil {
		return err
	}
	ip6 = ip6.SetPayload(udp, syscall.IPPROTO_UDP)
	ether, _ = ether.SetPayload(ip6)
	if _, err := h.session.Conn.WriteTo(ether, &dstAddr); err != nil {
		fastlog.NewLine(moduleMDNS, "failed to write").Error(err).Write()
	}
	return nil
}

func (h *DNSHandler) SendSleepProxyResponse(srcAddr packet.Addr, dstAddr packet.Addr, id uint16, name string) (err error) {
	if Debug {
		fastlog.NewLine(moduleMDNS, "send sleep proxy announcement").Struct(dstAddr).Write()
	}

	// Server response format: See https://datatracker.ietf.org/doc/html/rfc6763
	//
	// see http://www.cnpbagwell.com/mac-os-x/bonjour-sleep-proxy
	// Example python code: https://github.com/kfix/SleepProxyServer/blob/master/sleepproxy/manager.py

	// Sleep proxy encode information in front of the name
	// #<SPSType>-<SPSPortability>-<SPSMarginalPower>-<SPSTotalPower>.<SPSFeatureFlags> <nicelabel>
	name = "10-34-10-70 SleepProxyServer._sleep-proxy._udp.local."
	var ip4 [4]byte
	copy(ip4[:], h.session.NICInfo.HostAddr4.IP)
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, Response: true},

		// MDNS-SD PTR answer record
		// Instead of requesting records of type "SRV" with name "_ipp._tcp.example.com.",
		// the client requests records of type "PTR" (pointer from one name to
		// another in the DNS namespace) [RFC1035].
		// The result of this PTR lookup for the name "<Service>.<Domain>" is a
		//  set of zero or more PTR records giving Service Instance Names of the
		//  form:
		//        Service Instance Name = <Instance> . <Service> . <Domain>
		Questions: []dnsmessage.Question{
			/*
				{
					Name:  mustNewName(name),
					Type:  dnsmessage.TypeALL,
					Class: dnsmessage.ClassANY,
				},
			*/
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  mustNewName("_sleep-proxy._udp.local."),
					Type:  dnsmessage.TypePTR,
					Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.PTRResource{PTR: mustNewName(name)},
			},
			{
				Header: dnsmessage.ResourceHeader{
					Name:  mustNewName(name),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.AResource{A: ip4},
			},
			{
				Header: dnsmessage.ResourceHeader{
					Name:  mustNewName(name),
					Type:  dnsmessage.TypeSRV,
					Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.SRVResource{Target: mustNewName(name), Port: 5353},
			},
			//Every DNS-SD service MUST have a TXT record in addition to its SRV
			// record, with the same name, even if the service has no additional
			// data to store and the TXT record contains no more than a single zero
			// byte.
			{
				Header: dnsmessage.ResourceHeader{
					Name:  mustNewName(name),
					Type:  dnsmessage.TypeTXT,
					Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.TXTResource{TXT: []string{"vers=1.0"}},
			},
		},
		Authorities: []dnsmessage.Resource{},
		Additionals: []dnsmessage.Resource{},
	}
	buf, err := msg.Pack()
	if err != nil {
		return err
	}
	return h.sendMDNS(buf, srcAddr, dstAddr)
}

type HostName struct {
	Name       string
	Addr       packet.Addr
	Attributes map[string]string
}

// cache implements a simple cache for DNS responses. Clients multicast the same answer several times
// and at least twice, once for IPv4 and once for IPv6.
type cache struct {
	ipv4   []packet.IPNameEntry
	ipv6   []packet.IPNameEntry
	id     uint16
	expiry time.Time
}

func (h *DNSHandler) getMDNSCache(mac net.HardwareAddr, id uint16) (c cache, found bool) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	key := make([]byte, 6+2)
	copy(key, mac)
	key[6] = byte(id >> 8)
	key[7] = byte(id)
	if c, found := h.mdnsCache[string(key)]; found {
		if c.expiry.After(time.Now()) {
			if Debug {
				l := fastlog.NewLine(moduleMDNS, "found in mdns chache").MAC("mac", mac).Uint16("id", id)
				for _, v := range c.ipv4 {
					l.Struct(v)
				}
				for _, v := range c.ipv6 {
					l.Struct(v)
				}
				l.Write()
			}
			return c, true
		}
		delete(h.mdnsCache, string(key))
		if Debug {
			fastlog.NewLine(moduleMDNS, "delete from mdns chache").MAC("mac", mac).Uint16("id", id).Write()
		}
	}
	return cache{}, false
}

func (h *DNSHandler) putMDNSCache(mac net.HardwareAddr, id uint16, ipv4 []packet.IPNameEntry, ipv6 []packet.IPNameEntry) {
	if Debug {
		l := fastlog.NewLine(moduleMDNS, "add to mdns chache").MAC("mac", mac).Uint16("id", id)
		for _, v := range ipv4 {
			l.Struct(v)
		}
		for _, v := range ipv6 {
			l.Struct(v)
		}
		l.Write()
	}
	h.mutex.Lock()
	key := make([]byte, 6+2)
	copy(key, mac)
	key[6] = byte(id >> 8)
	key[7] = byte(id)
	h.mdnsCache[string(key)] = cache{id: id, ipv4: ipv4, ipv6: ipv6, expiry: time.Now().Add(time.Minute * 5)}
	h.mutex.Unlock()
}

// ProcesMDNS will process a multicast DNS packet.
// Note: host cannot be nil.
func (h *DNSHandler) ProcessMDNS(frame packet.Frame) (ipv4 []packet.IPNameEntry, ipv6 []packet.IPNameEntry, err error) {
	var p dnsmessage.Parser
	dnsHeader, err := p.Start(frame.Payload())
	if err != nil {
		return ipv4, ipv6, err
	}

	var addr packet.Addr
	if frame.Host != nil {
		addr = frame.Host.Addr
	}

	// if query, we can infer some information.
	if !dnsHeader.Response {
		var line *fastlog.Line
		if Debug {
			line = fastlog.NewLine(moduleMDNS, "query rcvd").Struct(addr).Struct(DNS(frame.Payload()))
		}
		if questions, err := p.AllQuestions(); err == nil {
			entry := packet.IPNameEntry{}
			entry.NameEntry.Type = moduleMDNS
			for _, q := range questions {
				name := string(q.Name.Data[:q.Name.Length])
				if Debug {
					line.String("qname", name)
				}
				// mdns query sends the name to validate it is unique
				// example: qname=Test-iPad.local.
				if !strings.HasSuffix(name, "_tcp.local.") && !strings.HasSuffix(name, "_udp.local.") && strings.HasSuffix(name, ".local.") {
					entry.NameEntry.Name = strings.TrimSuffix(name, ".local.")
				}
				if strings.Contains(name, "sleep-proxy") {
					entry.NameEntry.Manufacturer = "Apple"
					// Advertise that we are a SpeepProxy server
					// TODO: this is not working yet - September 2021
					// go h.SendSleepProxyResponse(h.session.NICInfo.HostAddr4, mdnsIPv4Addr, dnsHeader.ID, "sleepproxy")
				}
			}
			if entry.NameEntry.Name != "" || entry.NameEntry.Manufacturer != "" {
				ipv4 = append(ipv4, entry)
			}
		}
		if Debug {
			line.Write()
		}
		return ipv4, ipv6, nil
	}

	if Debug {
		fastlog.NewLine(moduleMDNS, "response rcvd").Struct(addr).Struct(DNS(frame.Payload())).Write()
	}

	if _, found := h.getMDNSCache(frame.SrcAddr.MAC, dnsHeader.ID); found {
		return nil, nil, nil
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

	model := ""
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
				// Model is saved in single ipv4 entry; copy to all IPv6 entries
				// before returning
				if model != "" {
					for i := range ipv4 {
						ipv4[i].NameEntry.Model = model
					}
					for i := range ipv6 {
						ipv6[i].NameEntry.Model = model
					}
				}

				// this is the last section; cache entry and return
				h.putMDNSCache(frame.SrcAddr.MAC, dnsHeader.ID, ipv4, ipv6)
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
			entry := packet.IPNameEntry{}
			entry.NameEntry.Type = moduleMDNS
			entry.NameEntry.Name = strings.TrimSuffix(hdr.Name.String(), ".local.")
			entry.Addr.MAC = packet.CopyMAC(frame.SrcAddr.MAC)
			entry.Addr.IP = packet.CopyIP(r.A[:])
			if Debug {
				fastlog.NewLine(moduleMDNS, "A resource").String("name", entry.NameEntry.Name).Struct(entry.Addr).Write()
			}
			ipv4 = append(ipv4, entry)

		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return ipv4, ipv6, err
			}
			entry := packet.IPNameEntry{}
			entry.NameEntry.Type = moduleMDNS
			entry.NameEntry.Name = strings.TrimSuffix(hdr.Name.String(), ".local.")
			entry.Addr.MAC = packet.CopyMAC(frame.SrcAddr.MAC)
			entry.Addr.IP = packet.CopyIP(r.AAAA[:])
			if Debug {
				fastlog.NewLine(moduleMDNS, "AAAA resource").String("name", entry.NameEntry.Name).Struct(entry.Addr).Write()
			}
			ipv6 = append(ipv6, entry)

		case dnsmessage.TypePTR:
			r, err := p.PTRResource()
			if err != nil {
				fastlog.NewLine(moduleMDNS, "invalid PTR resource").String("name", hdr.Name.String()).Error(err).Write()
				p.SkipAnswer()
				continue
			}
			if Debug {
				fastlog.NewLine(moduleMDNS, "PTR resource").String("name", hdr.Name.String()).String("ptr", r.PTR.String()).Write()
			}

		case dnsmessage.TypeSRV:
			// Service record :
			//    _service._proto.name. TTL class SRV priority weight port target
			// example:
			//	  dns.SRV name=sonosB8E9372ACF56._spotify-connect._tcp.local. target=sonosB8E9372ACF56.local. port=1400
			r, err := p.SRVResource()
			if err != nil {
				// Don't log if compressed error.
				// dnsmessage package does not allow compressed SRV name which is required in Multicast DNS.
				// This polutes the log with constant errors for each SRV.
				// https://github.com/golang/go/issues/24870
				if strings.Contains(err.Error(), "compressed name in SRV resource data") {
					if Debug {
						fastlog.NewLine(moduleMDNS, "ignore compressed name in SRV resource").String("name", hdr.Name.String()).String("message", err.Error()).Write()
					}
				} else {
					fastlog.NewLine(moduleMDNS, "invalid SRV resource").String("name", hdr.Name.String()).Error(err).Write()
				}
				p.SkipAnswer()
				continue
			}
			if Debug {
				fastlog.NewLine(moduleMDNS, "SRV resource").String("name", hdr.Name.String()).String("target", r.Target.String()).Uint16("port", r.Port).Write()
			}

		case dnsmessage.TypeTXT:
			r, err := p.TXTResource()
			if err != nil {
				fastlog.NewLine(moduleMDNS, "invalid TXT resource").String("name", hdr.Name.String()).Error(err).Write()
				p.SkipAnswer()
				continue
			}
			if m := parseTXT(r.TXT); m != "" {
				model = m
			}
			if Debug {
				fastlog.NewLine(moduleMDNS, "TXT resource").String("name", hdr.Name.String()).Sprintf("txt", r.TXT).String("model", model).Write()
			}

		case dnsmessage.TypeOPT:
			r, err := p.OPTResource()
			if err != nil {
				// fmt.Printf("mdns  : error invalid OPT resource name=%s error=[%s]\n", hdr.Name, err)
				fastlog.NewLine(moduleMDNS, "invalid OPT resource").String("name", hdr.Name.String()).Error(err).Write()
				p.SkipAnswer()
				continue
			}
			if Debug {
				// fmt.Printf("mdns  : OPT name=%s options=%v\n", hdr.Name, r.Options)
				fastlog.NewLine(moduleMDNS, "OPT resource").String("name", hdr.Name.String()).Sprintf("options", r.Options).Write()
			}
		case 47:
			if Debug {
				// fmt.Printf("mdns  : NSEC resource type not implemented %+v\n", hdr)
				fastlog.NewLine(moduleMDNS, "NSEC resource not implemented").String("name", hdr.Name.String()).Sprintf("hdr", hdr).Write()
			}
			p.SkipAnswer()

		default:
			// fmt.Printf("mdns  : error unexpected resource type %+v\n", hdr)
			fastlog.NewLine(moduleMDNS, "ignoring unexpected resource type").String("name", hdr.Name.String()).Sprintf("hdr", hdr).Write()
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
