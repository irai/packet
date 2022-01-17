package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
)

func (h *Handler) processPacket(ether packet.Ether) (err error) {
	var d1, d2, d3 time.Duration

	startTime := time.Now()

	frame, err := h.session.Parse(ether)
	if err != nil {
		return err
	}
	d1 = time.Since(startTime)

	switch frame.PayloadID {
	case packet.PayloadTCP: // most common traffic on a LAN
		// do nothing
	case packet.PayloadUDP:
		// do nothing
	case packet.PayloadIP4, packet.PayloadIP6:
		// do nothing
	case packet.PayloadSSL:
		// do nothing
	case packet.Payload8023:
		packet.Process8023Frame(frame, 14)
		return nil

	case packet.PayloadARP:
		if err = h.ARPHandler.ProcessPacket(frame); err != nil {
			return err
		}

	case packet.PayloadDHCP4:
		if err = h.DHCP4Handler.ProcessPacket(frame); err != nil {
			fmt.Printf("packet: error processing dhcp4: %s\n", err)
			return err
		}

	case packet.PayloadICMP4:
		if err = h.ICMP4Handler.ProcessPacket(frame); err != nil {
			fastlog.NewLine("packet", "error processing icmp4").Error(err).Write()
			return err
		}

	case packet.PayloadICMP6:
		if err = h.ICMP6Handler.ProcessPacket(frame); err != nil {
			fastlog.NewLine("packet", "error processing icmp6").Error(err).Write()
			return err
		}

	case packet.PayloadSSDP:
		if err = h.ProcessSSDP(frame); err != nil {
			return err
		}

	case packet.PayloadMDNS:
		if err = h.ProcessMDNS(frame); err != nil {
			return err
		}

	case packet.PayloadNBNS:
		if err = h.ProcessNBNS(frame); err != nil {
			return err
		}

	case packet.PayloadDHCP6:
		fastlog.NewLine("ether", "dhcp6 packet").Struct(frame.Ether()).LF().Module("udp", "dhcp6 packet").Struct(frame.UDP()).Write()
		fastlog.NewLine("packet", "ignore dhcp6 packet").ByteArray("payload", frame.UDP().Payload()).Write()

	case packet.PayloadWSDP:
		if packet.Debug {
			fastlog.NewLine(module, "ether").Struct(frame.Ether()).Struct(frame.Host).Write()
		}
		fastlog.NewLine(module, "wsd frame").String("payload", string(frame.Payload())).Write()

	case packet.PayloadDNS:
		dnsEntry, err := h.DNSHandler.ProcessDNS(nil, frame.Ether(), frame.Payload())
		if err != nil {
			fmt.Printf("packet: error processing dns: %s\n", err)
			return err
		}
		if dnsEntry.Name != "" {
			h.sendDNSNotification(dnsEntry)
		}

	case packet.PayloadLLMNR:
		if err = h.ProcessLLMNR(frame); err != nil {
			return err
		}

	case packet.PayloadNTP: // Network time synchonization protocol
		// do nothing
		fastlog.NewLine(module, "NTP frame").Struct(frame.Ether()).Write()

	case packet.PayloadPlex:
		// Plex application multicast on these ports to find players.
		// G'Day Mate (GDM) multicast packets
		// https://github.com/NineWorlds/serenity-android/wiki/Good-Day-Mate
		fastlog.NewLine(module, "plex frame").Struct(frame.Ether()).IP("srcip", frame.Ether().SrcIP()).IP("dstip", frame.Ether().DstIP()).ByteArray("payload", frame.Payload()).Write()

	case packet.PayloadUbiquiti:
		// Ubiquiti device discovery protocol
		// https://help.ui.com/hc/en-us/articles/204976244-EdgeRouter-Ubiquiti-Device-Discovery
		fastlog.NewLine("proto", "ubiquiti device discovery").Struct(frame.Ether()).IP("srcip", frame.Ether().SrcIP()).IP("dstip", frame.Ether().DstIP()).ByteArray("payload", frame.Ether().Payload()).Write()

	case packet.PayloadIGMP:
		// Internet Group Management Protocol - Ipv4 multicast groups
		// do nothing
		fastlog.NewLine("packet", "ipv4 igmp packet").Struct(frame.Ether()).Write()

	case packet.PayloadEthernetPause:
		if err := ProcessEthernetPause(frame); err != nil {
			return err
		}
	case packet.PayloadRRCP:
		if err := ProcessRRCP(frame); err != nil {
			return err
		}
	case packet.Payload802_11r:
		if err := Process802_11r(frame); err != nil {
			return err
		}
	case packet.PayloadIEEE1905:
		if err := ProcessIEEE1905(frame); err != nil {
			return err
		}
	case packet.PayloadSonos:
		if err := ProcessSonos(frame); err != nil {
			return err
		}
	case packet.Payload880a:
		if err := Process880a(frame); err != nil {
			return err
		}
	default:
		fastlog.NewLine(module, "protocol unknown").Struct(frame.Ether()).Int("proto", int(frame.PayloadID)).Write()
	}
	d2 = time.Since(startTime)

	if frame.Host != nil {
		h.session.Notify(frame)
	}
	d3 = time.Since(startTime)

	if d3 > time.Microsecond*600 {
		fastlog.NewLine("packet", "warning > 600 microseconds").String("l3", d1.String()).String("l4", d2.String()).String("total", d3.String()).
			Int("l4proto", int(frame.PayloadID)).Uint16Hex("ethertype", ether.EtherType()).Write()
	}
	return nil
}

func processInvalid(frame packet.Frame, pos int) error {
	fastlog.NewLine(module, "unexpected ethernet type").Struct(frame.Ether()).ByteArray("payload", frame.Payload()).Write()
	return nil
}

func (h *Handler) ProcessMDNS(frame packet.Frame) (err error) {
	// case udpSrcPort == 5353 || udpDstPort == 5353: // Multicast DNS (MDNS)
	ipv4Hosts, ipv6Hosts, err := h.DNSHandler.ProcessMDNS(frame)
	if err != nil {
		fmt.Printf("packet: error processing mdns: %s\n", err)
		return err
	}
	if len(ipv4Hosts) > 0 {
		if frame.Host != nil {
			frame.Host.UpdateMDNSName(ipv4Hosts[0].NameEntry)
		}
	}

	for _, v := range ipv6Hosts {
		fastlog.NewLine(module, "mdns ipv6 ignoring host").Struct(v).Write()
	}
	return nil
}

func (h *Handler) ProcessLLMNR(frame packet.Frame) (err error) {
	// case udpSrcPort == 5355 || udpDstPort == 5355:
	// Link Local Multicast Name Resolution (LLMNR)
	fastlog.NewLine(module, "ether").Struct(frame.Ether()).Module(module, "received llmnr packet").Write()
	ipv4Hosts, ipv6Hosts, err := h.DNSHandler.ProcessMDNS(frame)
	if err != nil {
		fmt.Printf("packet: error processing llmnr: %s\n", err)
		return err
	}
	if frame.Host != nil {
		if len(ipv4Hosts) > 0 {
			frame.Host.UpdateLLMNRName(ipv4Hosts[0].NameEntry)
		}
		for _, v := range ipv6Hosts {
			fastlog.NewLine(module, "mdns ipv6 ignoring host").Struct(v).Write()
		}
	}
	return nil
}

func (h *Handler) ProcessSSDP(frame packet.Frame) (err error) {
	// case udpDstPort == 1900:
	// Microsoft Simple Service Discovery Protocol
	nameEntry, location, err := h.DNSHandler.ProcessSSDP(frame.Host, frame.Ether(), frame.Payload())
	if err != nil {
		fastlog.NewLine(module, "error processing ssdp").Error(err).ByteArray("payload", frame.Payload()).Write()
		return err
	}

	if frame.Host != nil {
		frame.Host.UpdateSSDPName(nameEntry)

		// Retrieve service details if valid location
		// Location is the end point for the UPNP service discovery
		// Retrieve in a goroutine
		if location != "" {
			go func(host *packet.Host) {
				host.MACEntry.Row.RLock()
				if host.SSDPName.Expire.After(time.Now()) { // ignore if cache is valid
					host.MACEntry.Row.RUnlock()
					return
				}
				host.MACEntry.Row.RUnlock()
				nameEntry, err := h.DNSHandler.UPNPServiceDiscovery(host.Addr, location)
				if err != nil {
					fastlog.NewLine("engine", "error retrieving UPNP service discovery").String("location", location).Error(err).Write()
					return
				}
				var notify bool
				host.MACEntry.Row.Lock()
				host.SSDPName, notify = host.SSDPName.Merge(nameEntry)
				if notify {
					fastlog.NewLine(module, "updated ssdp name").Struct(host.Addr).Struct(host.SSDPName).Write()
					host.MACEntry.SSDPName, _ = host.MACEntry.SSDPName.Merge(host.SSDPName)
				}
				host.MACEntry.Row.Unlock()
				if notify {
					h.session.Notify(frame)
				}
			}(frame.Host)
			return nil
		}
	}
	return nil
}

func (h *Handler) ProcessNBNS(frame packet.Frame) (err error) {
	// case udpDstPort == 137 || udpDstPort == 138:
	// Netbions NBNS
	entry, err := h.DNSHandler.ProcessNBNS(frame.Host, frame.Ether(), frame.Payload())
	if err != nil {
		// don't log as error if dns parsing cannot handle nbns reserved keyword.
		// error: "skipping Question Name: segment prefix is reserved"
		// TODO: fix nbns parsing
		if strings.Contains(err.Error(), "prefix is reserved") {
			fastlog.NewLine(module, "nbns prefix is reserved - fixme").ByteArray("frame", frame.Ether()).Write()
			return err
		}
		fastlog.NewLine(module, "error processing nbns").Error(err).Write()
		return err
	}
	if entry.Name != "" {
		frame.Host.UpdateNBNSName(entry)
	}
	return nil
}

func ProcessEthernetPause(frame packet.Frame) error {
	// 0x8808:  Ethernet flow control - Pause frame
	// An overwhelmed network node can send a pause frame, which halts the transmission of the sender for a specified period of time.
	// EtherType 0x8808 is used to carry the pause command, with the Control opcode set to 0x0001 (hexadecimal).
	// When a station wishes to pause the other end of a link, it sends a pause frame to either the unique
	// 48-bit destination address of this link or to the 48-bit reserved multicast address of 01-80-C2-00-00-01.
	// A likely scenario is network congestion within a switch.
	p := packet.EthernetPause(frame.Payload())
	if err := p.IsValid(); err != nil {
		fastlog.NewLine(module, "invalid Ethernet pause frame").Error(err).Write()
		return err
	}
	fastlog.NewLine(module, "ethernet flow control frame").Struct(p).Write()
	return nil
}

func ProcessRRCP(frame packet.Frame) error {
	// case 0x8899: // Realtek Remote Control Protocol (RRCP)
	// proprietary protocol with scarce information available.
	// A common packet is the loop detection packet (proprietary protocol 0x23).
	p := packet.RRCP(frame.Payload())
	if err := p.IsValid(); err != nil {
		fastlog.NewLine(module, "invalid RRCP frame").Error(err).ByteArray("frame", frame.Payload()).Write()
		return err
	}
	fastlog.NewLine(module, "RRCP frame").Struct(frame.Ether()).ByteArray("payload", p).Write()
	return nil
}

func ProcessLLDP(frame packet.Frame) error {
	// case 0x88cc: // Link Layer Discovery Protocol (LLDP)
	p := packet.LLDP(frame.Payload())
	if err := p.IsValid(); err != nil {
		fastlog.NewLine(module, "invalid LLDP frame").Error(err).ByteArray("frame", p).Write()
		return err
	}
	fastlog.NewLine(module, "LLDP frame").Struct(frame.Ether()).Struct(p).Write()
	return nil
}

func Process802_11r(frame packet.Frame) error {
	// case 0x890d: // Fast Roaming Remote Request (802.11r)
	// Fast roaming, also known as IEEE 802.11r or Fast BSS Transition (FT),
	// allows a client device to roam quickly in environments implementing WPA2 Enterprise security,
	// by ensuring that the client device does not need to re-authenticate to the RADIUS server
	// every time it roams from one access point to another.
	// fmt.Printf("packet: 802.11r Fast Roaming frame %s payload=[% x]\n", ether, ether[:])
	fastlog.NewLine(module, "802.11r Fast Roaming frame").Struct(frame.Ether()).ByteArray("payload", frame.Payload()).Write()
	return nil
}

func ProcessIEEE1905(frame packet.Frame) error {
	// case 0x893a: // IEEE 1905.1 - network enabler for home networking
	// Enables topology discovery, link metrics, forwarding rules, AP auto configuration
	// TODO: investigate how to use IEEE 1905.1
	// See:
	// https://grouper.ieee.org/groups/802/1/files/public/docs2012/802-1-phkl-P1095-Tech-Presentation-1207-v01.pdf
	p := packet.IEEE1905(frame.Payload())
	if err := p.IsValid(); err != nil {
		fastlog.NewLine(module, "invalid IEEE 1905 frame").Error(err).ByteArray("frame", p).Write()
		return err
	}
	fastlog.NewLine(module, "IEEE 1905.1 frame").Struct(frame.Ether()).Struct(p).Write()
	return nil
}

func ProcessSonos(frame packet.Frame) error {
	// case 0x6970: // Sonos Data Routing Optimisation
	// References to type EthType 0x6970 appear in a Sonos patent
	// https://portal.unifiedpatents.com/patents/patent/US-20160006778-A1
	fastlog.NewLine(module, "Sonos data routing frame").Struct(frame.Ether()).ByteArray("payload", frame.Payload()).Write()
	return nil
}

func Process880a(frame packet.Frame) error {
	// case 0x880a: // Unknown protocol - but commonly seen in logs
	count := frame.Session.Statistics[packet.Payload880a].Count - 1
	if (count % 32) == 0 {
		fastlog.NewLine(module, "unknown 0x880a frame").Int("count", count).ByteArray("payload", frame.Payload()).Write()
	}
	return nil
}
