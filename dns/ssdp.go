package dns

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strings"
	"syscall"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
)

const moduleSSDP = "ssdp"

// SSDP draft here
// see : https://datatracker.ietf.org/doc/html/draft-cai-ssdp-v1-03
//
// Must be 239.255.255.250:1900. If the port number (“:1900”) is omitted,
// the receiver should assume the default SSDP port number of 1900.
var ssdpIPv4Addr = packet.Addr{MAC: packet.EthBroadcast, IP: net.IPv4(239, 255, 255, 250), Port: 1900}

// Web Discovery Protocol - WSD
var wsd4IPv4Addr = packet.Addr{MAC: packet.EthBroadcast, IP: net.IPv4(239, 255, 255, 250), Port: 3702}

// processSSDPNotify process notify ssdp messages
//
// When a device is added to the network, it multicasts discovery messages to advertise its root device, any embedded devices, and
// any services. Each discovery message contains four major components:
// 1. a potential search target (e.g., device type), sent in an NT (Notification Type) header,
// 2. a composite identifier for the advertisement, sent in a USN (Unique Service Name) header,
// 3. a URL for more information about the device (or enclosing device in the case of a service), sent in a LOCATION header,
// 4. a duration for which the advertisement is valid, sent in a CACHE-CONTROL header.
//
//
// see upnp spec: http://www.upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0.pdf
func processSSDPNotify(raw []byte) (name packet.NameEntry, location string, err error) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return packet.NameEntry{}, location, err
	}

	switch nts := req.Header.Get("NTS"); nts {
	case "ssdp:alive":
		// When a device is added to the network, it must send a multicast request with
		// method NOTIFY and ssdp:alive in the NTS header in the following format
		//    NOTIFY * HTTP/1.1
		//    HOST: 239.255.255.250:1900
		//    CACHE-CONTROL: max-age = seconds until advertisement expires
		//    LOCATION: URL for UPnP description for root device
		//    NT: search target
		//    NTS: ssdp:alive
		//    SERVER: OS/version UPnP/1.0 product/version
		//    USN: advertisement UUID
		if req.Method != "NOTIFY" {
			return packet.NameEntry{}, location, packet.ErrParseFrame
		}
		location = req.Header.Get("LOCATION")
		if Debug {
			fastlog.NewLine(moduleSSDP, "ssdp:alive recv").String("location", location).Write()
		}
		return packet.NameEntry{}, location, nil
	case "ssdp:byebye":
		// When a device is about to be removed from the network, it should explicitly revoke its discovery messages by sending one
		// multicast request for each ssdp:alive message it sent. Each multicast request must have method NOTIFY and ssdp:byebye in the
		// NTS header in the following format.
		//    NOTIFY * HTTP/1.1
		//    HOST: 239.255.255.250:1900
		//    NT: search target
		//    NTS: ssdp:byebye
		//    USN: uuid:advertisement UUID
		if Debug {
			// fmt.Printf("ssdp  : byebye %s", string(raw))
			fastlog.NewLine(moduleSSDP, "ssdp:byebye recv").Bytes("txt", raw).Write()
		}
	default:
		fmt.Printf("ssdp  : error unexpected NTS header %s\n", nts)
		return packet.NameEntry{}, location, packet.ErrParseFrame
	}
	return packet.NameEntry{}, location, nil
}

// processSSDPSearchRequest process M-SEARCH SSDP packet
//
// TODO: identify system from Chrome
// By default, Google Chrome sends SSDP network broadcast traffic on the LAN.
// Chrome then appends a USERAGENT: field and we can use this to identify the OS.
//
// Examples:
//   USER-AGENT: Chromium/74.0.3729.131 Linux
//   USER-AGENT: Microsoft Edge/91.0.864.64 Windows
//   USER-AGENT: Google Chrome/92.0.4515.107 Windows
//   USER-AGENT: My App/4 (iPhone; iOS 12.4) CocoaSSDP/0.1.0/1
//
// According to section 1.3.2 of the UPnP Device Architecture 1.1 the value should have the following syntax:
//   USER-AGENT: OS/version UPnP/1.1 product/version
// but clearly not many follow this format.
func processSSDPSearchRequest(raw []byte) (name packet.NameEntry, location string, err error) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return packet.NameEntry{}, "", err
	}
	man := req.Header.Get("MAN")
	if man != `"ssdp:discover"` {
		return packet.NameEntry{}, "", packet.ErrParseFrame
	}
	// fmt.Printf("ssdp  : recv discover packet %s", string(raw))
	ua := req.Header.Get("USER-AGENT")
	name = processUserAgent(ua)
	if Debug {
		fastlog.NewLine(moduleSSDP, "ssdp:discover recv").String("user-agent", ua).Struct(name).Write()
	}
	return name, "", nil
}

func processUserAgent(ua string) (name packet.NameEntry) {
	name.Type = moduleSSDP
	switch {
	case strings.Contains(ua, "iPhone"):
		name.Model = "iPhone"
		name.Manufacturer = "Apple"
	case strings.Contains(ua, "iPad"):
		name.Model = "iPad"
		name.Manufacturer = "Apple"
	}
	switch {
	case strings.Contains(ua, "Windows"):
		name.OS = "Windows"
	case strings.Contains(ua, "Linux"):
		name.OS = "Linux"
	case strings.Contains(ua, "iOS"):
		name.OS = "iOS"
	}
	return name
}

// processSSDPResponse process a M-SEARCH http response
func processSSDPResponse(raw []byte) (name packet.NameEntry, location string, err error) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		return packet.NameEntry{}, location, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return packet.NameEntry{}, "", packet.ErrParseFrame
	}
	location = resp.Header.Get("LOCATION")
	if Debug {
		fastlog.NewLine(moduleSSDP, "response").String("location", location).Write()
	}
	return packet.NameEntry{}, location, nil
}

// When a control point is added to the network, it should send a multicast request with method M-SEARCH in the following format.
//  M-SEARCH * HTTP/1.1
//  HOST: 239.255.255.250:1900
//  MAN: "ssdp:discover"
//  MX: seconds to delay response
//  ST: "ssdp:all"
var mSearchString = append([]byte(`
M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
MAN: "ssdp:discover"
MX: 1
ST: "ssdp:all"`), []byte{0x0d, 0x0a, 0x0d, 0x0a}...) // must have 0d0a,0d0a at the end

//SendSSDPSearch transmit a multicast SSDP M-SEARCH discovery packet
func (h *DNSHandler) SendSSDPSearch() (err error) {
	ether := packet.Ether(make([]byte, packet.EthMaxSize))
	ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_IP, h.session.NICInfo.HostMAC, ssdpIPv4Addr.MAC)
	ip4 := packet.IP4MarshalBinary(ether.Payload(), 255, h.session.NICInfo.HostIP4.IP, ssdpIPv4Addr.IP)
	udp := packet.UDPMarshalBinary(ip4.Payload(), 1900, 1900)
	if udp, err = udp.AppendPayload(mSearchString); err != nil {
		return err
	}
	ip4 = ip4.SetPayload(udp, syscall.IPPROTO_UDP)
	if ether, err = ether.SetPayload(ip4); err != nil {
		return err
	}
	if _, err := h.session.Conn.WriteTo(ether, &ssdpIPv4Addr); err != nil {
		fmt.Printf("mdns  : error failed to write %s\n", err)
	}
	return err
}

func (h *DNSHandler) ProcessSSDP(host *packet.Host, ether packet.Ether, payload []byte) (name packet.NameEntry, location string, err error) {

	// TODO: test ssdp packet without endline
	/*
				// Add newline to workaround buggy SSDP responses
		var endOfHeader = []byte{'\r', '\n', '\r', '\n'}
				if !bytes.HasSuffix(payload, endOfHeader) {
					raw = bytes.Join([][]byte{raw, endOfHeader}, nil)
				}
	*/

	if bytes.HasPrefix(payload, []byte("M-SEARCH ")) {
		if Debug {
			fastlog.NewLine(moduleSSDP, "m-search rcvd").MAC("mac", ether.Src()).IP("ip", ether.SrcIP()).Write()
		}
		return processSSDPSearchRequest(payload)
	}
	if bytes.HasPrefix(payload, []byte("NOTIFY ")) {
		if Debug {
			fastlog.NewLine(moduleSSDP, "notify rcvd").MAC("mac", ether.Src()).IP("ip", ether.SrcIP()).Write()
		}
		return processSSDPNotify(payload)
	}
	if Debug {
		fastlog.NewLine(moduleSSDP, "response rcvd").MAC("mac", ether.Src()).IP("ip", ether.SrcIP()).Write()
	}
	return processSSDPResponse(payload)
}
