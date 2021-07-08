package dns

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"syscall"

	"github.com/irai/packet"
)

// SSDP
// Must be 239.255.255.250:1900. If the port number (“:1900”) is omitted,
// the receiver should assume the default SSDP port number of 1900.
var ssdpIPv4Addr = packet.Addr{MAC: packet.EthBroadcast, IP: net.IPv4(239, 255, 255, 250), Port: 1900}

func ProcessSSDP(host *packet.Host, ether packet.Ether, payload []byte) (location string, err error) {

	/*
				// Add newline to workaround buggy SSDP responses
		var endOfHeader = []byte{'\r', '\n', '\r', '\n'}
				if !bytes.HasSuffix(payload, endOfHeader) {
					raw = bytes.Join([][]byte{raw, endOfHeader}, nil)
				}
	*/

	if bytes.HasPrefix(payload, []byte("M-SEARCH ")) {
		handleSearch(payload)
		return location, nil
	}
	if bytes.HasPrefix(payload, []byte("NOTIFY ")) {
		return handleNotify(payload)
	}
	return location, packet.ErrParseFrame
}

// handleNotify process notify ssdp messages
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
func handleNotify(raw []byte) (location string, err error) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return location, err
	}

	fmt.Printf("TRACE: ssdp frame %+v\n", req)

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
			return location, packet.ErrParseFrame
		}
		location = req.Header.Get("LOCATION")
		return location, nil
	case "ssdp:byebye":
		// When a device is about to be removed from the network, it should explicitly revoke its discovery messages by sending one
		// multicast request for each ssdp:alive message it sent. Each multicast request must have method NOTIFY and ssdp:byebye in the
		// NTS header in the following format.
		//    NOTIFY * HTTP/1.1
		//    HOST: 239.255.255.250:1900
		//    NT: search target
		//    NTS: ssdp:byebye
		//    USN: uuid:advertisement UUID
		fmt.Printf("ssdp  : byebye %s", raw)
	default:
		fmt.Printf("ssdp  : error invalid NTS header %s\n", nts)
		return location, packet.ErrParseFrame
	}
	return location, nil
}

func handleSearch(raw []byte) error {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return err
	}
	man := req.Header.Get("MAN")
	if man != `"ssdp:discover"` {
		return fmt.Errorf("unexpected MAN: %s", man)
	}
	fmt.Printf("ssdp  : discover %s", raw)
	return nil
}

// When a control point is added to the network, it should send a multicast request with method M-SEARCH in the following format.
//  M-SEARCH * HTTP/1.1
//  HOST: 239.255.255.250:1900
//  MAN: "ssdp:discover"
//  MX: seconds to delay response
//  ST: "ssdp:all"
func (h *DNSHandler) SendSSDPSearch() (err error) {
	buf := []byte(`
M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
MAN: "ssdp:discover"
MX: 3
ST: "ssdp:all"

`)
	ether := packet.Ether(make([]byte, packet.EthMaxSize))
	ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_IP, h.session.NICInfo.HostMAC, ssdpIPv4Addr.MAC)
	ip4 := packet.IP4MarshalBinary(ether.Payload(), 255, h.session.NICInfo.HostIP4.IP, ssdpIPv4Addr.IP)
	udp := packet.UDPMarshalBinary(ip4.Payload(), 1900, 1900)
	if udp, err = udp.AppendPayload(buf); err != nil {
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

// example XML
// <root xmlns="urn:schemas-upnp-org:device-1-0">
//   <specVersion>
//     <major>1</major>
//     <minor>0</minor>
//   </specVersion>
//   <device>
//     <friendlyName>192.168.0.103 - Sonos Play:1</friendlyName>
//     <manufacturer>Sonos, Inc.</manufacturer>
//     <modelNumber>S1</modelNumber>
//     <modelDescription>Sonos Play:1</modelDescription>
//     <modelName>Sonos Play:1</modelName>
type UPNPDevice struct {
	Name             string `xml:"friendlyName"`
	Model            string `xml:"modelName"`
	ModelNumber      string `xml:"modelNumber"`
	ModelDescription string `xml:"modelDescription"`
	Manufacturer     string `xml:"manufacturer"`
}
type UPNPService struct {
	XMLName xml.Name   `xml:"root"`
	Device  UPNPDevice `xml:"device"`
}

// UnmarshalSSDPService process a UPNP service description XML
//
// For a format and list of fields see section 2.3 service description
//    http://www.upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0.pdf
func UnmarshalSSDPService(b []byte) (v UPNPService, err error) {
	v = UPNPService{}
	if err := xml.Unmarshal(b, &v); err != nil {
		fmt.Printf("ssdp: error unmarshal message %v [%+x]", err, b)
		return v, err
	}
	if Debug {
		fmt.Printf("ssdp  : upnp service description name=%s model=%s manufacturer=%s mnumber=%s description=%s\n",
			v.Device.Name, v.Device.Model, v.Device.Manufacturer, v.Device.ModelNumber, v.Device.ModelDescription)
	}
	return v, nil
}
