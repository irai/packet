package dns

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/irai/packet"
)

// UPNP protocol description
// https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf

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

// unmarshalUPNPServiceDescriptor process a UPNP service description XML
//
// For a format and list of fields see section 2.3 service description
//    http://www.upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0.pdf
func unmarshalUPNPServiceDescriptor(b []byte) (v UPNPService, err error) {
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

func getUPNPServiceDescription(location string) ([]byte, error) {
	client := &http.Client{
		Timeout: time.Second * 3,
	}
	req, err := http.NewRequest("GET", location, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, packet.ErrNoReader
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (h *DNSHandler) UPNPServiceDiscovery(addr packet.Addr, location string) (name packet.NameEntry, err error) {

	desc, err := getUPNPServiceDescription(location)
	if err != nil {
		return packet.NameEntry{}, err
	}
	service, err := unmarshalUPNPServiceDescriptor(desc)
	if err != nil {
		return packet.NameEntry{}, err
	}
	if packet.Debug {
		fmt.Printf("engine: retrieved upnp name=%s model=%s manufacturer=%s\n", service.Device.Name, service.Device.Model, service.Device.Manufacturer)
	}

	name.Type = moduleSSDP
	name.Name = service.Device.Name
	name.Model = service.Device.Model
	name.Manufacturer = service.Device.Manufacturer
	name.Expire = time.Now().Add(time.Minute * 10) // cache this entry for a period
	return name, nil
}
