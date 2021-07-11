package engine

import (
	"fmt"

	"github.com/irai/packet"
	"github.com/irai/packet/dns"
)

type discoverAction struct {
	addr     packet.Addr
	location string
}

func (h *Handler) upnpServiceDiscovery(d discoverAction) (Notification, error) {
	host := h.session.FindIP(d.addr.IP)
	if host == nil {
		return Notification{}, packet.ErrInvalidIP
	}
	host.MACEntry.Row.RLock()
	if host.UPNPName != "" { // already have name
		host.MACEntry.Row.RUnlock()
		return Notification{}, nil
	}
	host.MACEntry.Row.RUnlock()

	desc, err := dns.GetUPNPServiceDescription(d.location)
	if err != nil {
		// fmt.Printf("engine: error in service discovery location=%s error=%s\n", d.location, err)
		return Notification{}, err
	}
	service, err := dns.UnmarshalSSDPService(desc)
	if err != nil {
		// fmt.Printf("engine: error in service discovery unmarshal location=%s error=%s\n", d.location, err)
		return Notification{}, err
	}
	if packet.Debug {
		fmt.Printf("engine: updated upnp name=%s model=%s manufacturer=%s\n", service.Device.Name, service.Device.Model, service.Device.Manufacturer)
	}
	host.MACEntry.Row.Lock()
	defer host.MACEntry.Row.Unlock()
	if host.UPNPName == service.Device.Name {
		return Notification{}, nil
	}

	host.UPNPName = service.Device.Name
	host.Model = service.Device.Model
	host.Manufacturer = service.Device.Manufacturer
	return Notification{Addr: host.Addr, Online: host.Online,
		UPNPName: host.UPNPName, DHCPName: host.DHCP4Name, MDNSName: host.MDNSName,
		Model: host.Model, Manufacturer: host.Manufacturer}, nil

}

func (h *Handler) SSDPSearchAll() error {
	return h.DNSHandler.SendSSDPSearch()
}

func (h *Handler) MDNSQueryAll() error {
	return h.DNSHandler.SendMDNSQuery(dns.MDNSServiceDiscovery)
}
