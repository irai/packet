package engine

import (
	"fmt"

	"github.com/irai/packet"
	"github.com/irai/packet/dns"
)

type discoverAction struct {
	action   string
	addr     packet.Addr
	location string
}

func (h *Handler) upnpServiceDiscovery(d discoverAction) error {
	host := h.session.FindIP(d.addr.IP)
	if host == nil {
		return packet.ErrInvalidIP
	}
	host.MACEntry.Row.RLock()
	if host.UPNPName != "" { // already have name
		host.MACEntry.Row.RUnlock()
		return nil
	}
	host.MACEntry.Row.RUnlock()
	desc, err := dns.GetUPNPServiceDescription(d.location)
	if err != nil {
		// fmt.Printf("engine: error in service discovery location=%s error=%s\n", d.location, err)
		return err
	}
	service, err := dns.UnmarshalSSDPService(desc)
	if err != nil {
		// fmt.Printf("engine: error in service discovery unmarshal location=%s error=%s\n", d.location, err)
		return err
	}
	host.MACEntry.Row.Lock()
	host.UPNPName = service.Device.Name
	if host.Model == "" {
		host.Model = service.Device.Model
	}
	if host.Manufacturer == "" {
		host.Manufacturer = service.Device.Manufacturer
	}
	host.MACEntry.Row.Unlock()
	if packet.Debug {
		fmt.Printf("engine: updated upnp name=%s model=%s manufacturer=%s\n", service.Device.Name, service.Device.Model, service.Device.Manufacturer)
	}
	return nil

}
