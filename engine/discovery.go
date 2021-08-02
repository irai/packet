package engine

import (
	"github.com/irai/packet/dns"
)

func (h *Handler) SSDPSearchAll() error {
	return h.DNSHandler.SendSSDPSearch()
}

func (h *Handler) MDNSQueryAll() error {
	return h.DNSHandler.SendMDNSQuery(dns.MDNSServiceDiscovery)
}

func (h *Handler) NBNSNodeStatus() error {
	return h.DNSHandler.SendNBNSNodeStatus()
}
