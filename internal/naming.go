package internal

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/irai/packet"
	"gopkg.in/yaml.v2"
)

// NameEntry holds a name entry
type NameEntry struct {
	MAC         net.HardwareAddr
	Vendor      string
	DHCPName    string
	MDNSName    string
	NBNSName    string
	OSName      string
	GenericName string
	Model       string
}

func (e NameEntry) String() string {
	return fmt.Sprintf("mac=%s dhcp=%s mdns=%s vendor=%s nbns=%s generic=%s\n", e.MAC, e.DHCPName, e.MDNSName, e.Vendor, e.NBNSName, e.GenericName)
}

// NameHandler manages the naming table in memory and on disk.
type NameHandler struct {
	filename  string
	nameTable []NameEntry
}

// NewNameHandler create a new NameHandler to manage the naming table
func NewNameHandler(filename string) *NameHandler {
	handler := &NameHandler{nameTable: make([]NameEntry, 0, 64), filename: filename}
	if filename != "" {
		source, _ := ioutil.ReadFile(handler.filename)
		handler.loadNames(source)
	}
	return handler
}

// PrintTable utility function to print the name table
func (h *NameHandler) PrintTable() {
	for _, v := range h.nameTable {
		fmt.Printf("packet: name %s\n", v)
	}
}

/**
func (h *NameHandler) FindName(name string) net.HardwareAddr {
	for i := range h.nameTable {
		if h.nameTable[i].Name == name {
			return h.nameTable[i].MAC
		}
		if h.nameTable[i].DHCPName == name {
			return h.nameTable[i].MAC
		}
		if h.nameTable[i].MDNSName == name {
			return h.nameTable[i].MAC
		}
		if h.nameTable[i].NBNSName == name {
			return h.nameTable[i].MAC
		}
	}
	return nil
}
*/

func (h *NameHandler) findOrCreateIndex(mac net.HardwareAddr) (index int, found bool, err error) {
	if mac == nil || bytes.Equal(mac, net.HardwareAddr{}) {
		return 0, false, packet.ErrInvalidMAC
	}
	if i, found := h.findIndex(mac); found {
		return i, true, nil
	}

	entry := NameEntry{MAC: mac}
	h.nameTable = append(h.nameTable, entry)
	if packet.Debug {
		fmt.Printf("packet:  mac=%s new entry", mac)
		h.PrintTable()
	}
	return len(h.nameTable) - 1, found, nil
}

func (h *NameHandler) FindMAC(mac net.HardwareAddr) NameEntry {
	if i, found := h.findIndex(mac); found {
		return h.nameTable[i]
	}
	return NameEntry{}
}

func (h *NameHandler) findIndex(mac net.HardwareAddr) (index int, found bool) {
	for i := range h.nameTable {
		if bytes.Equal(h.nameTable[i].MAC, mac) {
			return i, true
		}
	}
	return 0, false
}

// setDHCPName set the dhcp name
func (h *NameHandler) SetDHCPName(mac net.HardwareAddr, name string) (NameEntry, error) {
	i, _, err := h.findOrCreateIndex(mac)
	if err != nil {
		return NameEntry{}, err
	}
	if h.nameTable[i].DHCPName == name || name == "" {
		return h.nameTable[i], nil
	}
	h.nameTable[i].DHCPName = name
	if packet.Debug {
		fmt.Printf("packet: naming updated dhcp %s\n", h.nameTable[i])
	}
	return h.nameTable[i], h.save()
}

// setMDNSName set the MDNS name
func (h *NameHandler) SetMDNSName(mac net.HardwareAddr, name string, model string) (NameEntry, error) {
	i, _, err := h.findOrCreateIndex(mac)
	if err != nil {
		return NameEntry{}, err
	}
	if h.nameTable[i].Model == model && h.nameTable[i].MDNSName == name {
		return h.nameTable[i], nil
	}
	// MDNS model is descriptive and overide others
	h.nameTable[i].MDNSName = name
	h.nameTable[i].Model = model

	if packet.Debug {
		fmt.Printf("packet: naming updated mdns %s\n", h.nameTable[i])
	}
	return h.nameTable[i], h.save()
}

// QueryNBNSName send a network query to retrieve nbns name
func (h *NameHandler) QueryNBNSName(ip net.IP) {
	fmt.Printf("queryNBNSName not implemented")
	// if config.C != nil && config.C.NBNSHandler != nil {
	// config.C.NBNSHandler.SendQuery(ip)
	// }
}

// SetNBNSName set the NBNS name
func (h *NameHandler) SetNBNSName(mac net.HardwareAddr, name string) (NameEntry, error) {
	i, _, err := h.findOrCreateIndex(mac)
	if err != nil {
		return NameEntry{}, err
	}
	if h.nameTable[i].NBNSName == name || name == "" {
		return h.nameTable[i], nil
	}
	h.nameTable[i].NBNSName = name
	if packet.Debug {
		fmt.Printf("packet: naming updated nbns %s\n", h.nameTable[i])
	}
	return h.nameTable[i], h.save()
}

// setGenericName set a generic name
func (h *NameHandler) SetGenericName(mac net.HardwareAddr, name string) (NameEntry, error) {
	i, _, err := h.findOrCreateIndex(mac)
	if err != nil {
		return NameEntry{}, err
	}
	if h.nameTable[i].GenericName == name || name == "" {
		return h.nameTable[i], nil
	}
	h.nameTable[i].GenericName = name
	if packet.Debug {
		fmt.Printf("packet: naming updated generic %s\n", h.nameTable[i])
	}
	return h.nameTable[i], h.save()
}

func (h *NameHandler) SetVendorName(mac net.HardwareAddr, vendor string) (NameEntry, error) {
	i, _, err := h.findOrCreateIndex(mac)
	if err != nil {
		return NameEntry{}, err
	}
	if h.nameTable[i].Vendor == vendor || vendor == "" {
		return h.nameTable[i], nil
	}
	h.nameTable[i].Vendor = vendor
	if packet.Debug {
		fmt.Printf("packet: naming updated vendor %s\n", h.nameTable[i])
	}
	return h.nameTable[i], h.save()
}

// LookupMACVendor send REST request to retrieve the mac manufacturar
// Set retry to -1 to disable call
func (h *NameHandler) LookupMACVendor(mac net.HardwareAddr, retry int) (string, error) {
	if retry <= 0 || retry > 10 {
		fmt.Printf("packet: naming lookup disabled mac=%s\n", mac)
		return "", nil
	}
	if mac == nil || bytes.Equal(mac, net.HardwareAddr{}) {
		return "", packet.ErrInvalidMAC
	}

	aurl := fmt.Sprintf("http://api.macvendors.com/%s", mac.String())
	for i := 0; i < retry; i++ {
		resp, err := get(aurl)
		if err != nil {
			fmt.Printf("packet: error lookup vendor name resp=%+v error=\"%s\"\n", resp, err)
			return "", err
		}
		defer resp.Body.Close()

		// API rate limite - retry
		switch {
		case resp.StatusCode == 429:
			time.Sleep(time.Second)
			continue
		case resp.StatusCode != http.StatusOK:
			fmt.Printf("packet: error lookup vendor name resp=%+v\n", resp)
			return "", packet.ErrNoReader
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		vendor := strings.TrimSpace(string(body))
		if packet.Debug {
			fmt.Printf("packet: naming mac=% vendor=%s", mac, vendor)
		}
		return vendor, nil
	}
	fmt.Printf("packet: error naming exceeded retry attempts to get vendor mac=%s\n", mac)
	return "", packet.ErrNotFound
}

func get(aurl string) (resp *http.Response, err error) {
	client := &http.Client{
		Timeout: time.Second * 20,
	}
	req, _ := http.NewRequest("GET", aurl, nil)
	resp, err = client.Do(req)
	return resp, err
}

// LoadNames load config from file
func (h *NameHandler) loadNames(source []byte) (err error) {
	newTable := make([]NameEntry, 0, 256)
	if err = yaml.Unmarshal(source, &newTable); err != nil {
		return err
	}

	// Keep non nil and non-zero MACs
	for i := range newTable {
		if newTable[i].MAC != nil &&
			!bytes.Equal(newTable[i].MAC, net.HardwareAddr{}) &&
			!bytes.Equal(newTable[i].MAC, net.HardwareAddr{0, 0, 0, 0, 0, 0}) {
			h.nameTable = append(h.nameTable, newTable[i])
		}
	}
	return nil
}

// Save save names to file
func (h *NameHandler) save() (err error) {
	stream, err := yaml.Marshal(h.nameTable)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(h.filename, stream, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}
