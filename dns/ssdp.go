package dns

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"

	"github.com/irai/packet"
)

func (h *DNSHandler) ProcessSSDP(host *packet.Host, ether packet.Ether, payload []byte) (hostName HostName, err error) {
	/*
				// Add newline to workaround buggy SSDP responses
		var endOfHeader = []byte{'\r', '\n', '\r', '\n'}
				if !bytes.HasSuffix(payload, endOfHeader) {
					raw = bytes.Join([][]byte{raw, endOfHeader}, nil)
				}
	*/

	if bytes.HasPrefix(payload, []byte("M-SEARCH ")) {
		handleSearch(payload)
		return hostName, nil
	}
	if bytes.HasPrefix(payload, []byte("NOTIFY ")) {
		return handleNotify(payload)
	}
	return hostName, packet.ErrParseFrame
}

func handleNotify(raw []byte) (hostName HostName, err error) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return hostName, err
	}

	switch nts := req.Header.Get("NTS"); nts {
	case "ssdp:alive":
		if req.Method != "NOTIFY" {
			return hostName, packet.ErrParseFrame
		}
		hostName.Attributes["type"] = req.Header.Get("NT")
		hostName.Attributes["description"] = req.Header.Get("SERVER")
		hostName.Attributes["usn"] = req.Header.Get("USN")
		hostName.Attributes["location"] = req.Header.Get("LOCATION")
	case "ssdp:byebye":
		if req.Method != "NOTIFY" {
			return hostName, packet.ErrParseFrame
		}
		fmt.Printf("ssdp  : byebye %s", raw)
	default:
		fmt.Printf("ssdp  : error invalid NTS header %s\n", nts)
		return hostName, packet.ErrParseFrame
	}
	return hostName, nil
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
