package packet

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/hex"
	"net"
	"strings"

	"github.com/irai/packet/fastlog"
)

// Gzip commpressed file containing mac OUI and manufacturer name.
// Format as follows:   000019<tab>Applied Dynamics
// Get the latest from here:
//   https://linuxnet.ca/ieee/oui/nmap-mac-prefixes
//
// Alternatively we could use the wireshart format, but it is much larger file
// https://gitlab.com/wireshark/wireshark/-/raw/master/manuf
//
//go:embed nmap-mac-prefixes.gz
var manufacturersFile []byte

var manufacturersMap = make(map[string]string)

// Uncmpress and load manufacturers file into a map during initialisation
func init() {
	countErrors := 0
	f, err := gzip.NewReader(bytes.NewReader(manufacturersFile))
	if err != nil {
		panic(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' || len(line) < 8 {
			continue
		}

		s := strings.Split(line, "\t")
		if len(s) < 2 || len(s[0]) != 6 {
			countErrors++
			continue
		}

		d, err := hex.DecodeString(s[0])
		if err != nil || len(d) != 3 {
			countErrors++
			continue
		}
		manufacturersMap[string(d)] = strings.Join(s[1:], " ")
	}
	if err := scanner.Err(); err != nil {
		fastlog.NewLine(module, "error reading manufacturing file").Int("count", countErrors).Write()
		panic(err)
	}
	if countErrors != 0 {
		fastlog.NewLine(module, "error in manufacturing file").Int("count", countErrors).Write()
		panic(err)
	}
}

// FindManufacturer locates the manufacturer name using the first 24bits of the mac address.
func FindManufacturer(mac net.HardwareAddr) (name string) {
	if len(mac) != 6 {
		return ""
	}
	return manufacturersMap[string(mac[:3])]
}
