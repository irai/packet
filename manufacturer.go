package packet

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"net"
	"strconv"
	"strings"

	"github.com/irai/packet/fastlog"
)

//go:embed manuf.gz
// Gzip compressed file in the format used by wireshark as specified here:
// https://gitlab.com/wireshark/wireshark/-/raw/master/manuf
var manufacturers []byte

func findManufacturer(mac net.HardwareAddr) string {
	_, s, _ := FindManufacturer(mac)
	return s
}

// FindManufacturer locates the manufacturer name using the first 24bits of the mac address.
func FindManufacturer(mac net.HardwareAddr) (shortName string, longName string, err error) {
	if len(mac) != 6 {
		return
	}
	countErrors := 0

	f, err := gzip.NewReader(bytes.NewReader(manufacturers))
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}

		s := strings.Split(line, "\t")
		if len(s) < 2 {
			countErrors++
			continue
		}
		if len(s) < 3 { // some entries don't have long names
			s = append(s, s[1])
		}

		d := net.HardwareAddr{}
		switch len(s[0]) {
		case 8:
			d, err = net.ParseMAC(s[0] + ":00:00:00")
			if err != nil {
				countErrors++
				continue
			}
			if bytes.Equal(mac[0:3], d[0:3]) {
				return s[1], s[2], nil
			}
		default:
			tmp := strings.Split(s[0], "/")
			if len(s) != 2 {
				countErrors++
				continue
			}
			d, err = net.ParseMAC(tmp[0])
			if err != nil {
				countErrors++
				continue
			}
			if bits, err := strconv.Atoi(tmp[1]); err != nil || bits < 24 {
				countErrors++
				continue
			}
			if !bytes.Equal(mac[0:3], d[0:3]) {
				fastlog.NewLine(module, "partial manufacturer ethernet matching not implemented").String("entry", s[0]).MAC("mac", mac).Write()
				return s[1], s[2], nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	if countErrors != 0 {
		fastlog.NewLine(module, "error in manufacturing file").Int("count", countErrors).Write()
	}
	return "", "", nil
}
