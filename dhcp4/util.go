package dhcp4

import (
	"net"

	log "github.com/sirupsen/logrus"
)

func dupIP(srcIP net.IP) net.IP {
	ip := make(net.IP, len(srcIP))
	copy(ip, srcIP)
	return ip
}

func dupMAC(srcMAC net.HardwareAddr) net.HardwareAddr {
	mac := make(net.HardwareAddr, len(srcMAC))
	copy(mac, srcMAC)
	return mac
}

func dupBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	ret := make([]byte, len(b))
	copy(ret, b)
	return ret
}

func dupFields(src map[string]interface{}) map[string]interface{} {
	ret := make(map[string]interface{}, len(src)+10)
	for key, value := range src {
		ret[key] = value
	}
	return ret
}

func checkOptions(a Options, b Options) Options {
	c := Options{}
	for key := range a {
		if value, ok := b[key]; ok {
			c[key] = value
		} else {
			c[key] = nil
		}
	}
	return c
}

func debugging() bool {
	if Debug && log.IsLevelEnabled(log.DebugLevel) {
		return true
	}
	return false
}

func tracing() bool {
	if Debug && log.IsLevelEnabled(log.TraceLevel) {
		return true
	}
	return false
}
