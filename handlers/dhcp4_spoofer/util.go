package dhcp4

import (
	"net"
)

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
