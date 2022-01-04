// Code generated by "stringer -type=PayloadID"; DO NOT EDIT.

package packet

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[PayloadEther-1]
	_ = x[Payload8023-2]
	_ = x[PayloadARP-3]
	_ = x[PayloadIP4-4]
	_ = x[PayloadIP6-5]
	_ = x[PayloadICMP4-6]
	_ = x[PayloadICMP6-7]
	_ = x[PayloadUDP-8]
	_ = x[PayloadTCP-9]
	_ = x[PayloadDHCP4-10]
	_ = x[PayloadDHCP6-11]
	_ = x[PayloadDNS-12]
	_ = x[PayloadMDNS-13]
	_ = x[PayloadSSL-14]
	_ = x[PayloadNTP-15]
	_ = x[PayloadSSDP-16]
	_ = x[PayloadWSDP-17]
	_ = x[PayloadNBNS-18]
	_ = x[PayloadPlex-19]
	_ = x[PayloadUbiquiti-20]
	_ = x[PayloadLLMNR-21]
	_ = x[PayloadIGMP-22]
	_ = x[PayloadEthernetPause-23]
	_ = x[PayloadRRCP-24]
	_ = x[PayloadLLDP-25]
	_ = x[Payload802_11r-26]
	_ = x[PayloadIEEE1905-27]
	_ = x[PayloadSonos-28]
	_ = x[Payload880a-29]
}

const _PayloadID_name = "PayloadEtherPayload8023PayloadARPPayloadIP4PayloadIP6PayloadICMP4PayloadICMP6PayloadUDPPayloadTCPPayloadDHCP4PayloadDHCP6PayloadDNSPayloadMDNSPayloadSSLPayloadNTPPayloadSSDPPayloadWSDPPayloadNBNSPayloadPlexPayloadUbiquitiPayloadLLMNRPayloadIGMPPayloadEthernetPausePayloadRRCPPayloadLLDPPayload802_11rPayloadIEEE1905PayloadSonosPayload880a"

var _PayloadID_index = [...]uint16{0, 12, 23, 33, 43, 53, 65, 77, 87, 97, 109, 121, 131, 142, 152, 162, 173, 184, 195, 206, 221, 233, 244, 264, 275, 286, 300, 315, 327, 338}

func (i PayloadID) String() string {
	i -= 1
	if i < 0 || i >= PayloadID(len(_PayloadID_index)-1) {
		return "PayloadID(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _PayloadID_name[_PayloadID_index[i]:_PayloadID_index[i+1]]
}