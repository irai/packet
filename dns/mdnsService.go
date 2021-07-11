package dns

import (
	"strings"
)

type serviceDef struct {
	service      string
	defaultModel string
	keyName      string
}

// full IANA list here:
// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
//
// Bonjour
// see spec http://devimages.apple.com/opensource/BonjourPrinting.pdf
var serviceTable = []serviceDef{
	{"_http._tcp.local.", "Network server", ""},
	{"_workstation._tcp.local.", "", ""},
	{"_ipp._tcp.local.", "printer", "ty"},
	{"_ipps._tcp.local.", "printer", "ty"},
	{"_printer._tcp.local.", "printer", "ty"},
	{"_pdl-datastream._tcp.local.", "printer", "ty"},
	{"_privet._tcp.local.", "printer", "ty"},
	{"_scanner._tcp.local.", "scanner", "ty"},
	{"_uscan._tcp.local.", "scanner", "ty"},
	{"_uscans._tcp.local.", "scanner", "ty"},
	{"_smb._tcp.local.", "", "model"},
	{"_device-info._udp.local.", "computer", "model"},
	{"_device-info._tcp.local.", "computer", "model"},
	{"_netbios-ns._udp.local.", "", ""},
	{"_spotify-connect._tcp.local.", "Spotify speaker", ""},
	{"_sonos._tcp.local.", "Sonos speaker", ""},
	{"_snmp._udp.local.", "", ""},
	{"_music._tcp.local.", "", ""},
	{"_raop._tcp.local.", "Apple device", ""},           // Remote Audio Output Protocol (AirTunes) - Apple
	{"_apple-mobdev2._tcp.local.", "Apple device", ""},  // Apple Mobile Device Protocol - Apple
	{"_airplay._tcp.local.", "Apple TV", "model"},       //Protocol for streaming of audio/video content - Apple
	{"_touch-able._tcp.local.", "Apple device", "DvTy"}, //iPhone and iPod touch Remote Controllable - Apple
	{"_nvstream._tcp.local.", "", ""},
	{"_googlecast._tcp.local.", "Chromecast", "md"},
	{"_googlezone._tcp.local.", "Google device", ""},
	{"_sleep-proxy._udp.local.", "Apple", ""},
	{"_xbox._tcp.local.", "xbox", ""},
	{"_xbox._udp.local.", "xbox", ""},
	{"_psams._tcp.local.", "playstation", ""}, // play station
	{"_psams._udp.local.", "playstation", ""}, // play station
}

// parseTXT search for model field
//   [model=MacBookPro14,1 osxvers=20 ecolor=157,157,160]
func parseTXT(txt []string) (model string) {
	if len(txt) <= 2 {
		return ""
	}

	for _, v := range txt {
		a := strings.Split(v, "=")
		if len(a) < 2 {
			continue
		}
		switch a[0] {
		case "model":
			return a[1]
		case "ty":
			return a[1]
		case "DvTy": // iphone and ipad
			return a[1]
		case "md": // google chromecast
			return a[1]
		}
	}

	return ""
}
