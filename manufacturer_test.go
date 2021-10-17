package packet

import (
	"net"
	"testing"
)

func mustmac(mac string) net.HardwareAddr {
	m, err := net.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	return m
}

func Test_findManufacturer(t *testing.T) {
	tests := []struct {
		name         string
		mac          net.HardwareAddr
		wantLongName string
		wantErr      bool
	}{
		{name: "tplink", wantErr: false, mac: mustmac("34:e8:94:42:29:a9"), wantLongName: "TP-Link"},
		{name: "apple", wantErr: false, mac: mustmac("84:b1:53:ea:1f:40"), wantLongName: "Apple"},
		{name: "intel", wantErr: false, mac: mustmac("dc:21:5c:3e:c9:f7"), wantLongName: "Intel"},
		{name: "blank", wantErr: false, mac: mustmac("02:42:15:e6:10:08"), wantLongName: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// f := bytes.NewReader(sampleManufacturerFile)
			gotLongName := FindManufacturer(tt.mac)
			if gotLongName != tt.wantLongName {
				t.Errorf("findManufacturer() gotLongName = %v, want %v", gotLongName, tt.wantLongName)
			}
		})
	}
}

func BenchmarkAddr_ManufacturerLookup(t *testing.B) {
	count = 0
	for i := 0; i < t.N; i++ {
		gotLongName := FindManufacturer(mustmac("84:b1:53:ea:1f:40"))
		if gotLongName != "Apple" {
			t.Fatalf("findManufacturer() gotLongName %v ", gotLongName)
		}
		count++
	}
}
