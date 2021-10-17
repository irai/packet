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
		name          string
		mac           net.HardwareAddr
		wantShortName string
		wantLongName  string
		wantErr       bool
	}{
		{name: "simple", wantErr: false, mac: mustmac("34:e8:94:42:29:a9"), wantShortName: "Tp-LinkT", wantLongName: "Tp-Link Technologies Co.,Ltd."},
		{name: "simple", wantErr: false, mac: mustmac("84:b1:53:ea:1f:40"), wantShortName: "Apple", wantLongName: "Apple, Inc."},
		{name: "simple", wantErr: false, mac: mustmac("dc:21:5c:3e:c9:f7"), wantShortName: "IntelCor", wantLongName: "Intel Corporate"},
		{name: "simple", wantErr: false, mac: mustmac("02:42:15:e6:10:08"), wantShortName: "", wantLongName: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// f := bytes.NewReader(sampleManufacturerFile)
			gotShortName, gotLongName, err := FindManufacturer(tt.mac)
			if (err != nil) != tt.wantErr {
				t.Errorf("findManufacturer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotShortName != tt.wantShortName {
				t.Errorf("findManufacturer() gotShortName = %v, want %v", gotShortName, tt.wantShortName)
			}
			if gotLongName != tt.wantLongName {
				t.Errorf("findManufacturer() gotLongName = %v, want %v", gotLongName, tt.wantLongName)
			}
		})
	}
}
