package fastlog

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"syscall"
	"testing"

	"github.com/irai/packet"
)

/** Results: July 2021
goos: linux
goarch: amd64
pkg: github.com/irai/packet/fastlog
Benchmark_FastLoggingOld-8       1776063               691 ns/op             754 B/op          8 allocs/op
Benchmark_FastLogging-8          2249403               531 ns/op             242 B/op          7 allocs/op
Benchmark_FastLogging2-8         2266210               533 ns/op             242 B/op          7 allocs/op
Benchmark_Printf-8               1514708               801 ns/op             274 B/op          8 allocs/op
PASS
ok      github.com/irai/packet/fastlog  8.559s
*/

func withBuffer(data ...string) error {
	var out bytes.Buffer
	out.Grow(512)
	for _, v := range data {
		out.WriteString(v)
	}
	out.WriteString("\n")
	// _, err := std.out.Write(out.Bytes())

	return nil
}

func Benchmark_FastLoggingOld(b *testing.B) {
	std.out = ioutil.Discard
	buf := make([]byte, packet.EthMaxSize)
	for i := 0; i < b.N; i++ {
		mac2 := net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, byte(i)}
		ether := packet.EtherMarshalBinary(buf, syscall.ETH_P_IPV6, mac2, mac2)
		withBuffer("ether: ", ether.String())
	}
}
func Benchmark_FastLogging(b *testing.B) {
	std.out = ioutil.Discard
	buf := make([]byte, packet.EthMaxSize)
	var err error
	mac2 := net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x03}
	for i := 0; i < b.N; i++ {
		ether := packet.EtherMarshalBinary(buf, syscall.ETH_P_IPV6, mac2, mac2)
		err = Strings("ether: ", ether.String())
	}
	if err != nil {
		fmt.Print(err)
	}
}

func Benchmark_FastLogging2(b *testing.B) {
	std.out = ioutil.Discard
	buf := make([]byte, packet.EthMaxSize)
	var err error
	for i := 0; i < b.N; i++ {
		mac2 := net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, byte(i)}
		ether := packet.EtherMarshalBinary(buf, syscall.ETH_P_IPV6, mac2, mac2)
		err = Strings2("ether: ", ether.String())
	}
	if err != nil {
		fmt.Print(err)
	}
}

//  348084	      3067 ns/op	     274 B/op	       8 allocs/op
func Benchmark_Printf(b *testing.B) {
	std.out = ioutil.Discard
	var err error
	buf := make([]byte, packet.EthMaxSize)
	for i := 0; i < b.N; i++ {
		mac2 := net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, byte(i)}
		ether := packet.EtherMarshalBinary(buf, syscall.ETH_P_IPV6, mac2, mac2)
		_, err = fmt.Fprintf(std.out, "ether: %s\n", ether)
	}
	if err != nil {
		fmt.Print(err)
	}
}
