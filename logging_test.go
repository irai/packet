package packet

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"sync"
	"syscall"
	"testing"

	"github.com/irai/packet/fastlog"
)

/** Results: July 2021
goos: linux
goarch: amd64
pkg: github.com/irai/packet
Benchmark_FastLogPrintf-8                1454368               780 ns/op             274 B/op          8 allocs/op
Benchmark_FastLogByteBuffer-8            2184068               550 ns/op             242 B/op          7 allocs/op
Benchmark_FastLogStrings-8               2242190               527 ns/op             242 B/op          7 allocs/op
Benchmark_FastLogString2-8               2241307               517 ns/op             242 B/op          7 allocs/op
Benchmark_FastLogLinePrint-8             4046708               282 ns/op              34 B/op          2 allocs/op
PASS
ok      github.com/irai/packet  8.619s
*/
var testPool = sync.Pool{New: func() interface{} { return new(bytes.Buffer) }}

func withBuffer(data ...string) error {
	buffer := testPool.Get().(*bytes.Buffer)
	defer testPool.Put(buffer)

	buffer.Reset()

	for _, v := range data {
		buffer.WriteString(v)
	}
	buffer.WriteString("\n")
	_, err := fastlog.Std.Out.Write(buffer.Bytes())

	return err
}

func Benchmark_FastLogPrintf(b *testing.B) {
	fastlog.Std.Out = ioutil.Discard
	var err error
	buf := make([]byte, EthMaxSize)
	for i := 0; i < b.N; i++ {
		mac2 := net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, byte(i)}
		ether := EtherMarshalBinary(buf, syscall.ETH_P_IPV6, mac2, mac2)
		_, err = fmt.Fprintf(fastlog.Std.Out, "ether: %s\n", ether)
	}
	if err != nil {
		fmt.Print(err)
	}
}

func Benchmark_FastLogByteBuffer(b *testing.B) {
	fastlog.Std.Out = ioutil.Discard
	buf := make([]byte, EthMaxSize)
	mac2 := net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x03}
	for i := 0; i < b.N; i++ {
		ether := EtherMarshalBinary(buf, syscall.ETH_P_IPV6, mac2, mac2)
		withBuffer("ether: ", ether.String())
	}
}
func Benchmark_FastLogStrings(b *testing.B) {
	fastlog.Std.Out = ioutil.Discard
	buf := make([]byte, EthMaxSize)
	var err error
	mac2 := net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x03}
	for i := 0; i < b.N; i++ {
		ether := EtherMarshalBinary(buf, syscall.ETH_P_IPV6, mac2, mac2)
		err = fastlog.Strings("ether: ", ether.String())
	}
	if err != nil {
		fmt.Print(err)
	}
}

func Benchmark_FastLogString2(b *testing.B) {
	fastlog.Std.Out = ioutil.Discard
	buf := make([]byte, EthMaxSize)
	var err error
	mac2 := net.HardwareAddr{0xaf, 0x02, 0x03, 0x04, 0x05, 0x03}
	for i := 0; i < b.N; i++ {
		ether := EtherMarshalBinary(buf, syscall.ETH_P_IPV6, mac2, mac2)
		err = fastlog.Strings2("ether: ", ether.String())
	}
	if err != nil {
		fmt.Print(err)
	}
}

func Benchmark_FastLogLinePrint(b *testing.B) {
	fastlog.Std.Out = ioutil.Discard
	buf := make([]byte, EthMaxSize)
	var err error
	mac2 := net.HardwareAddr{0xaf, 0x02, 0x03, 0x04, 0x05, 0x03}
	for i := 0; i < b.N; i++ {
		ether := EtherMarshalBinary(buf, syscall.ETH_P_IPV6, mac2, mac2)
		err = fastlog.Std.NewLine("ether", "").Struct(ether).Write()
	}
	if err != nil {
		fmt.Print(err)
	}
}
