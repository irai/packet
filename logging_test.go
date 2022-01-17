package packet

import (
	"io/ioutil"
	"syscall"
	"testing"

	"github.com/irai/packet/fastlog"
)

func Benchmark_FastLogPrint(b *testing.B) {
	p := make([]byte, EthMaxSize)
	ether := EncodeEther(p, syscall.ETH_P_IP, mac1, EthBroadcast)
	ip4 := EncodeIP4(ether.Payload(), 255, ip1, IP4Broadcast)
	ether, _ = ether.SetPayload(ip4)

	h := testSession()
	frame, _ := h.Parse(ether)

	fastlog.Std.Out = ioutil.Discard
	b.Run("ether", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			fastlog.Std.NewLine("ether", "").Struct(ether).Write()
		}
	})
	b.Run("ip", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			fastlog.Std.NewLine("ipv4", "").Struct(ip4).Write()
		}
	})
	b.Run("frame", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			frame.Log(fastlog.Std.NewLine("frame", "")).Write()
		}
	})
}
