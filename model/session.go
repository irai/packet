package model

import "net"

type Session struct {
	Conn      net.PacketConn
	NICInfo   NICInfo
	HostTable []int
	MACTable  []int
}
