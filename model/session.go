package model

import (
	"net"
	"time"
)

type Session struct {
	Conn     net.PacketConn
	NICInfo  NICInfo
	LANHosts HostTable // store IP list - one for each host
	MACTable MACTable  // store mac list
}

// PacketNOOP is a no op packet processor
type PacketNOOP struct{}

var _ PacketProcessor = PacketNOOP{}

func (p PacketNOOP) Start() error { return nil }
func (p PacketNOOP) Stop() error  { return nil }
func (p PacketNOOP) ProcessPacket(*Host, []byte, []byte) (*Host, Result, error) {
	return nil, Result{}, nil
}
func (p PacketNOOP) StartHunt(addr model.Addr) (HuntStage, error) { return StageNoChange, nil }
func (p PacketNOOP) StopHunt(addr model.Addr) (HuntStage, error)  { return StageNoChange, nil }
func (p PacketNOOP) CheckAddr(addr model.Addr) (HuntStage, error) { return StageNoChange, nil }

// func (p PacketNOOP) HuntStage(addr Addr) HuntStage              { return StageNormal }
func (p PacketNOOP) MinuteTicker(now time.Time) error { return nil }
