package packet

import "time"

// PacketProcessor defines the interface for packet processing modules
type PacketProcessor interface {
	Start() error
	Stop() error
	ProcessPacket(host *Host, p []byte, header []byte) (Result, error)
	StartHunt(Addr) (HuntStage, error)
	StopHunt(Addr) (HuntStage, error)
	CheckAddr(Addr) (HuntStage, error)
	MinuteTicker(time.Time) error
}

// PacketNOOP is a no op packet processor
type PacketNOOP struct{}

var _ PacketProcessor = PacketNOOP{}

func (p PacketNOOP) Start() error { return nil }
func (p PacketNOOP) Stop() error  { return nil }
func (p PacketNOOP) ProcessPacket(*Host, []byte, []byte) (Result, error) {
	return Result{}, nil
}
func (p PacketNOOP) StartHunt(addr Addr) (HuntStage, error) { return StageNoChange, nil }
func (p PacketNOOP) StopHunt(addr Addr) (HuntStage, error)  { return StageNoChange, nil }
func (p PacketNOOP) CheckAddr(addr Addr) (HuntStage, error) { return StageNoChange, nil }
func (p PacketNOOP) Close() error                           { return nil }

// func (p PacketNOOP) HuntStage(addr Addr) HuntStage              { return StageNormal }
func (p PacketNOOP) MinuteTicker(now time.Time) error { return nil }
