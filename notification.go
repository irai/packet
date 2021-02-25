package packet

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/irai/packet/raw"
)

type Notification struct {
	IP     net.IP
	MAC    net.HardwareAddr
	Online bool
}

func (h *Handler) AddCallback(f func(Notification) error) {
	h.callback = append(h.callback, f)
}

func (h *Handler) purgeLoop(ctx context.Context, offline time.Duration, purge time.Duration) error {

	dur := time.Minute * 1
	if offline <= dur {
		dur = offline / 2
	}
	ticker := time.NewTicker(dur).C
	for {
		select {
		case <-ctx.Done():
			return nil

		case <-ticker:

			now := time.Now()
			offlineCutoff := now.Add(offline * -1) // Mark offline entries last updated before this time
			deleteCutoff := now.Add(purge * -1)    // Delete entries that have not responded in last hour

			purge := make([]net.IP, 0, 16)
			notify := make([]Notification, 0, 16)

			h.LANHosts.Lock()
			for _, e := range h.LANHosts.Table {

				// Delete from table if the device was not seen for the last hour
				if e.LastSeen.Before(deleteCutoff) {
					purge = append(purge, e.IP)
					continue
				}

				// Set offline if no updates since the offline deadline
				// Ignore virtual hosts; offline controlled by spoofing goroutine
				if e.Online && e.LastSeen.Before(offlineCutoff) {
					e.Online = false
					notify = append(notify, Notification{IP: e.IP, MAC: e.MAC, Online: e.Online})
				}
			}
			callback := h.callback // keep a copy
			h.LANHosts.Unlock()

			// delete after loop because this will change the table
			if len(purge) > 0 {
				for _, v := range purge {
					h.LANHosts.Delete(v)
				}
			}

			for _, v := range notify {
				for _, f := range callback {
					if err := f(v); err != nil {
						fmt.Printf("packet: error in call back: %s", err)
					}
				}
			}
		}
	}
}

func (h *Handler) notifyCallback(host *raw.Host) {
	notification := Notification{IP: host.IP, MAC: host.MAC, Online: host.Online}
	for _, f := range h.callback {
		if err := f(notification); err != nil {
			fmt.Printf("packet: error in call back: %s", err)
		}
	}
}
