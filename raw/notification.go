package raw

import (
	"context"
	"fmt"
	"net"
	"time"
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

	// Typically one minute but loop more often if offline smaller than 1 minute
	dur := time.Minute * 1
	if offline <= dur {
		dur = offline / 4
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

			h.LANHosts.Lock()
			for _, e := range h.LANHosts.Table {

				// Delete from table if the device is offline and was not seen for the last hour
				if !e.Online && e.LastSeen.Before(deleteCutoff) {
					purge = append(purge, e.IP)
					continue
				}

				// Set offline if no updates since the offline deadline
				if e.Online && e.LastSeen.Before(offlineCutoff) {
					e.Online = false // set value here while we have the lock
					h.makeOffline(e.MAC, e.IP)
				}
			}
			h.LANHosts.Unlock()

			// delete after loop because this will change the table
			if len(purge) > 0 {
				for _, v := range purge {
					h.LANHosts.Delete(v)
				}
			}
		}
	}
}

func (h *Handler) notifyCallback(notification Notification) {
	for _, f := range h.callback {
		if err := f(notification); err != nil {
			fmt.Printf("packet: error in call back: %s", err)
		}
	}
}
