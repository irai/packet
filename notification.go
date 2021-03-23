package packet

import (
	"net"
	"time"
)

type Notification struct {
	Addr     Addr
	Online   bool
	DHCPName string
	MDNSName string
}

/***
// AddCallback sets theO call back function for notifications
// the callback function is invoked immediately for each existing entry
func (h *Handler) AddCallback(f func(Notification) error) {
	h.mutex.Lock()
	h.callback = append(h.callback, f)
	list := []Notification{}
	for _, v := range h.LANHosts.Table {
		list = append(list, Notification{Addr: Addr{MAC: v.MACEntry.MAC, IP: v.IP}, Online: v.Online})
	}
	h.mutex.Unlock()
	// notify without lock
	go func() {
		time.Sleep(time.Millisecond * 10)
		for _, v := range list {
			if err := f(v); err != nil {
				fmt.Printf("packet: error in call back %+v error: %s", v, err)
			}
		}
	}()
}
***/

// purge is called each minute by the minute goroutine
func (h *Handler) purge(now time.Time, offlineDur time.Duration, purgeDur time.Duration) error {

	offlineCutoff := now.Add(offlineDur * -1) // Mark offline entries last updated before this time
	deleteCutoff := now.Add(purgeDur * -1)    // Delete entries that have not responded in last hour

	purge := make([]net.IP, 0, 16)
	offline := make([]*Host, 0, 16)

	h.mutex.RLock()
	for _, e := range h.LANHosts.Table {
		e.Row.RLock()

		// Delete from table if the device is offline and was not seen for the last hour
		if !e.Online && e.LastSeen.Before(deleteCutoff) {
			purge = append(purge, e.IP)
			e.Row.RUnlock()
			continue
		}

		// Set offline if no updates since the offline deadline
		if e.Online && e.LastSeen.Before(offlineCutoff) {
			offline = append(offline, e)
		}
		e.Row.RUnlock()
	}
	h.mutex.RUnlock()

	for _, host := range offline {
		h.lockAndSetOffline(host) // will lock/unlock row
	}

	// delete after loop because this will change the table
	if len(purge) > 0 {
		for _, v := range purge {
			h.deleteHostWithLock(v)
		}
	}

	return nil
}

/***
func (h *Handler) notifyCallback(notification Notification) {
	for _, f := range h.callback {
		if err := f(notification); err != nil {
			fmt.Printf("packet: error in call back: %s", err)
		}
	}
}
***/
