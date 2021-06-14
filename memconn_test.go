package packet

import (
	"sync"
	"testing"
	"time"
)

func Test_bufferedPacketConn_ReadFrom(t *testing.T) {
	a, b := TestNewBufferedConn()

	sent := []byte("test")
	buffer := make([]byte, 32)
	count := 0
	var mutex sync.Mutex

	go func(t *testing.T) {
		for {
			if _, _, err := b.ReadFrom(buffer); err != nil {
				panic(err)
			}
			mutex.Lock()
			count++
			mutex.Unlock()
		}
	}(t)
	// time.Sleep(time.Millisecond * 10) // time for read to start

	a.WriteTo(sent, nil)
	a.WriteTo(sent, nil)
	a.WriteTo(sent, nil)
	time.Sleep(time.Millisecond * 5)
	mutex.Lock()
	defer mutex.Unlock()
	if count != 3 {
		t.Fatal("error in read ", count)
	}
}
