package fastlog

import (
	"io"
	"os"
	"sync"
)

type Logger struct {
	out  io.Writer
	pool sync.Pool
}

const bufSize = 1024

var std = &Logger{out: os.Stderr, pool: sync.Pool{New: func() interface{} { return new([bufSize]byte) }}}

func Strings(data ...string) error {
	// buffer := [512]byte{}
	// buffer := std.buffer
	buffer := std.pool.Get().(*[bufSize]byte)
	defer std.pool.Put(buffer)
	pos := 0
	for _, v := range data {
		if pos+len(v) <= cap(buffer) {
			copy(buffer[pos:], v)
			pos = pos + len(v)
			continue
		}
		copy(buffer[0:], "MSG TRUNCATED")
		break
	}
	buffer[pos] = '\n'
	_, err := std.out.Write(buffer[:pos+1])
	return err
}

func Strings2(str1 string, str2 string) error {
	buffer := std.pool.Get().(*[bufSize]byte)
	defer std.pool.Put(buffer)
	pos := copy(buffer[0:], str1)
	pos = pos + copy(buffer[pos:], str2)
	buffer[pos] = '\n'
	_, err := std.out.Write(buffer[:pos+1])
	return err
}
