package fastlog

import (
	"fmt"
	"io"
	"os"
	"sync"
)

type Logger struct {
	Out   io.Writer
	pool  sync.Pool
	lines sync.Pool
}

const bufSize = 1024

var Std = &Logger{
	Out:   os.Stderr,
	pool:  sync.Pool{New: func() interface{} { return new([bufSize]byte) }},
	lines: sync.Pool{New: func() interface{} { return new(Line) }},
}

type Line struct {
	buffer [bufSize]byte
	index  int
}

type LineLog interface {
	Print(*Line) *Line
}

func NewLine(module string, msg string) *Line {
	return Std.NewLine(module, msg)
}

func (logger *Logger) NewLine(module string, msg string) *Line {
	l := Std.lines.Get().(*Line)
	copy(l.buffer[0:], "      :")
	copy(l.buffer[0:6], module)
	l.index = 7
	if msg != "" {
		l.index = l.index + copy(l.buffer[8:], " msg=\"")
		l.index = l.index + copy(l.buffer[l.index:], msg)
		l.buffer[l.index] = '"'
		l.index++
	}
	return l
}

func (l *Line) Byte(value byte) *Line {
	l.buffer[l.index] = value
	l.index++
	return l
}

func (l *Line) Write() error {
	l.buffer[l.index] = '\n'
	_, err := Std.Out.Write(l.buffer[:l.index+1])
	Std.lines.Put(l)
	return err
}

func (l *Line) String(name string, value string) *Line {
	l.buffer[l.index] = ' '
	l.index++
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.buffer[l.index] = '='
	l.index++
	l.index = l.index + copy(l.buffer[l.index:], value)
	return l
}

func (l *Line) Struct(value LineLog) *Line {
	return value.Print(l)
}

func (l *Line) Int(name string, value int) *Line {
	l.buffer[l.index] = ' '
	l.index++
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.buffer[l.index] = '='
	l.index++
	l.index = l.index + copy(l.buffer[l.index:], fmt.Sprintf("%d", value))
	return l
}

func (l *Line) Uint16Hex(name string, value uint16) *Line {
	l.buffer[l.index] = ' '
	l.index++
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.buffer[l.index] = '='
	l.index++
	l.index = l.index + copy(l.buffer[l.index:], "0x")
	l.buffer[l.index] = hexAscii[(value>>12)&0x0f]
	l.index++
	l.buffer[l.index] = hexAscii[(value>>8)&0x0f]
	l.index++
	l.buffer[l.index] = hexAscii[(value>>4)&0x0f]
	l.index++
	l.buffer[l.index] = hexAscii[value&0x0f]
	l.index++
	return l
}

var hexAscii = []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

func (l *Line) writeHex(value byte) {
	l.buffer[l.index] = hexAscii[value>>4]
	l.index++
	l.buffer[l.index] = hexAscii[value&0x0f]
	l.index++
}

func (l *Line) ByteArray(name string, value []byte) *Line {
	l.buffer[l.index] = ' '
	l.index++
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.index = l.index + copy(l.buffer[l.index:], "=[")
	for _, v := range value {
		l.writeHex(v)
		l.buffer[l.index] = ' '
		l.index++
	}
	l.index--
	l.buffer[l.index] = ']'
	l.index++
	return l
}

func Strings(data ...string) error {
	// buffer := [512]byte{}
	// buffer := std.buffer
	buffer := Std.pool.Get().(*[bufSize]byte)
	defer Std.pool.Put(buffer)
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
	_, err := Std.Out.Write(buffer[:pos+1])
	return err
}

func Strings2(str1 string, str2 string) error {
	buffer := Std.pool.Get().(*[bufSize]byte)
	defer Std.pool.Put(buffer)
	pos := copy(buffer[0:], str1)
	pos = pos + copy(buffer[pos:], str2)
	buffer[pos] = '\n'
	_, err := Std.Out.Write(buffer[:pos+1])
	return err
}
