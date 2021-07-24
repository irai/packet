package fastlog

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

// Package fastlog implements a simple, fast logger for hotpath logging. It is
// 3 times faster than using fmt.Printf().
//
// It achieves this by:
//  - avoiding type introspection
//  - Writting directly to in memory buffer - no string conversion
//  - specialised types for MAC/IP/Int writing directly to buffer
//  - minimum validation - assumes the caller is passing valid types and valid len
//  - assumes a max fixed memory buffer len of 1024k per message - ie. it will segfault if the caller passes longer data
//  - pool of reusable buffers
//
// Results: July 2021 logging Ethernet frame
// Benchmark_FastLogPrintf-8                1454368               780 ns/op             274 B/op          8 allocs/op
// Benchmark_FastLogLinePrint-8             4046708               282 ns/op              34 B/op          2 allocs/op

// bufSize sets the maximum len for a log entry
const bufSize = 1024

type Logger struct {
	Out   io.Writer
	pool  sync.Pool
	lines sync.Pool
}

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
	l.index = 0
	return l.newModule(module, msg)
}

func (l *Line) Module(name string, msg string) *Line {
	return l.newModule(name, msg)
}

func (l *Line) newModule(module string, msg string) *Line {
	copy(l.buffer[l.index:], "      :")
	copy(l.buffer[l.index:l.index+6], module)
	l.index = l.index + 7
	if msg != "" {
		// l.index = l.index + copy(l.buffer[l.index:], " msg=\"")
		l.appendByte(' ')
		l.appendByte('"')
		l.index = l.index + copy(l.buffer[l.index:], msg)
		l.appendByte('"')
	}
	return l
}

// LF append a line feed to line
func (l *Line) LF() *Line {
	l.appendByte('\n')
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

func (l *Line) MAC(name string, value net.HardwareAddr) *Line {
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte('=')
	if value != nil && len(value) == 6 {
		l.writeHex(value[0])
		l.appendByte(':')
		l.writeHex(value[1])
		l.appendByte(':')
		l.writeHex(value[2])
		l.appendByte(':')
		l.writeHex(value[3])
		l.appendByte(':')
		l.writeHex(value[4])
		l.appendByte(':')
		l.writeHex(value[5])
		return l
	}
	l.index = l.index + copy(l.buffer[l.index:], "nil")
	return l
}

func (l *Line) Struct(value LineLog) *Line {
	return value.Print(l)
}

func (l *Line) Uint8(name string, value uint8) *Line {
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte('=')
	l.index = l.index + copy(l.buffer[l.index:], byteAscii[value])
	return l
}

func (l *Line) Uint16Hex(name string, value uint16) *Line {
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte('=')
	l.appendByte('0')
	l.appendByte('x')
	l.appendByte(hexAscii[(value>>12)&0x0f])
	l.appendByte(hexAscii[(value>>8)&0x0f])
	l.appendByte(hexAscii[(value>>4)&0x0f])
	l.appendByte(hexAscii[value&0x0f])
	return l
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

var byteAscii = []string{
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "100", "101", "102", "103", "104", "105", "106", "107", "108", "109", "110", "111", "112", "113", "114", "115", "116", "117", "118", "119", "120", "121", "122", "123", "124", "125", "126", "127", "128", "129", "130", "131", "132", "133", "134", "135", "136", "137", "138", "139", "140", "141", "142", "143", "144", "145", "146", "147", "148", "149", "150", "151", "152", "153", "154", "155", "156", "157", "158", "159", "160", "161", "162", "163", "164", "165", "166", "167", "168", "169", "170", "171", "172", "173", "174", "175", "176", "177", "178", "179", "180", "181", "182", "183", "184", "185", "186", "187", "188", "189", "190", "191", "192", "193", "194", "195", "196", "197", "198", "199", "200", "201", "202", "203", "204", "205", "206", "207", "208", "209", "210", "211", "212", "213", "214", "215", "216", "217", "218", "219", "220", "221", "222", "223", "224", "225", "226", "227", "228", "229", "230", "231", "232", "233", "234", "235", "236", "237", "238", "239", "240", "241", "242", "243", "244", "245", "246", "247", "248", "249", "250", "251", "252", "253", "254", "255"}

func (l *Line) appendIP6(ip net.IP) {
	startZ := -1
	endZ := -1

	// find longest zeroes
	for i := 0; i < 8; i++ {
		j := i
		for ; j < 8; j++ {
			if ip[j*2] != 0x00 || ip[j*2+1] != 0x00 {
				break
			}
			if zeros := j - i; zeros > 1 && zeros > endZ-startZ { // longer than previous ?
				startZ = i
				endZ = j
			}
		}
	}

	if endZ == startZ {
		startZ = 99
	}
	for i := 0; i < 8; i++ {
		if i == startZ {
			if startZ == 0 {
				l.appendByte(':')
			}
			l.appendByte(':')
			continue
		}
		if i >= startZ && i <= endZ {
			continue
		}
		if ip[i*2] != 0x00 {
			l.writeHexNoleadingZeros(ip[i*2])
			l.writeHex(ip[(i*2)+1])
		} else {
			l.writeHexNoleadingZeros(ip[(i*2)+1])
		}
		l.appendByte(':')
	}
	if endZ < 7 {
		l.index--
	}
}

func (l *Line) IP(name string, value net.IP) *Line {
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte('=')
	if value != nil {
		if ip := value.To4(); ip != nil {
			l.index = l.index + copy(l.buffer[l.index:], byteAscii[ip[0]])
			l.appendByte('.')
			l.index = l.index + copy(l.buffer[l.index:], byteAscii[ip[1]])
			l.appendByte('.')
			l.index = l.index + copy(l.buffer[l.index:], byteAscii[ip[2]])
			l.appendByte('.')
			l.index = l.index + copy(l.buffer[l.index:], byteAscii[ip[3]])
			return l
		}
		l.appendIP6(value)
		return l
	}
	l.index = l.index + copy(l.buffer[l.index:], "nil")
	return l
}

func (l *Line) appendByte(value byte) {
	l.buffer[l.index] = value
	l.index++
}

var hexAscii = []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

func (l *Line) writeHexNoleadingZeros(value byte) {
	if x := value >> 4; x != 0 {
		l.appendByte(hexAscii[x])
	}
	l.appendByte(hexAscii[value&0x0f])
}

func (l *Line) writeHex(value byte) {
	l.appendByte(hexAscii[value>>4])
	l.appendByte(hexAscii[value&0x0f])
}

// ByteArray log a []byte in hexadecimal
func (l *Line) ByteArray(name string, value []byte) *Line {
	truncated := false
	rem := cap(l.buffer) - l.index - 1 - len(name) - 2
	if rem <= len(value)*3 { // each byte occupies 3 characters
		copy(l.buffer[cap(l.buffer)-len("TRUNCATED "):], []byte("TRUNCATED "))
		rem = rem - len("TRUNCATED ")
		value = value[:rem/3]
		truncated = true
	}
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.index = l.index + copy(l.buffer[l.index:], "=[")
	for _, v := range value {
		l.writeHex(v)
		l.appendByte(' ')
	}
	l.index--
	l.appendByte(']')
	if truncated {
		l.index = cap(l.buffer) - 1
	}
	return l
}

/**
func Strings(data ...string) error {
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
*/
