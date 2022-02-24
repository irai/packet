package fastlog

import (
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Package fastlog implements a simple, fast logger for hotpath logging. It is
// 2.x times faster than using fmt.Printf().
//
// It achieves this by:
//  - avoiding type introspection
//  - Writting directly to in memory buffer - no string conversion
//  - specialised types for MAC/IP/Int writing directly to buffer
//  - multiline logging in a single write
//  - minimum validation - assumes the caller is passing valid types and valid len
//  - assumes a max fixed memory buffer len of 2048k per message - ie. it will segfault if the caller passes longer data
//  - pool of reusable buffers
//
// Results: Jan 2022
// cpu: 11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz
// Benchmark_Fastlog/printf_struct_reference-8         	 1693278	       705.4 ns/op	     344 B/op	       8 allocs/op
// Benchmark_Fastlog/fastlog_struct_reference-8        	 6253689	       173.1 ns/op	     144 B/op	       1 allocs/op
// Benchmark_Fastlog/some_alloc-8                      	 5560839	       214.9 ns/op	     152 B/op	       2 allocs/op
// Benchmark_Fastlog/zero_alloc-8                      	 2933750	       433.3 ns/op	       0 B/op	       0 allocs/op

// bufSize sets the maximum len for a log entry
const bufSize = 2048

// type LogLevel struct {
// l int32
// }
type LogLevel uint32

const (
	LevelError = LogLevel(0)
	LevelInfo  = LogLevel(1)
	LevelDebug = LogLevel(2)
)

func (l LogLevel) String() string {
	switch l {
	case LevelError:
		return "error"
	case LevelInfo:
		return "info"
	}
	return "debug"
}

var lines = sync.Pool{New: func() interface{} { return new(Line) }}

type Logger struct {
	Out    io.Writer
	module string
	level  uint32 // atomic int32
}

type FastLog interface {
	FastLog(*Line) *Line
}

type Line struct {
	buffer [bufSize]byte
	index  int
}

var Std = New("logger")

func Str2LogLevel(level string) LogLevel {
	switch strings.ToLower(level) {
	case "info":
		return LevelInfo
	case "debug":
		return LevelDebug
	}
	return LevelError
}

func (l *Logger) Level() LogLevel {
	return LogLevel(atomic.LoadUint32(&l.level))
}

func (l *Logger) SetLevel(level LogLevel) {
	atomic.StoreUint32(&l.level, uint32(level))
}

func (l *Logger) Disable() {
	atomic.StoreUint32(&l.level, uint32(LevelError))
}

func (l *Logger) EnableInfo() {
	atomic.StoreUint32(&l.level, uint32(LevelInfo))
}

func (l *Logger) IsInfo() bool {
	return atomic.LoadUint32(&l.level) >= uint32(LevelInfo)
}

func (l *Logger) EnableDebug() {
	atomic.StoreUint32(&l.level, uint32(LevelDebug))
}

func (l *Logger) IsDebug() bool {
	return atomic.LoadUint32(&l.level) >= uint32(LevelDebug)
}

func New(module string) *Logger {
	return NewOut(os.Stderr, module)
}

func NewOut(out io.Writer, module string) *Logger {
	return &Logger{
		Out:    out,
		module: module,
	}
}

func NewLine(module string, msg string) *Line {
	return Std.NewLine(module, msg)
}

func (logger *Logger) Msg(msg string) *Line {
	return logger.NewLine(logger.module, msg)
}

func (logger *Logger) NewLine(module string, msg string) *Line {
	l := lines.Get().(*Line)
	l.index = 0
	return l.newModule(module, msg)
}

func (l *Line) Module(name string, msg string) *Line {
	l.appendByte('\n')
	return l.newModule(name, msg)
}

func (l *Line) newModule(module string, msg string) *Line {
	if module != "" {
		copy(l.buffer[l.index:], "      :")
		copy(l.buffer[l.index:l.index+6], module)
		l.index = l.index + 7
	}
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

// ToString converts the buffer to string and return the buffer to the pool.
// The buffer is no longer available after calling this function.
func (l *Line) ToString() string {
	str := string(l.buffer[:l.index])
	l.index = copy(l.buffer[:], "invalid buffer freed via ToString()") // guarding against reuse by caller
	lines.Put(l)
	return str
}

// Write writes the buffer and return the buffer to the pool.
// The buffer is no longer available after calling this function.
func (l *Line) Write() error {
	if l.index >= len(l.buffer) { // add as last character
		l.index--
	}
	l.buffer[l.index] = '\n'
	_, err := Std.Out.Write(l.buffer[:l.index+1])
	l.index = copy(l.buffer[:], "invalid buffer freed via Write()") // guarding against reuse by caller
	lines.Put(l)
	return err
}

func (l *Line) String(name string, value string) *Line {
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte('=')
	l.appendByte('"')
	l.index = l.index + copy(l.buffer[l.index:], value)
	if l.index == cap(l.buffer) { // prevent segfault for long strings
		l.index--
	}
	l.appendByte('"')
	return l
}

func (l *Line) StringArray(name string, value []string) *Line {
	if l.index+len(name)+4 > cap(l.buffer) {
		return l
	}
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte('=')
	l.appendByte('[')
	if len(value) <= 0 {
		l.appendByte(']')
		return l
	}

	for _, v := range value {
		if l.index+len(v)+4 > cap(l.buffer) {
			break
		}
		l.appendByte('"')
		l.index = l.index + copy(l.buffer[l.index:], v)
		l.appendByte('"')
		l.appendByte(',')
		l.appendByte(' ')
	}
	l.index--
	l.appendByte(']')
	return l
}

// Bytes append an unmodified byte string to line.
func (l *Line) Bytes(name string, value []byte) *Line {
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte('=')
	l.index = l.index + copy(l.buffer[l.index:], value)
	return l
}

// Label adds a static string to the line
func (l *Line) Label(name string) *Line {
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	return l
}

func (l *Line) Error(value error) *Line {
	l.index = l.index + copy(l.buffer[l.index:], " error=[")
	l.index = l.index + copy(l.buffer[l.index:], value.Error())
	l.appendByte(']')
	return l
}

func (l *Line) Bool(name string, value bool) *Line {
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte('=')
	if value {
		l.index = l.index + copy(l.buffer[l.index:], "true")
	} else {
		l.index = l.index + copy(l.buffer[l.index:], "false")
	}
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

func (l *Line) Struct(value FastLog) *Line {
	if value == nil || (reflect.ValueOf(value).Kind() == reflect.Ptr && reflect.ValueOf(value).IsNil()) {
		return l
	}
	return value.FastLog(l)
}

func (l *Line) Stringer(value fmt.Stringer) *Line {
	if value == nil || (reflect.ValueOf(value).Kind() == reflect.Ptr && reflect.ValueOf(value).IsNil()) {
		return l
	}
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], value.String())
	return l
}

func (l *Line) Duration(name string, duration time.Duration) *Line {
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], duration.String())
	return l
}

func (l *Line) Time(name string, t time.Time) *Line {
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte(' ')
	tmp := make([]byte, 0, 64)
	tmp = t.AppendFormat(tmp, time.StampMilli)
	// l.index = l.index + copy(l.buffer[l.index:], time.String())
	l.index = l.index + copy(l.buffer[l.index:], tmp)
	return l
}

func (l *Line) Sprintf(name string, value interface{}) *Line {
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], fmt.Sprintf("%+v", value))
	return l
}

// printUint32 copied from https://cs.opensource.google/go/x/net/+/master:dns/dnsmessage/message.go
func (l *Line) printUint32(value uint32) *Line {
	// Max value is 4294967295.
	buf := make([]byte, 10)
	for b, d := buf, uint32(1000000000); d > 0; d /= 10 {
		b[0] = byte(value/d%10 + '0')
		if b[0] == '0' && len(b) == len(buf) && len(buf) > 1 {
			buf = buf[1:]
		}
		b = b[1:]
		value %= d
	}
	l.index = l.index + copy(l.buffer[l.index:], buf)
	return l
}

func (l *Line) Uint8(name string, value uint8) *Line {
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte('=')
	l.index = l.index + copy(l.buffer[l.index:], byteAscii[value])
	return l
}

func (l *Line) Uint8Hex(name string, value uint8) *Line {
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte('=')
	l.appendByte('0')
	l.appendByte('x')
	l.appendByte(hexAscii[(value>>4)&0x0f])
	l.appendByte(hexAscii[value&0x0f])
	return l
}

func (l *Line) Uint16(name string, value uint16) *Line {
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte('=')
	l.printUint32(uint32(value))
	return l
}

func (l *Line) Uint32(name string, value uint32) *Line {
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte('=')
	l.printUint32(uint32(value))
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
	tmp := make([]byte, 0, 24)                     // zero allocation
	tmp = strconv.AppendInt(tmp, int64(value), 10) // zero allocation
	l.index = l.index + copy(l.buffer[l.index:], tmp)
	// l.index = l.index + copy(l.buffer[l.index:], strconv.Itoa(value))
	return l
}

var byteAscii = []string{
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "100", "101", "102", "103", "104", "105", "106", "107", "108", "109", "110", "111", "112", "113", "114", "115", "116", "117", "118", "119", "120", "121", "122", "123", "124", "125", "126", "127", "128", "129", "130", "131", "132", "133", "134", "135", "136", "137", "138", "139", "140", "141", "142", "143", "144", "145", "146", "147", "148", "149", "150", "151", "152", "153", "154", "155", "156", "157", "158", "159", "160", "161", "162", "163", "164", "165", "166", "167", "168", "169", "170", "171", "172", "173", "174", "175", "176", "177", "178", "179", "180", "181", "182", "183", "184", "185", "186", "187", "188", "189", "190", "191", "192", "193", "194", "195", "196", "197", "198", "199", "200", "201", "202", "203", "204", "205", "206", "207", "208", "209", "210", "211", "212", "213", "214", "215", "216", "217", "218", "219", "220", "221", "222", "223", "224", "225", "226", "227", "228", "229", "230", "231", "232", "233", "234", "235", "236", "237", "238", "239", "240", "241", "242", "243", "244", "245", "246", "247", "248", "249", "250", "251", "252", "253", "254", "255"}

func (l *Line) appendIP6(ip net.IP) {
	if len(ip) != net.IPv6len {
		l.index = l.index + copy(l.buffer[l.index:], "nil")
		return
	}
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

func (l *Line) IPArray(name string, value []net.IP) *Line {
	if l.index+len(name)+4 > cap(l.buffer) {
		return l
	}
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte('=')
	l.appendByte('[')
	if len(value) <= 0 {
		l.appendByte(']')
		return l
	}

	for _, v := range value {
		if l.index+28+2 > cap(l.buffer) { // assume longest IP len 4*8+4
			break
		}
		if v != nil {
			if ip := v.To4(); ip != nil {
				l.index = l.index + copy(l.buffer[l.index:], byteAscii[ip[0]])
				l.appendByte('.')
				l.index = l.index + copy(l.buffer[l.index:], byteAscii[ip[1]])
				l.appendByte('.')
				l.index = l.index + copy(l.buffer[l.index:], byteAscii[ip[2]])
				l.appendByte('.')
				l.index = l.index + copy(l.buffer[l.index:], byteAscii[ip[3]])
				return l
			}
			l.appendIP6(v)
		}
		l.appendByte(',')
		l.appendByte(' ')
	}
	l.index--
	l.appendByte(']')
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
	if len(value) > 0 {
		l.index--
	}
	l.appendByte(']')
	if truncated {
		l.index = cap(l.buffer) - 1
	}
	return l
}

/**
[]interface() does not compile - this is a go design
...Fastlog does not work either

func (l *Line) FastLogArray(name string, value []interface{}) *Line {
	if l.index+len(name)+4 > cap(l.buffer) {
		return l
	}
	l.appendByte(' ')
	l.index = l.index + copy(l.buffer[l.index:], name)
	l.appendByte('=')
	l.appendByte('[')
	if len(value) <= 0 {
		l.appendByte(']')
		return l
	}

	tmp := Line{}
	for _, v := range value {
		tmp.index = 0
		if fl, ok := v.(FastLog); ok {
			fl.FastLog(&tmp)
		} else {
			tmp.index = tmp.index + copy(tmp.buffer[tmp.index:], "invalid fastlog interface")
		}
		if l.index+tmp.index+4 > cap(l.buffer) {
			break
		}
		l.appendByte('{')
		l.index = l.index + copy(l.buffer[l.index:], tmp.buffer[:tmp.index])
		l.appendByte('}')
		l.appendByte(',')
		l.appendByte(' ')
	}
	l.index--
	l.appendByte(']')
	return l
}

**/
