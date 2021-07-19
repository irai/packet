package fastlog

import (
	"io"
	"os"
)

type Logger struct {
	out io.Writer
}

var std = &Logger{out: os.Stderr}

func Strings(data ...string) error {
	for _, v := range data {
		std.out.Write([]byte(v))
	}
	_, err := std.out.Write([]byte{'\n'})
	return err
}
