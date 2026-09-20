package main

import (
	"bytes"
	"io"
	"strings"
)

// maxConfigBytes bounds the config file too. It is ours rather than a caller's,
// but an unbounded read is an unbounded read.
const maxConfigBytes = 16 << 10

func newLimitedReader(b []byte) io.Reader {
	return io.LimitReader(bytes.NewReader(b), maxConfigBytes)
}

// trimNewline strips the trailing newline a file almost always has, without
// touching a password that legitimately contains spaces.
func trimNewline(s string) string { return strings.TrimRight(s, "\r\n") }
