//go:build windows

package main

import (
	"io"
	"strings"
	"testing"
)

func TestBridgeBufferCapCannotBeBypassedByWriterInterfaces(t *testing.T) {
	for _, write := range []func(io.Writer) (int64, error){
		func(w io.Writer) (int64, error) {
			n, err := io.WriteString(w, strings.Repeat("a", bridgeOutputLimit+1))
			return int64(n), err
		},
		func(w io.Writer) (int64, error) {
			return io.Copy(w, struct{ io.Reader }{strings.NewReader(strings.Repeat("a", bridgeOutputLimit+1))})
		},
	} {
		b := &boundedBridgeBuffer{}
		if n, err := write(b); err != nil || n != int64(bridgeOutputLimit+1) || len(b.Bytes()) != bridgeOutputLimit || !b.truncated {
			t.Fatalf("copied=%d kept=%d truncated=%v err=%v", n, len(b.Bytes()), b.truncated, err)
		}
	}
}
