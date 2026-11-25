package modelbroker

import (
	"io"
	"strings"
	"testing"
)

func TestOllamaOutputCapCannotBeBypassedByWriterInterfaces(t *testing.T) {
	for _, write := range []func(io.Writer) (int64, error){
		func(w io.Writer) (int64, error) {
			n, err := io.WriteString(w, strings.Repeat("a", 4096))
			return int64(n), err
		},
		func(w io.Writer) (int64, error) {
			// Hide WriterTo so io.Copy would use a promoted ReaderFrom.
			return io.Copy(w, struct{ io.Reader }{strings.NewReader(strings.Repeat("a", 4096))})
		},
	} {
		b := &boundedOllamaBuffer{limit: 16}
		if n, err := write(b); err != nil || n != 4096 || len(b.Bytes()) != 16 || !b.overflow {
			t.Fatalf("copied=%d kept=%d overflow=%v err=%v", n, len(b.Bytes()), b.overflow, err)
		}
	}
}
