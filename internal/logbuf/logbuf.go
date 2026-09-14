// Package logbuf provides a bounded in-memory ring of recent log lines. It
// implements io.Writer so it can tee the standard logger's output, and it is
// what the admin panel reads: the most recent lines only, gone on restart.
package logbuf

import (
	"strings"
	"sync"
)

// Line is one captured log line. Seq increases monotonically from 1, so a
// client that remembers the last Seq it saw can ask for everything newer.
type Line struct {
	Seq  uint64
	Text string
}

// Buffer is a fixed-capacity ring of log lines. The zero value is not usable;
// call New.
type Buffer struct {
	mu    sync.Mutex
	lines []Line
	start int // index of the oldest line
	count int
	seq   uint64
}

func New(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = 1
	}
	return &Buffer{lines: make([]Line, capacity)}
}

// Write implements io.Writer. The standard logger emits one formatted line
// per Write call, so each call normally becomes one entry (with the trailing
// newline removed); multi-line payloads are split rather than stored raw.
func (b *Buffer) Write(p []byte) (int, error) {
	for _, text := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if text == "" {
			continue
		}
		b.append(text)
	}
	return len(p), nil
}

func (b *Buffer) append(text string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	idx := (b.start + b.count) % len(b.lines)
	if b.count == len(b.lines) {
		b.start = (b.start + 1) % len(b.lines) // overwrite the oldest
	} else {
		b.count++
	}
	b.lines[idx] = Line{Seq: b.seq, Text: text}
}

// Since returns all buffered lines with Seq > after, oldest first.
func (b *Buffer) Since(after uint64) []Line {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Line, 0, b.count)
	for i := 0; i < b.count; i++ {
		line := b.lines[(b.start+i)%len(b.lines)]
		if line.Seq > after {
			out = append(out, line)
		}
	}
	return out
}
