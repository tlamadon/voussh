package logbuf

import (
	"fmt"
	"log"
	"strings"
	"testing"
)

func texts(lines []Line) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = l.Text
	}
	return out
}

func TestWriteAndSince(t *testing.T) {
	b := New(10)
	for i := 1; i <= 3; i++ {
		fmt.Fprintf(b, "line %d\n", i)
	}

	got := b.Since(0)
	if len(got) != 3 {
		t.Fatalf("Since(0) returned %d lines, want 3", len(got))
	}
	for i, l := range got {
		if want := fmt.Sprintf("line %d", i+1); l.Text != want {
			t.Errorf("line %d = %q, want %q", i, l.Text, want)
		}
		if l.Seq != uint64(i+1) {
			t.Errorf("seq = %d, want %d", l.Seq, i+1)
		}
	}

	// Incremental polling: only lines newer than the given seq come back.
	newer := b.Since(got[1].Seq)
	if len(newer) != 1 || newer[0].Text != "line 3" {
		t.Errorf("Since(%d) = %v, want [line 3]", got[1].Seq, texts(newer))
	}
	if len(b.Since(got[2].Seq)) != 0 {
		t.Error("Since(latest) should be empty")
	}
}

func TestWraparoundDropsOldest(t *testing.T) {
	b := New(3)
	for i := 1; i <= 5; i++ {
		fmt.Fprintf(b, "line %d\n", i)
	}

	got := b.Since(0)
	if want := []string{"line 3", "line 4", "line 5"}; fmt.Sprint(texts(got)) != fmt.Sprint(want) {
		t.Errorf("after wraparound = %v, want %v", texts(got), want)
	}
	// Seq keeps counting across the wrap, so a client that saw dropped lines
	// still resumes correctly.
	if got[0].Seq != 3 || got[2].Seq != 5 {
		t.Errorf("seqs = %d..%d, want 3..5", got[0].Seq, got[2].Seq)
	}
}

// The buffer's whole purpose is to sit behind log.SetOutput.
func TestAsLoggerOutput(t *testing.T) {
	b := New(10)
	logger := log.New(b, "", log.LstdFlags)
	logger.Printf("hello %s", "world")

	got := b.Since(0)
	if len(got) != 1 {
		t.Fatalf("got %d lines, want 1", len(got))
	}
	if want := "hello world"; !strings.Contains(got[0].Text, want) {
		t.Errorf("line %q does not contain %q", got[0].Text, want)
	}
}
