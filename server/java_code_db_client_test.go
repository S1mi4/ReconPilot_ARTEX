package server

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadTaskJavaCodeDBLineHandlesLongAndOversizedLines(t *testing.T) {
	long := strings.Repeat("a", 200_000)
	reader := bufio.NewReaderSize(strings.NewReader(long+"\nnext\n"), 4096)
	line, err := readTaskJavaCodeDBLine(reader, 1<<20)
	if err != nil || strings.TrimSpace(string(line)) != long {
		t.Fatalf("long line: len=%d err=%v", len(line), err)
	}
	line, err = readTaskJavaCodeDBLine(reader, 1<<20)
	if err != nil || strings.TrimSpace(string(line)) != "next" {
		t.Fatalf("next line = %q err=%v", line, err)
	}
	oversized := bufio.NewReaderSize(strings.NewReader(strings.Repeat("b", 10_000)+"\n"), 1024)
	if _, err := readTaskJavaCodeDBLine(oversized, 4096); err == nil {
		t.Fatal("oversized line was accepted")
	}
}
