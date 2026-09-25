package main

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// syncBuffer is written by the REPL and its event printer concurrently.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestREPL(t *testing.T) {
	in := strings.NewReader("put greeting hello world\nget greeting\nput\nadd x\nall\nnope\nquit\n")
	var out syncBuffer
	err := run(context.Background(), t.TempDir(), "/ip4/127.0.0.1/tcp/0", "", "demo", "keyvalue", true, in, &out)
	require.NoError(t, err)
	got := out.String()
	require.Contains(t, got, "address: /orbitdb/")
	require.Contains(t, got, "hello world\n")
	require.Contains(t, got, "usage: put <key> <value>")
	require.Contains(t, got, `"add" is not supported by keyvalue databases`)
	require.Contains(t, got, "greeting = hello world")
	require.Contains(t, got, `unknown command "nope"`)
}
