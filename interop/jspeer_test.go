//go:build interop

package interop

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

// jsPeer drives interop/js-peer/peer.mjs, an @orbitdb/core 4.0.0 node.
type jsPeer struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  chan string
	nextID int

	PeerID   string
	Addrs    []string
	Identity struct {
		ID        string `json:"id"`
		Hash      string `json:"hash"`
		PublicKey string `json:"publicKey"`
	}
}

func startJSPeer(t *testing.T) *jsPeer {
	t.Helper()
	dir, err := filepath.Abs("js-peer")
	require.NoError(t, err)
	if _, err := exec.LookPath("node"); err != nil {
		skipOrFail(t, "node is not installed")
	}
	if _, err := os.Stat(filepath.Join(dir, "node_modules", "@orbitdb", "core")); err != nil {
		skipOrFail(t, "run `npm ci` in interop/js-peer first")
	}

	cmd := exec.Command("node", "peer.mjs")
	cmd.Dir = dir
	cmd.Stderr = testWriter{t}
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	p := &jsPeer{t: t, cmd: cmd, stdin: stdin, lines: make(chan string, 16)}
	go func() {
		defer close(p.lines)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		for sc.Scan() {
			p.lines <- sc.Text()
		}
	}()
	t.Cleanup(p.stop)

	var ready string
	p.await(0, &ready)
	require.Equal(t, "ready", ready)

	var info struct {
		PeerID   string   `json:"peerId"`
		Addrs    []string `json:"addrs"`
		Identity json.RawMessage
	}
	p.call("info", nil, &info)
	p.PeerID, p.Addrs = info.PeerID, info.Addrs
	require.NoError(t, json.Unmarshal(info.Identity, &p.Identity))
	return p
}

func skipOrFail(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("ORBITDB_INTEROP_REQUIRED") != "" {
		t.Fatal(reason)
	}
	t.Skip(reason)
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) {
	w.t.Logf("%s", b)
	return len(b), nil
}

// call sends a command and decodes its result into out (which may be nil).
func (p *jsPeer) call(cmd string, args any, out any) {
	p.t.Helper()
	if err := p.try(cmd, args, out); err != nil {
		p.t.Fatalf("js %s: %v", cmd, err)
	}
}

// try sends a command and returns the JS error, if any.
func (p *jsPeer) try(cmd string, args any, out any) error {
	p.t.Helper()
	p.nextID++
	id := p.nextID
	req, err := json.Marshal(map[string]any{"id": id, "cmd": cmd, "args": args})
	require.NoError(p.t, err)
	_, err = p.stdin.Write(append(req, '\n'))
	require.NoError(p.t, err)
	return p.await(id, out)
}

func (p *jsPeer) await(id int, out any) error {
	p.t.Helper()
	timeout := time.After(90 * time.Second)
	for {
		select {
		case line, ok := <-p.lines:
			require.True(p.t, ok, "js peer exited")
			var resp struct {
				ID     int             `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  string          `json:"error"`
			}
			require.NoError(p.t, json.Unmarshal([]byte(line), &resp), line)
			if resp.ID != id {
				p.t.Logf("js: ignoring response %s", line)
				continue
			}
			if resp.Error != "" {
				return fmt.Errorf("%s", resp.Error)
			}
			if out != nil {
				require.NoError(p.t, json.Unmarshal(resp.Result, out), line)
			}
			return nil
		case <-timeout:
			p.t.Fatalf("js peer did not answer request %d", id)
		}
	}
}

// requireNoErrors fails if the JS databases reported errors, e.g. entries
// from Go they could not decode or verify.
func (p *jsPeer) requireNoErrors() {
	p.t.Helper()
	var errs []string
	p.call("errors", nil, &errs)
	require.Empty(p.t, errs, "errors reported by the JS peer")
}

func (p *jsPeer) addrInfo() peer.AddrInfo {
	p.t.Helper()
	addr, err := ma.NewMultiaddr(p.Addrs[0])
	require.NoError(p.t, err)
	info, err := peer.AddrInfoFromP2pAddr(addr)
	require.NoError(p.t, err)
	return *info
}

func (p *jsPeer) stop() {
	_ = p.try("stop", nil, nil)
	_ = p.stdin.Close()
	done := make(chan struct{})
	go func() {
		_ = p.cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
