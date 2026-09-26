package syncutils

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/orbitdb/go-orbitdb/identities"
	"github.com/orbitdb/go-orbitdb/identities/identitytypes"
	"github.com/orbitdb/go-orbitdb/internal/block"
	"github.com/orbitdb/go-orbitdb/internal/testutil"
	"github.com/orbitdb/go-orbitdb/ipfs"
	"github.com/orbitdb/go-orbitdb/oplog"
	"github.com/orbitdb/go-orbitdb/storage"
)

func TestHeadsProtocolMatchesJavaScript(t *testing.T) {
	for _, m := range testutil.JSVectors(t).Manifests {
		require.Equal(t, m.HeadsProtocol, string(HeadsProtocol(m.Address)))
	}
	require.Equal(t, "/orbitdb/heads/orbitdb/x/", string(HeadsProtocol("/orbitdb/x/")), "a trailing slash is kept, as in JS")
	require.Equal(t, "orbitdb/orbitdb/zdpu/", posixJoin("./orbitdb", ".//orbitdb/zdpu/"))
	require.Equal(t, ".", posixJoin("./"))
}

func TestReadHeadsSplitsConcatenatedBlocks(t *testing.T) {
	var stream bytes.Buffer
	var want [][]byte
	for _, v := range []any{"a", map[string]any{"x": []any{1, 2, map[string]any{"y": []byte{1, 2}}}}, 1.5, nil, int64(1 << 40)} {
		_, data, err := block.Encode(v)
		require.NoError(t, err)
		want = append(want, data)
		stream.Write(data)
	}
	for _, e := range testutil.JSVectors(t).Entries {
		want = append(want, e.Bytes)
		stream.Write(e.Bytes)
	}
	got, err := readHeads(bufio.NewReader(&stream))
	require.NoError(t, err)
	require.Equal(t, want, got)

	empty, err := readHeads(bufio.NewReader(bytes.NewReader(nil)))
	require.NoError(t, err)
	require.Empty(t, empty)

	truncated := want[len(want)-1]
	_, err = readHeads(bufio.NewReader(bytes.NewReader(truncated[:len(truncated)-3])))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)

	_, err = readHeads(bufio.NewReader(bytes.NewReader([]byte{0x5f}))) // indefinite-length bytes
	require.Error(t, err)
}

type peerLog struct {
	node *ipfs.Node
	log  *oplog.Log
	sync *Sync

	mu     sync.Mutex
	joined []peer.ID
	left   []peer.ID
	errs   []error
}

func newPeerLog(t *testing.T, identity *identitytypes.Identity, logID string, start bool) *peerLog {
	t.Helper()
	ctx := context.Background()
	node, err := ipfs.New(ctx, ipfs.Options{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = node.Close() })
	entries, err := storage.NewIPFSBlockStorage(node.Blocks, storage.IPFSBlockStorageOptions{Timeout: 10 * time.Second})
	require.NoError(t, err)
	l, err := oplog.NewLog(ctx, identity, oplog.Options{LogID: logID, EntryStorage: entries})
	require.NoError(t, err)

	pl := &peerLog{node: node, log: l}
	pl.sync, err = New(Options{
		Host:   node.Host,
		PubSub: node.PubSub,
		Log:    l,
		OnSynced: func(ctx context.Context, e *oplog.Entry) {
			if _, err := l.JoinEntry(ctx, e); err != nil {
				pl.mu.Lock()
				pl.errs = append(pl.errs, err)
				pl.mu.Unlock()
			}
		},
		OnJoin: func(p peer.ID, _ []*oplog.Entry) {
			pl.mu.Lock()
			pl.joined = append(pl.joined, p)
			pl.mu.Unlock()
		},
		OnLeave: func(p peer.ID) {
			pl.mu.Lock()
			pl.left = append(pl.left, p)
			pl.mu.Unlock()
		},
		OnError: func(err error) {
			pl.mu.Lock()
			pl.errs = append(pl.errs, err)
			pl.mu.Unlock()
		},
		DisableAutoStart: !start,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pl.sync.Stop() })
	return pl
}

func (pl *peerLog) payloads(t *testing.T) []any {
	t.Helper()
	values, err := pl.log.Values(context.Background())
	require.NoError(t, err)
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v.Payload
	}
	return out
}

func identities2(t *testing.T) (*identitytypes.Identity, *identitytypes.Identity) {
	t.Helper()
	ids, err := identities.New(identities.Options{Keystore: testutil.Keystore(t)})
	require.NoError(t, err)
	a, err := ids.CreateIdentity(context.Background(), identities.CreateOptions{ID: "userA"})
	require.NoError(t, err)
	b, err := ids.CreateIdentity(context.Background(), identities.CreateOptions{ID: "userB"})
	require.NoError(t, err)
	return a, b
}

func TestReplicatesBetweenTwoPeers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	idA, idB := identities2(t)
	a := newPeerLog(t, idA, "/orbitdb/test-sync", true)
	b := newPeerLog(t, idB, "/orbitdb/test-sync", false)

	// a writes before b is around: b must get these through the heads
	// exchange, fetching the ancestors of the head over bitswap.
	for i := range 3 {
		_, err := a.log.Append(ctx, fmt.Sprint("a", i), oplog.AppendOptions{ReferencesCount: 16})
		require.NoError(t, err)
	}
	require.NoError(t, b.node.Connect(ctx, a.node.AddrInfo()))
	require.NoError(t, b.sync.Start())

	require.Eventually(t, func() bool { return len(b.payloads(t)) == 3 }, 30*time.Second, 50*time.Millisecond)
	require.Equal(t, []any{"a0", "a1", "a2"}, b.payloads(t))
	require.Eventually(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return len(b.joined) > 0
	}, 10*time.Second, 50*time.Millisecond, "OnJoin fires after the exchange")
	require.Contains(t, a.sync.Peers(), b.node.Host.ID())

	// Updates after the join travel over pubsub, both ways.
	e, err := b.log.Append(ctx, "b0", oplog.AppendOptions{ReferencesCount: 16})
	require.NoError(t, err)
	require.NoError(t, b.sync.Add(ctx, e))
	e, err = a.log.Append(ctx, "a3", oplog.AppendOptions{ReferencesCount: 16})
	require.NoError(t, err)
	require.NoError(t, a.sync.Add(ctx, e))

	require.Eventually(t, func() bool {
		return len(a.payloads(t)) == 5 && len(b.payloads(t)) == 5
	}, 30*time.Second, 50*time.Millisecond)
	require.Equal(t, a.payloads(t), b.payloads(t), "both peers converge on the same order")

	a.mu.Lock()
	require.Empty(t, a.errs)
	a.mu.Unlock()
	b.mu.Lock()
	require.Empty(t, b.errs)
	b.mu.Unlock()

	// When b stops syncing, a sees it leave.
	require.NoError(t, b.sync.Stop())
	require.Eventually(t, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return len(a.left) > 0
	}, 30*time.Second, 50*time.Millisecond)
	require.NotContains(t, a.sync.Peers(), b.node.Host.ID())
	require.NoError(t, b.sync.Stop(), "stopping twice is fine")
}

func TestPeerWithoutTheDatabaseIsIgnored(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	idA, idB := identities2(t)
	a := newPeerLog(t, idA, "/orbitdb/one", true)
	b := newPeerLog(t, idB, "/orbitdb/two", true)
	require.NoError(t, b.node.Connect(ctx, a.node.AddrInfo()))
	_, err := a.log.Append(ctx, "x", oplog.AppendOptions{})
	require.NoError(t, err)
	time.Sleep(500 * time.Millisecond)
	require.Empty(t, b.payloads(t))
	require.Empty(t, a.sync.Peers())
	a.mu.Lock()
	require.Empty(t, a.errs)
	a.mu.Unlock()
}

func TestConcurrentStartStop(t *testing.T) {
	// Start and Stop from several goroutines while a peer keeps opening
	// heads exchanges: runs must never overlap (a WaitGroup reused across
	// runs would panic, and re-joining the topic before the old one is
	// closed would fail).
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	idA, idB := identities2(t)
	a := newPeerLog(t, idA, "/orbitdb/churn", true)
	b := newPeerLog(t, idB, "/orbitdb/churn", true)
	require.NoError(t, b.node.Connect(ctx, a.node.AddrInfo()))
	_, err := b.log.Append(ctx, "x", oplog.AppendOptions{})
	require.NoError(t, err)

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				require.NoError(t, a.sync.Stop())
				require.NoError(t, a.sync.Start())
			}
		}()
	}
	wg.Wait()
	require.NoError(t, a.sync.Start())
	require.Eventually(t, func() bool { return len(a.payloads(t)) == 1 }, 30*time.Second, 50*time.Millisecond,
		"after the churn, sync still works")
}

func TestNewValidates(t *testing.T) {
	_, err := New(Options{})
	require.Error(t, err)
}

func TestAddBeforeStartIsNoop(t *testing.T) {
	idA, _ := identities2(t)
	a := newPeerLog(t, idA, "/orbitdb/idle", false)
	e, err := a.log.Append(context.Background(), "x", oplog.AppendOptions{})
	require.NoError(t, err)
	require.NoError(t, a.sync.Add(context.Background(), e))
	require.Empty(t, a.sync.Peers())
}
