package ipfs_test

import (
	"context"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"

	"github.com/orbitdb/go-orbitdb/internal/block"
	"github.com/orbitdb/go-orbitdb/ipfs"
	"github.com/orbitdb/go-orbitdb/storage"
)

func newNode(t *testing.T) *ipfs.Node {
	t.Helper()
	n, err := ipfs.New(context.Background(), ipfs.Options{})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, n.Close()) })
	return n
}

func TestBlocksAreFetchedFromPeers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, b := newNode(t), newNode(t)
	require.NoError(t, b.Connect(ctx, a.AddrInfo()))

	storeA, err := storage.NewIPFSBlockStorage(a.Blocks, storage.IPFSBlockStorageOptions{Pinner: a.Pins})
	require.NoError(t, err)
	storeB, err := storage.NewIPFSBlockStorage(b.Blocks, storage.IPFSBlockStorageOptions{Pinner: b.Pins, Timeout: 20 * time.Second})
	require.NoError(t, err)

	hash, data, err := block.Encode(map[string]any{"hello": "world"})
	require.NoError(t, err)
	require.NoError(t, storeA.Put(ctx, hash, data))

	got, err := storeB.Get(ctx, hash)
	require.NoError(t, err, "b fetches the block from a over bitswap")
	require.Equal(t, data, got)

	pinned, err := a.Pins.IsPinned(ctx, mustCID(t, hash))
	require.NoError(t, err)
	require.True(t, pinned)
}

func TestRepoPersistsBlocks(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	n, err := ipfs.New(ctx, ipfs.Options{Repo: repo})
	require.NoError(t, err)
	s, err := storage.NewIPFSBlockStorage(n.Blocks, storage.IPFSBlockStorageOptions{Pinner: n.Pins})
	require.NoError(t, err)
	hash, data, err := block.Encode("persisted")
	require.NoError(t, err)
	require.NoError(t, s.Put(ctx, hash, data))
	require.NoError(t, n.Close())

	n, err = ipfs.New(ctx, ipfs.Options{Repo: repo})
	require.NoError(t, err)
	defer n.Close()
	s, err = storage.NewIPFSBlockStorage(n.Blocks, storage.IPFSBlockStorageOptions{Timeout: time.Second})
	require.NoError(t, err)
	got, err := s.Get(ctx, hash)
	require.NoError(t, err)
	require.Equal(t, data, got)
	pinned, err := n.Pins.IsPinned(ctx, mustCID(t, hash))
	require.NoError(t, err)
	require.True(t, pinned, "pins persist too")
}

func TestMissingBlockTimesOut(t *testing.T) {
	a := newNode(t)
	s, err := storage.NewIPFSBlockStorage(a.Blocks, storage.IPFSBlockStorageOptions{Timeout: 200 * time.Millisecond})
	require.NoError(t, err)
	hash, _, err := block.Encode("nobody has this")
	require.NoError(t, err)
	_, err = s.Get(context.Background(), hash)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func mustCID(t *testing.T, hash string) cid.Cid {
	t.Helper()
	c, err := cid.Decode(hash)
	require.NoError(t, err)
	return c
}
