package storage

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ipfs/boxo/blockservice"
	"github.com/ipfs/boxo/blockstore"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/go-datastore"
	dssync "github.com/ipfs/go-datastore/sync"
	"github.com/multiformats/go-multibase"
	mh "github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/require"
)

func newBlockService() blockservice.BlockService {
	bs := blockstore.NewBlockstore(dssync.MutexWrap(datastore.NewMapDatastore()))
	return blockservice.New(bs, nil)
}

// dagCBORKey returns the base58btc CIDv1 dag-cbor key OrbitDB would use for
// data.
func dagCBORKey(t *testing.T, data []byte) string {
	t.Helper()
	sum, err := mh.Sum(data, mh.SHA2_256, -1)
	require.NoError(t, err)
	s, err := cid.NewCidV1(cid.DagCBOR, sum).StringOfBase(multibase.Base58BTC)
	require.NoError(t, err)
	return s
}

type recordingPinner struct {
	mu     sync.Mutex
	pinned map[cid.Cid]int
}

func (p *recordingPinner) IsPinned(_ context.Context, c cid.Cid) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pinned[c] > 0, nil
}

func (p *recordingPinner) Pin(_ context.Context, c cid.Cid) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pinned[c]++
	return nil
}

func TestIPFSBlockStoragePutGet(t *testing.T) {
	ctx := context.Background()
	pinner := &recordingPinner{pinned: map[cid.Cid]int{}}
	s, err := NewIPFSBlockStorage(newBlockService(), IPFSBlockStorageOptions{Pinner: pinner})
	require.NoError(t, err)
	defer s.Close()

	data := []byte{0xa1, 0x61, 0x61, 0x01} // dag-cbor {"a": 1}
	key := dagCBORKey(t, data)
	require.NoError(t, s.Put(ctx, key, data))

	got, err := s.Get(ctx, key)
	require.NoError(t, err)
	require.Equal(t, data, got)

	c, _ := cid.Decode(key)
	require.Equal(t, 1, pinner.pinned[c], "put pins the block")
	require.NoError(t, s.Persist(ctx, key))
	require.Equal(t, 1, pinner.pinned[c], "an already pinned block is not pinned again")
}

func TestIPFSBlockStorageRejectsMismatchedData(t *testing.T) {
	s, err := NewIPFSBlockStorage(newBlockService(), IPFSBlockStorageOptions{})
	require.NoError(t, err)
	key := dagCBORKey(t, []byte{0x01})
	require.ErrorContains(t, s.Put(context.Background(), key, []byte{0x02}), "does not match")
}

func TestIPFSBlockStorageInvalidKey(t *testing.T) {
	s, err := NewIPFSBlockStorage(newBlockService(), IPFSBlockStorageOptions{})
	require.NoError(t, err)
	require.ErrorContains(t, s.Put(context.Background(), "not-a-cid", []byte{1}), "invalid CID")
	_, err = s.Get(context.Background(), "not-a-cid")
	require.ErrorContains(t, err, "invalid CID")
}

func TestIPFSBlockStorageMissingBlock(t *testing.T) {
	s, err := NewIPFSBlockStorage(newBlockService(), IPFSBlockStorageOptions{})
	require.NoError(t, err)
	_, err = s.Get(context.Background(), dagCBORKey(t, []byte{0x07}))
	require.ErrorIs(t, err, ErrNotFound)
}

// blockingService never finds a block, like a bitswap exchange with no peer
// that has it.
type blockingService struct{}

func (blockingService) GetBlock(ctx context.Context, _ cid.Cid) (blocks.Block, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (blockingService) AddBlock(context.Context, blocks.Block) error { return nil }

func TestIPFSBlockStorageTimeoutAndClose(t *testing.T) {
	s, err := NewIPFSBlockStorage(blockingService{}, IPFSBlockStorageOptions{Timeout: 50 * time.Millisecond})
	require.NoError(t, err)
	start := time.Now()
	_, err = s.Get(context.Background(), dagCBORKey(t, []byte{0x07}))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 5*time.Second)

	s, err = NewIPFSBlockStorage(blockingService{}, IPFSBlockStorageOptions{Timeout: time.Hour})
	require.NoError(t, err)
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = s.Close()
	}()
	_, err = s.Get(context.Background(), dagCBORKey(t, []byte{0x07}))
	require.ErrorIs(t, err, context.Canceled, "Close aborts in-flight gets")
}

func TestIPFSBlockStorageNoOps(t *testing.T) {
	ctx := context.Background()
	s, err := NewIPFSBlockStorage(newBlockService(), IPFSBlockStorageOptions{})
	require.NoError(t, err)
	data := []byte{0x01}
	key := dagCBORKey(t, data)
	require.NoError(t, s.Put(ctx, key, data))
	require.NoError(t, s.Del(ctx, key))
	require.NoError(t, s.Clear(ctx))
	require.NoError(t, s.Merge(ctx, NewMemoryStorage()))
	_, err = s.Get(ctx, key)
	require.NoError(t, err, "blocks are content-addressed and never deleted")
	require.Empty(t, collect(t, s, IteratorOptions{}))
}
