package storage

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"time"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	ipld "github.com/ipfs/go-ipld-format"
)

// DefaultIPFSTimeout bounds a single block Get or Put, matching the 30s
// default of @orbitdb/core.
const DefaultIPFSTimeout = 30 * time.Second

// BlockService is the subset of a block service IPFSBlockStorage needs.
// boxo's blockservice.BlockService satisfies it; with a bitswap exchange
// attached, Get fetches blocks the local node does not have from peers.
type BlockService interface {
	GetBlock(ctx context.Context, c cid.Cid) (blocks.Block, error)
	AddBlock(ctx context.Context, b blocks.Block) error
}

// Pinner pins blocks so a garbage-collecting blockstore keeps them.
type Pinner interface {
	IsPinned(ctx context.Context, c cid.Cid) (bool, error)
	Pin(ctx context.Context, c cid.Cid) error
}

// IPFSBlockStorage stores values as IPFS blocks keyed by their CID. Keys are
// CID strings (OrbitDB uses base58btc CIDv1 dag-cbor hashes). Values are
// verified against the key's multihash before being stored, so a peer cannot
// plant bytes under a hash they do not match.
//
// Like @orbitdb/core, Del, Iterator, Merge and Clear are no-ops: blocks are
// content-addressed and may be shared with other databases.
type IPFSBlockStorage struct {
	blocks  BlockService
	pinner  Pinner
	timeout time.Duration

	shutdown context.Context
	cancel   context.CancelFunc
}

// IPFSBlockStorageOptions configures NewIPFSBlockStorage.
type IPFSBlockStorageOptions struct {
	// Pinner, if set, is used to pin every block that is put or persisted.
	Pinner Pinner
	// Timeout bounds each Get and Put. Zero means DefaultIPFSTimeout.
	Timeout time.Duration
}

// NewIPFSBlockStorage returns a storage backed by bs.
func NewIPFSBlockStorage(bs BlockService, opts IPFSBlockStorageOptions) (*IPFSBlockStorage, error) {
	if bs == nil {
		return nil, errors.New("storage: a block service is required")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultIPFSTimeout
	}
	shutdown, cancel := context.WithCancel(context.Background())
	return &IPFSBlockStorage{
		blocks:   bs,
		pinner:   opts.Pinner,
		timeout:  opts.Timeout,
		shutdown: shutdown,
		cancel:   cancel,
	}, nil
}

// withTimeout derives a context that ends at the per-call timeout, when ctx
// ends, or when the storage is closed.
func (s *IPFSBlockStorage) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	stop := context.AfterFunc(s.shutdown, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// Put implements Storage.
func (s *IPFSBlockStorage) Put(ctx context.Context, key string, value []byte) error {
	c, err := cid.Decode(key)
	if err != nil {
		return fmt.Errorf("storage: invalid CID %q: %w", key, err)
	}
	sum, err := c.Prefix().Sum(value)
	if err != nil {
		return fmt.Errorf("storage: hash block: %w", err)
	}
	if !sum.Equals(c) {
		return fmt.Errorf("storage: block does not match CID %s", key)
	}
	b, err := blocks.NewBlockWithCid(value, c)
	if err != nil {
		return err
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	if err := s.blocks.AddBlock(ctx, b); err != nil {
		return fmt.Errorf("storage: add block %s: %w", key, err)
	}
	return s.persist(ctx, c)
}

// Get implements Storage. When the block service has a network exchange the
// call blocks until a peer provides the block or the timeout expires.
func (s *IPFSBlockStorage) Get(ctx context.Context, key string) ([]byte, error) {
	c, err := cid.Decode(key)
	if err != nil {
		return nil, fmt.Errorf("storage: invalid CID %q: %w", key, err)
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	b, err := s.blocks.GetBlock(ctx, c)
	if err != nil {
		if ipld.IsNotFound(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
		}
		return nil, fmt.Errorf("storage: get block %s: %w", key, err)
	}
	return b.RawData(), nil
}

// Persist implements Persister by pinning the block, if a Pinner is set.
func (s *IPFSBlockStorage) Persist(ctx context.Context, key string) error {
	c, err := cid.Decode(key)
	if err != nil {
		return fmt.Errorf("storage: invalid CID %q: %w", key, err)
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	return s.persist(ctx, c)
}

func (s *IPFSBlockStorage) persist(ctx context.Context, c cid.Cid) error {
	if s.pinner == nil {
		return nil
	}
	pinned, err := s.pinner.IsPinned(ctx, c)
	if err != nil {
		return fmt.Errorf("storage: check pin %s: %w", c, err)
	}
	if pinned {
		return nil
	}
	if err := s.pinner.Pin(ctx, c); err != nil {
		return fmt.Errorf("storage: pin %s: %w", c, err)
	}
	return nil
}

// Del implements Storage. It is a no-op.
func (s *IPFSBlockStorage) Del(context.Context, string) error { return nil }

// Iterator implements Storage. It yields nothing: a block service cannot be
// enumerated.
func (s *IPFSBlockStorage) Iterator(context.Context, IteratorOptions) iter.Seq2[Pair, error] {
	return func(func(Pair, error) bool) {}
}

// Merge implements Storage. It is a no-op.
func (s *IPFSBlockStorage) Merge(context.Context, Storage) error { return nil }

// Clear implements Storage. It is a no-op.
func (s *IPFSBlockStorage) Clear(context.Context) error { return nil }

// Close implements Storage. It aborts in-flight Gets and Puts.
func (s *IPFSBlockStorage) Close() error {
	s.cancel()
	return nil
}
