package accesscontrollers

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/orbitdb/go-orbitdb/identities"
	"github.com/orbitdb/go-orbitdb/internal/block"
	"github.com/orbitdb/go-orbitdb/oplog"
	"github.com/orbitdb/go-orbitdb/storage"
)

// IPFSType is the type of IPFS access controllers.
const IPFSType = "ipfs"

// IPFSOptions configures IPFS.
type IPFSOptions struct {
	// Write lists the identity ids allowed to write; "*" allows anyone.
	// Defaults to the local identity.
	Write []string
	// Storage holds the access controller block. Defaults to an LRU cache
	// over the IPFS node's block storage.
	Storage storage.Storage
}

// IPFSAccessController allows a fixed list of writers.
type IPFSAccessController struct {
	address    string
	write      []string
	identities *identities.Identities
}

// IPFS returns a factory for IPFS access controllers.
func IPFS(opts IPFSOptions) Factory {
	return func(ctx context.Context, p Params) (AccessController, error) {
		if p.Identities == nil {
			return nil, errors.New("accesscontrollers: identities are required")
		}
		st := opts.Storage
		if st == nil {
			if p.IPFS == nil {
				return nil, errors.New("accesscontrollers: IPFS or a storage is required")
			}
			blocks, err := storage.NewIPFSBlockStorage(p.IPFS.Blocks, storage.IPFSBlockStorageOptions{Pinner: p.IPFS.Pins})
			if err != nil {
				return nil, err
			}
			lru, err := storage.NewLRUStorage(1000)
			if err != nil {
				return nil, err
			}
			st = storage.NewComposedStorage(lru, blocks)
		}
		ac := &IPFSAccessController{identities: p.Identities}
		if p.Address != "" {
			hash := strings.ReplaceAll(p.Address, "/ipfs/", "")
			data, err := st.Get(ctx, hash)
			if err != nil {
				return nil, fmt.Errorf("load access controller %s: %w", p.Address, err)
			}
			if ac.write, err = decodeManifest(data); err != nil {
				return nil, fmt.Errorf("access controller %s: %w", p.Address, err)
			}
			ac.address = p.Address
			return ac, nil
		}

		write := opts.Write
		if write == nil {
			if p.Identity == nil {
				return nil, errors.New("accesscontrollers: a write list or an identity is required")
			}
			write = []string{p.Identity.ID}
		}
		hash, data, err := block.Encode(map[string]any{"type": IPFSType, "write": write})
		if err != nil {
			return nil, err
		}
		if err := st.Put(ctx, hash, data); err != nil {
			return nil, err
		}
		ac.write = slices.Clone(write)
		ac.address = "/" + IPFSType + "/" + hash
		return ac, nil
	}
}

func decodeManifest(data []byte) ([]string, error) {
	v, err := block.Decode(data)
	if err != nil {
		return nil, err
	}
	m, err := block.Map(v)
	if err != nil {
		return nil, err
	}
	return block.Strings(m, "write")
}

// Type implements AccessController.
func (*IPFSAccessController) Type() string { return IPFSType }

// Address implements AccessController.
func (a *IPFSAccessController) Address() string { return a.address }

// Write returns the writers.
func (a *IPFSAccessController) Write() []string { return slices.Clone(a.write) }

// CanAppend implements oplog.AccessController.
func (a *IPFSAccessController) CanAppend(ctx context.Context, entry *oplog.Entry) (bool, error) {
	return writerAllowed(ctx, a.identities, entry, func(id string) (bool, error) {
		return contains(a.write, id), nil
	})
}
