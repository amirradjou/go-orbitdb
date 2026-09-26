// Package ipfs assembles the IPFS pieces OrbitDB runs on: a libp2p host,
// gossipsub for database update announcements, and a block service whose
// bitswap exchange fetches entries, identities and manifests from peers.
//
// It plays the role Helia plays for @orbitdb/core. The defaults (TCP,
// Noise, Yamux, gossipsub, bitswap) interoperate with a Helia node that
// enables the same transports.
//
// Callers with their own libp2p stack can fill a Node by hand instead of
// calling New.
package ipfs

import (
	"context"
	"errors"
	"fmt"

	"github.com/ipfs/boxo/bitswap"
	bsnet "github.com/ipfs/boxo/bitswap/network/bsnet"
	"github.com/ipfs/boxo/blockservice"
	"github.com/ipfs/boxo/blockstore"
	"github.com/ipfs/boxo/ipld/merkledag"
	pin "github.com/ipfs/boxo/pinning/pinner"
	"github.com/ipfs/boxo/pinning/pinner/dspinner"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/go-datastore"
	dssync "github.com/ipfs/go-datastore/sync"
	leveldb "github.com/ipfs/go-ds-leveldb"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/orbitdb/go-orbitdb/storage"
)

// Node is what OrbitDB needs from IPFS.
type Node struct {
	// Host is the libp2p host. OrbitDB registers the heads exchange
	// protocol on it.
	Host host.Host
	// PubSub carries database updates; each database is a topic.
	PubSub *pubsub.PubSub
	// Blocks stores blocks locally and fetches missing ones from peers.
	Blocks storage.BlockService
	// Pins, if set, pins the blocks OrbitDB stores.
	Pins storage.Pinner

	closers []func() error
}

// Options configures New.
type Options struct {
	// ListenAddrs are the multiaddrs to listen on. Defaults to TCP on
	// 127.0.0.1 with a random port.
	ListenAddrs []string
	// PrivateKey is the peer identity key. Defaults to a new Ed25519 key.
	PrivateKey crypto.PrivKey
	// Datastore backs the blockstore and the pinner. If nil, a LevelDB
	// datastore in Repo is used, or an in-memory one when Repo is empty
	// (blocks then do not survive a restart).
	Datastore datastore.Batching
	// Repo is a directory for a persistent datastore.
	Repo string
	// Libp2pOptions are appended to the host options.
	Libp2pOptions []libp2p.Option
	// PubSubOptions are appended to the gossipsub options.
	PubSubOptions []pubsub.Option
}

// DefaultListenAddrs is used when Options.ListenAddrs is empty.
var DefaultListenAddrs = []string{"/ip4/127.0.0.1/tcp/0"}

// New starts a node.
func New(ctx context.Context, opts Options) (_ *Node, err error) {
	n := &Node{}
	defer func() {
		if err != nil {
			_ = n.Close()
		}
	}()

	listen := opts.ListenAddrs
	if len(listen) == 0 {
		listen = DefaultListenAddrs
	}
	libp2pOpts := []libp2p.Option{libp2p.ListenAddrStrings(listen...)}
	if opts.PrivateKey != nil {
		libp2pOpts = append(libp2pOpts, libp2p.Identity(opts.PrivateKey))
	}
	libp2pOpts = append(libp2pOpts, opts.Libp2pOptions...)
	h, err := libp2p.New(libp2pOpts...)
	if err != nil {
		return nil, fmt.Errorf("ipfs: start libp2p host: %w", err)
	}
	n.Host = h
	n.closers = append(n.closers, h.Close)

	psOpts := append([]pubsub.Option{
		// Send our own updates to every peer on the topic, not only to
		// mesh peers, as js-libp2p's gossipsub does by default. In small
		// swarms the mesh often has not formed yet when the first update
		// after a connection is published.
		pubsub.WithFloodPublish(true),
	}, opts.PubSubOptions...)
	if n.PubSub, err = pubsub.NewGossipSub(ctx, h, psOpts...); err != nil {
		return nil, fmt.Errorf("ipfs: start gossipsub: %w", err)
	}

	ds := opts.Datastore
	switch {
	case ds != nil:
	case opts.Repo != "":
		level, err := leveldb.NewDatastore(opts.Repo, nil)
		if err != nil {
			return nil, fmt.Errorf("ipfs: open datastore: %w", err)
		}
		ds = level
		n.closers = append(n.closers, level.Close)
	default:
		ds = dssync.MutexWrap(datastore.NewMapDatastore())
	}
	bstore := blockstore.NewBlockstore(ds)
	bswap := bitswap.New(ctx, bsnet.NewFromIpfsHost(h), nil, bstore)
	// Close bitswap before the host it runs on.
	n.closers = append([]func() error{bswap.Close}, n.closers...)
	bsvc := blockservice.New(bstore, bswap)
	n.Blocks = bsvc

	pinner, err := dspinner.New(ctx, ds, merkledag.NewDAGService(bsvc))
	if err != nil {
		return nil, fmt.Errorf("ipfs: start pinner: %w", err)
	}
	n.Pins = &directPinner{pinner: pinner}
	n.closers = append([]func() error{pinner.Close}, n.closers...)
	return n, nil
}

// AddrInfo returns the node's peer id and listen addresses.
func (n *Node) AddrInfo() peer.AddrInfo {
	return peer.AddrInfo{ID: n.Host.ID(), Addrs: n.Host.Addrs()}
}

// Connect dials a peer.
func (n *Node) Connect(ctx context.Context, pi peer.AddrInfo) error {
	return n.Host.Connect(ctx, pi)
}

// Close stops the node.
func (n *Node) Close() error {
	var errs []error
	for _, c := range n.closers {
		errs = append(errs, c())
	}
	n.closers = nil
	return errors.Join(errs...)
}

// directPinner adapts boxo's pinner to storage.Pinner. OrbitDB blocks carry
// no IPLD links (hashes are strings), so a direct pin keeps everything a
// recursive pin would.
type directPinner struct {
	pinner pin.Pinner
}

func (p *directPinner) IsPinned(ctx context.Context, c cid.Cid) (bool, error) {
	_, pinned, err := p.pinner.IsPinned(ctx, c)
	return pinned, err
}

func (p *directPinner) Pin(ctx context.Context, c cid.Cid) error {
	if err := p.pinner.PinWithMode(ctx, c, pin.Direct, "orbitdb"); err != nil {
		return err
	}
	return p.pinner.Flush(ctx)
}
