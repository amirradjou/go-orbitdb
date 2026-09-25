// Package syncutils implements the OrbitDB sync protocol, which replicates
// a log between peers.
//
// It is a port of src/sync.js in @orbitdb/core 4 and interoperates with it:
//
//   - every peer subscribes to a gossipsub topic named after the log id
//     (the database address);
//   - when a peer sees another peer subscribe, it opens a libp2p stream
//     with protocol /orbitdb/heads/<address> and both sides send the raw
//     block bytes of their current heads, then close their write side;
//   - after appending, a peer publishes the new entry's block bytes on the
//     topic.
//
// Received heads are handed to OnSynced, which joins them into the log;
// the log fetches any missing ancestors itself (over bitswap when its entry
// storage is IPFS-backed).
package syncutils

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	msmux "github.com/multiformats/go-multistream"

	"github.com/amirradjou/go-orbitdb/internal/queue"
	"github.com/amirradjou/go-orbitdb/oplog"
)

// DefaultTimeout bounds a heads exchange with one peer, as in @orbitdb/core.
const DefaultTimeout = 30 * time.Second

// maxHeadsBytes caps how much a peer may send in one heads exchange.
const maxHeadsBytes = 64 << 20

// Options configures New.
type Options struct {
	Host   host.Host
	PubSub *pubsub.PubSub
	Log    *oplog.Log

	// OnSynced is called, one entry at a time, for every head received
	// from a peer, either in a heads exchange or as a published update.
	OnSynced func(ctx context.Context, entry *oplog.Entry)
	// OnJoin is called when a heads exchange with a peer has completed,
	// with the local heads at that moment.
	OnJoin func(p peer.ID, heads []*oplog.Entry)
	// OnLeave is called when a peer leaves the topic or disconnects.
	OnLeave func(p peer.ID)
	// OnError is called for errors that happen in the background.
	OnError func(err error)

	// Timeout bounds each heads exchange. Defaults to DefaultTimeout.
	Timeout time.Duration
	// DisableAutoStart leaves the protocol stopped until Start is called.
	DisableAutoStart bool
}

// Sync replicates one log.
type Sync struct {
	opts     Options
	address  string
	protocol protocol.ID

	// lifecycle serialises Start and Stop, so a new run never begins
	// before the previous one has fully stopped.
	lifecycle sync.Mutex

	mu    sync.Mutex
	run   *run // nil while stopped
	peers map[peer.ID]struct{}
}

// run is the state of one Start..Stop cycle.
type run struct {
	ctx    context.Context
	cancel context.CancelFunc
	topic  *pubsub.Topic
	sub    *pubsub.Subscription
	events *pubsub.TopicEventHandler
	queue  *queue.Queue
	// readers counts the pubsub reader goroutines; handlers counts inbound
	// heads exchanges, incremented under Sync.mu while the run is current.
	readers  sync.WaitGroup
	handlers sync.WaitGroup
}

// New creates a Sync and, unless DisableAutoStart is set, starts it.
func New(opts Options) (*Sync, error) {
	if opts.Host == nil || opts.PubSub == nil {
		return nil, errors.New("sync: a libp2p host and pubsub are required")
	}
	if opts.Log == nil {
		return nil, errors.New("sync: a log is required")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	s := &Sync{
		opts:     opts,
		address:  opts.Log.ID(),
		protocol: HeadsProtocol(opts.Log.ID()),
		peers:    make(map[peer.ID]struct{}),
	}
	if !opts.DisableAutoStart {
		if err := s.Start(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// HeadsProtocol returns the libp2p protocol id of the heads exchange for a
// database address. Like @orbitdb/core it joins "/orbitdb/heads/" and the
// address and collapses repeated slashes, so "/orbitdb/zdpu..." becomes
// "/orbitdb/heads/orbitdb/zdpu...".
func HeadsProtocol(address string) protocol.ID {
	return protocol.ID(posixJoin("/orbitdb/heads/", address))
}

// posixJoin mirrors src/utils/path-join.js: it joins with "/" and removes
// a slash that follows a slash, a leading "./" and a "./" that follows a
// slash.
func posixJoin(parts ...string) string {
	s := strings.Join(parts, "/")
	var b strings.Builder
	for i := 0; i < len(s); {
		prevSlash := i > 0 && s[i-1] == '/'
		switch {
		case prevSlash && s[i] == '/':
			for i < len(s) && s[i] == '/' {
				i++
			}
		case i == 0 && strings.HasPrefix(s, "./"):
			i += 2
		case prevSlash && strings.HasPrefix(s[i:], "./"):
			i += 2
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	if b.Len() == 0 {
		return "."
	}
	return b.String()
}

// Start subscribes to the topic and starts serving heads exchanges.
func (s *Sync) Start() error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	s.mu.Lock()
	running := s.run != nil
	s.mu.Unlock()
	if running {
		return nil
	}

	topic, err := s.opts.PubSub.Join(s.address)
	if err != nil {
		return fmt.Errorf("sync: join topic %s: %w", s.address, err)
	}
	events, err := topic.EventHandler()
	if err != nil {
		_ = topic.Close()
		return fmt.Errorf("sync: topic events: %w", err)
	}
	sub, err := topic.Subscribe()
	if err != nil {
		events.Cancel()
		_ = topic.Close()
		return fmt.Errorf("sync: subscribe %s: %w", s.address, err)
	}
	r := &run{topic: topic, sub: sub, events: events, queue: queue.New()}
	r.ctx, r.cancel = context.WithCancel(context.Background())

	s.mu.Lock()
	s.run = r
	s.mu.Unlock()
	s.opts.Host.SetStreamHandler(s.protocol, s.handleStream)

	r.readers.Add(2)
	go s.readMessages(r)
	go s.readPeerEvents(r)
	return nil
}

// Stop unsubscribes and stops serving heads exchanges, and returns once
// nothing of the run is left running. Pending received heads are dropped.
func (s *Sync) Stop() error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	s.mu.Lock()
	r := s.run
	s.run = nil
	clear(s.peers)
	s.mu.Unlock()
	if r == nil {
		return nil
	}

	r.cancel()
	s.opts.Host.RemoveStreamHandler(s.protocol)
	r.sub.Cancel()
	r.events.Cancel()
	r.readers.Wait()
	r.handlers.Wait()
	r.queue.Close()
	return r.topic.Close()
}

// Peers returns the peers currently replicating the log with us.
func (s *Sync) Peers() []peer.ID {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]peer.ID, 0, len(s.peers))
	for p := range s.peers {
		out = append(out, p)
	}
	return out
}

// Add announces a newly appended entry to peers.
func (s *Sync) Add(ctx context.Context, entry *oplog.Entry) error {
	s.mu.Lock()
	r := s.run
	s.mu.Unlock()
	if r == nil || entry == nil || entry.Hash == "" {
		return nil
	}
	data, err := s.opts.Log.Storage().Get(ctx, entry.Hash)
	if err != nil {
		return fmt.Errorf("sync: read entry %s: %w", entry.Hash, err)
	}
	return r.topic.Publish(ctx, data)
}

// enqueue runs task on the run's serial queue with the run's context.
func (r *run) enqueue(task func(ctx context.Context)) {
	r.queue.Add(func() { task(r.ctx) })
}

func (s *Sync) readMessages(r *run) {
	defer r.readers.Done()
	self := s.opts.Host.ID()
	for {
		msg, err := r.sub.Next(r.ctx)
		if err != nil {
			return // cancelled
		}
		if msg.ReceivedFrom == self {
			continue // our own announcement
		}
		data := msg.Data
		r.enqueue(func(ctx context.Context) {
			entry, err := oplog.DecodeEntry(ctx, data, s.opts.Log.Encryption())
			if err != nil {
				s.emitError(fmt.Errorf("sync: decode update from %s: %w", msg.ReceivedFrom, err))
				return
			}
			s.synced(ctx, entry)
		})
	}
}

func (s *Sync) readPeerEvents(r *run) {
	defer r.readers.Done()
	for {
		ev, err := r.events.NextPeerEvent(r.ctx)
		if err != nil {
			return // cancelled
		}
		p := ev.Peer
		switch ev.Type {
		case pubsub.PeerJoin:
			r.enqueue(func(ctx context.Context) { s.dialPeer(ctx, p) })
		case pubsub.PeerLeave:
			r.enqueue(func(context.Context) {
				s.mu.Lock()
				delete(s.peers, p)
				s.mu.Unlock()
				if s.opts.OnLeave != nil {
					s.opts.OnLeave(p)
				}
			})
		}
	}
}

// addPeer records p and reports whether it was new.
func (s *Sync) addPeer(p peer.ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.peers[p]; ok {
		return false
	}
	s.peers[p] = struct{}{}
	return true
}

func (s *Sync) removePeer(p peer.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.peers, p)
}

// dialPeer runs a heads exchange with a peer that joined the topic.
func (s *Sync) dialPeer(ctx context.Context, p peer.ID) {
	if !s.addPeer(p) {
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, s.opts.Timeout)
	defer cancel()
	stream, err := s.opts.Host.NewStream(dialCtx, p, s.protocol)
	if err != nil {
		s.removePeer(p)
		if errors.Is(err, msmux.ErrNotSupported[protocol.ID]{}) || ctx.Err() != nil {
			return // the peer does not have this database open, or we stopped
		}
		s.emitError(fmt.Errorf("sync: dial %s: %w", p, err))
		return
	}
	s.exchange(ctx, p, stream)
}

// handleStream answers a heads exchange opened by a peer.
func (s *Sync) handleStream(stream network.Stream) {
	s.mu.Lock()
	r := s.run
	if r == nil {
		s.mu.Unlock()
		_ = stream.Reset()
		return
	}
	r.handlers.Add(1)
	s.mu.Unlock()
	defer r.handlers.Done()

	p := stream.Conn().RemotePeer()
	s.addPeer(p)
	s.exchange(r.ctx, p, stream)
}

// exchange sends our heads and reads the peer's, then hands the received
// heads to OnSynced and reports the join.
func (s *Sync) exchange(ctx context.Context, p peer.ID, stream network.Stream) {
	_ = stream.SetDeadline(time.Now().Add(s.opts.Timeout))
	// Abort the stream as soon as the sync stops.
	defer context.AfterFunc(ctx, func() { _ = stream.Reset() })()
	sendErr := make(chan error, 1)
	go func() { sendErr <- s.sendHeads(ctx, stream) }()

	heads, readErr := readHeads(bufio.NewReader(io.LimitReader(stream, maxHeadsBytes)))
	err := errors.Join(<-sendErr, readErr)
	_ = stream.Close()
	if err != nil {
		s.removePeer(p)
		if ctx.Err() == nil {
			s.emitError(fmt.Errorf("sync: heads exchange with %s: %w", p, err))
		}
		return
	}

	for _, data := range heads {
		entry, err := oplog.DecodeEntry(ctx, data, s.opts.Log.Encryption())
		if err != nil {
			s.emitError(fmt.Errorf("sync: decode head from %s: %w", p, err))
			continue
		}
		s.synced(ctx, entry)
	}
	if ctx.Err() == nil && s.opts.OnJoin != nil {
		heads, err := s.opts.Log.Heads(ctx)
		if err != nil {
			s.emitError(err)
			return
		}
		s.opts.OnJoin(p, heads)
	}
}

// sendHeads writes each head block in its own Write, so a js-libp2p peer
// receives each one as a separate message, then closes our write side.
func (s *Sync) sendHeads(ctx context.Context, stream network.Stream) error {
	heads, err := s.opts.Log.Heads(ctx)
	if err != nil {
		return err
	}
	for _, h := range heads {
		data, err := s.opts.Log.Storage().Get(ctx, h.Hash)
		if err != nil {
			return fmt.Errorf("read head %s: %w", h.Hash, err)
		}
		if _, err := stream.Write(data); err != nil {
			return err
		}
	}
	return stream.CloseWrite()
}

func (s *Sync) synced(ctx context.Context, entry *oplog.Entry) {
	if s.opts.OnSynced != nil && ctx.Err() == nil {
		s.opts.OnSynced(ctx, entry)
	}
}

func (s *Sync) emitError(err error) {
	if s.opts.OnError != nil {
		s.opts.OnError(err)
	}
}

// readHeads splits the stream into the dag-cbor blocks it carries. Blocks
// are self-delimiting, so no framing is needed (and none is sent by
// @orbitdb/core, whose stream chunks may coalesce).
func readHeads(r *bufio.Reader) ([][]byte, error) {
	var heads [][]byte
	for {
		if _, err := r.Peek(1); errors.Is(err, io.EOF) {
			return heads, nil
		}
		item, err := readCBORItem(r)
		if err != nil {
			return nil, err
		}
		heads = append(heads, item)
	}
}

// readCBORItem reads exactly one CBOR data item, returning its bytes.
func readCBORItem(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	pending := 1
	for pending > 0 {
		pending--
		ib, err := r.ReadByte()
		if err != nil {
			return nil, unexpectedEOF(err)
		}
		buf = append(buf, ib)
		major, info := ib>>5, ib&0x1f
		var arg uint64
		switch {
		case info < 24:
			arg = uint64(info)
		case info <= 27:
			n := 1 << (info - 24)
			b := make([]byte, n)
			if _, err := io.ReadFull(r, b); err != nil {
				return nil, unexpectedEOF(err)
			}
			buf = append(buf, b...)
			for _, c := range b {
				arg = arg<<8 | uint64(c)
			}
		default:
			return nil, fmt.Errorf("unsupported CBOR additional info %d", info)
		}
		switch major {
		case 2, 3: // byte string, text string
			if arg > maxHeadsBytes {
				return nil, fmt.Errorf("CBOR string of %d bytes is too large", arg)
			}
			start := len(buf)
			buf = append(buf, make([]byte, arg)...)
			if _, err := io.ReadFull(r, buf[start:]); err != nil {
				return nil, unexpectedEOF(err)
			}
		case 4: // array
			if arg > maxHeadsBytes {
				return nil, fmt.Errorf("CBOR array of %d items is too large", arg)
			}
			pending += int(arg)
		case 5: // map
			if arg > maxHeadsBytes {
				return nil, fmt.Errorf("CBOR map of %d entries is too large", arg)
			}
			pending += 2 * int(arg)
		case 6: // tag
			pending++
		}
	}
	return buf, nil
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
