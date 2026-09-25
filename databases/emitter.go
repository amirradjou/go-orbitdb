package databases

import (
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/amirradjou/go-orbitdb/oplog"
)

// EventType identifies a database event.
type EventType int

// Database events, as emitted by @orbitdb/core's database.events.
const (
	// EventUpdate: an entry was appended locally or joined from a peer.
	// Event.Entry is set.
	EventUpdate EventType = iota + 1
	// EventJoin: a heads exchange with a peer completed. Event.Peer and
	// Event.Heads are set.
	EventJoin
	// EventLeave: a peer stopped replicating. Event.Peer is set.
	EventLeave
	// EventError: a background error, e.g. an invalid entry from a peer.
	// Event.Err is set.
	EventError
	// EventClose: the database was closed. It is the last event.
	EventClose
	// EventDrop: the database was dropped.
	EventDrop
)

func (t EventType) String() string {
	switch t {
	case EventUpdate:
		return "update"
	case EventJoin:
		return "join"
	case EventLeave:
		return "leave"
	case EventError:
		return "error"
	case EventClose:
		return "close"
	case EventDrop:
		return "drop"
	}
	return "unknown"
}

// Event is something that happened to a database.
type Event struct {
	Type  EventType
	Entry *oplog.Entry
	Peer  peer.ID
	Heads []*oplog.Entry
	Err   error
}

// Emitter fans events out to subscriptions. Emitting never blocks: each
// subscription buffers events until its reader takes them.
type Emitter struct {
	mu     sync.Mutex
	subs   map[*Subscription]struct{}
	closed bool
}

func newEmitter() *Emitter {
	return &Emitter{subs: make(map[*Subscription]struct{})}
}

// Subscribe returns a subscription that receives every event emitted from
// now on. Call Close when done with it. After the database closes, the
// channel delivers the remaining events, ending with EventClose, and is
// closed.
func (e *Emitter) Subscribe() *Subscription {
	s := &Subscription{
		emitter: e,
		out:     make(chan Event),
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	e.mu.Lock()
	if e.closed {
		s.finishing = true
	} else {
		e.subs[s] = struct{}{}
	}
	e.mu.Unlock()
	go s.run()
	return s
}

func (e *Emitter) emit(ev Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	for s := range e.subs {
		s.push(ev)
	}
}

// close ends every subscription once it has delivered its queued events.
func (e *Emitter) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.closed = true
	for s := range e.subs {
		s.finish()
	}
	e.subs = nil
}

// Subscription receives database events.
type Subscription struct {
	emitter *Emitter
	out     chan Event
	wake    chan struct{}
	done    chan struct{}
	once    sync.Once

	mu        sync.Mutex
	queue     []Event
	finishing bool
}

// Events returns the channel events are delivered on.
func (s *Subscription) Events() <-chan Event { return s.out }

// Close unsubscribes and discards undelivered events. The channel is
// closed.
func (s *Subscription) Close() {
	s.once.Do(func() {
		s.emitter.mu.Lock()
		delete(s.emitter.subs, s)
		s.emitter.mu.Unlock()
		close(s.done)
	})
}

func (s *Subscription) push(ev Event) {
	s.mu.Lock()
	s.queue = append(s.queue, ev)
	s.mu.Unlock()
	s.signal()
}

func (s *Subscription) finish() {
	s.mu.Lock()
	s.finishing = true
	s.mu.Unlock()
	s.signal()
}

func (s *Subscription) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Subscription) run() {
	defer close(s.out)
	for {
		s.mu.Lock()
		if len(s.queue) == 0 {
			finishing := s.finishing
			s.mu.Unlock()
			if finishing {
				return
			}
			select {
			case <-s.wake:
				continue
			case <-s.done:
				return
			}
		}
		ev := s.queue[0]
		s.queue = s.queue[1:]
		s.mu.Unlock()
		select {
		case s.out <- ev:
		case <-s.done:
			return
		}
	}
}
