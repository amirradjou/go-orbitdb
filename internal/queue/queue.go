// Package queue runs tasks one at a time, in the order they were added,
// like the p-queue (concurrency 1) instances @orbitdb/core uses to
// serialise sync messages.
package queue

import "sync"

// Queue is a FIFO of tasks run by a single worker goroutine. Adding never
// blocks.
type Queue struct {
	mu      sync.Mutex
	tasks   []func()
	wake    chan struct{}
	closed  bool
	stopped chan struct{}
}

// New starts a queue.
func New() *Queue {
	q := &Queue{wake: make(chan struct{}, 1), stopped: make(chan struct{})}
	go q.run()
	return q
}

func (q *Queue) run() {
	defer close(q.stopped)
	for {
		q.mu.Lock()
		if q.closed {
			q.mu.Unlock()
			return
		}
		if len(q.tasks) == 0 {
			q.mu.Unlock()
			<-q.wake
			continue
		}
		task := q.tasks[0]
		q.tasks = q.tasks[1:]
		q.mu.Unlock()
		task()
	}
}

// Add queues task. It reports false if the queue is closed.
func (q *Queue) Add(task func()) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
	q.tasks = append(q.tasks, task)
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return true
}

// Close drops pending tasks and waits for the running one, if any.
func (q *Queue) Close() {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		<-q.stopped
		return
	}
	q.closed = true
	q.tasks = nil
	select {
	case q.wake <- struct{}{}:
	default:
	}
	q.mu.Unlock()
	<-q.stopped
}
