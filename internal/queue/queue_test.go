package queue

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRunsInOrderOneAtATime(t *testing.T) {
	q := New()
	defer q.Close()
	var (
		mu      sync.Mutex
		order   []int
		running int
		wg      sync.WaitGroup
	)
	for i := range 100 {
		wg.Add(1)
		require.True(t, q.Add(func() {
			defer wg.Done()
			mu.Lock()
			running++
			require.Equal(t, 1, running, "tasks never overlap")
			order = append(order, i)
			running--
			mu.Unlock()
		}))
	}
	wg.Wait()
	for i, v := range order {
		require.Equal(t, i, v)
	}
}

func TestCloseDropsPendingAndWaitsForRunning(t *testing.T) {
	q := New()
	started := make(chan struct{})
	release := make(chan struct{})
	finished := false
	q.Add(func() {
		close(started)
		<-release
		finished = true
	})
	ranSecond := false
	q.Add(func() { ranSecond = true })
	<-started

	closed := make(chan struct{})
	go func() {
		q.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close returned while a task was running")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-closed
	require.True(t, finished)
	require.False(t, ranSecond, "pending tasks are dropped")
	require.False(t, q.Add(func() {}), "a closed queue rejects tasks")
	q.Close() // idempotent
}
