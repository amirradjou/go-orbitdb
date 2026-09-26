package oplog_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/orbitdb/go-orbitdb/identities/identitytypes"
	"github.com/orbitdb/go-orbitdb/oplog"
	"github.com/orbitdb/go-orbitdb/storage"
)

func newLog(t *testing.T, identity *identitytypes.Identity, opts oplog.Options) *oplog.Log {
	t.Helper()
	l, err := oplog.NewLog(context.Background(), identity, opts)
	require.NoError(t, err)
	return l
}

func payloads(t *testing.T, l *oplog.Log) []any {
	t.Helper()
	values, err := l.Values(context.Background())
	require.NoError(t, err)
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v.Payload
	}
	return out
}

func TestAppendAndValues(t *testing.T) {
	ctx := context.Background()
	identity := fixtureIdentities(t)("userA")
	l := newLog(t, identity, oplog.Options{LogID: "A"})

	values, err := l.Values(ctx)
	require.NoError(t, err)
	require.Empty(t, values)
	clock, err := l.Clock(ctx)
	require.NoError(t, err)
	require.Equal(t, oplog.NewClock(identity.PublicKey, 0), clock)

	for i := range 5 {
		e, err := l.Append(ctx, fmt.Sprint("hello", i), oplog.AppendOptions{})
		require.NoError(t, err)
		require.NotEmpty(t, e.Hash)
		require.Equal(t, int64(i+1), e.Clock.Time)
		require.Equal(t, identity.PublicKey, e.Key)
		require.Equal(t, identity.Hash, e.Identity)

		heads, err := l.Heads(ctx)
		require.NoError(t, err)
		require.Len(t, heads, 1)
		require.Equal(t, e.Hash, heads[0].Hash)

		has, err := l.Has(ctx, e.Hash)
		require.NoError(t, err)
		require.True(t, has)
		got, err := l.Get(ctx, e.Hash)
		require.NoError(t, err)
		require.Equal(t, e.Payload, got.Payload)
	}
	require.Equal(t, []any{"hello0", "hello1", "hello2", "hello3", "hello4"}, payloads(t, l))

	_, err = l.Get(ctx, "")
	require.Error(t, err)
	_, err = l.Get(ctx, "zdpuAsKzwUEa8cz9pkJxxFMxLuP3cutA9PDGoLZytrg4RSVEa")
	require.ErrorIs(t, err, storage.ErrNotFound)
	has, err := l.Has(ctx, "zdpuAsKzwUEa8cz9pkJxxFMxLuP3cutA9PDGoLZytrg4RSVEa")
	require.NoError(t, err)
	require.False(t, has)
}

func TestNewLogValidation(t *testing.T) {
	_, err := oplog.NewLog(context.Background(), nil, oplog.Options{})
	require.EqualError(t, err, "identity is required")

	l := newLog(t, fixtureIdentities(t)("userA"), oplog.Options{})
	require.NotEmpty(t, l.ID(), "a log id is generated")
}

func TestCreateEntryValidation(t *testing.T) {
	ctx := context.Background()
	identity := fixtureIdentities(t)("userA")
	_, err := oplog.CreateEntry(ctx, nil, "A", "x", oplog.EntryOptions{})
	require.ErrorContains(t, err, "identity is required")
	_, err = oplog.CreateEntry(ctx, identity, "", "x", oplog.EntryOptions{})
	require.ErrorContains(t, err, "requires an id")
	_, err = oplog.CreateEntry(ctx, identity, "A", nil, oplog.EntryOptions{})
	require.ErrorContains(t, err, "requires a payload")

	decoded, err := identitytypes.Decode(identity.Bytes)
	require.NoError(t, err)
	_, err = oplog.CreateEntry(ctx, decoded, "A", "x", oplog.EntryOptions{})
	require.ErrorContains(t, err, "no signer", "an identity without keys cannot sign")
}

func TestVerifyEntryRejectsTampering(t *testing.T) {
	ctx := context.Background()
	identity := fixtureIdentities(t)("userA")
	e, err := oplog.CreateEntry(ctx, identity, "A", "hello", oplog.EntryOptions{})
	require.NoError(t, err)
	ok, err := oplog.VerifyEntry(e)
	require.NoError(t, err)
	require.True(t, ok)

	for name, mutate := range map[string]func(*oplog.Entry){
		"payload": func(e *oplog.Entry) { e.Payload = "evil" },
		"id":      func(e *oplog.Entry) { e.ID = "B" },
		"clock":   func(e *oplog.Entry) { e.Clock.Time = 99 },
		"next":    func(e *oplog.Entry) { e.Next = []string{"zdpuAsKzwUEa8cz9pkJxxFMxLuP3cutA9PDGoLZytrg4RSVEa"} },
		"key":     func(e *oplog.Entry) { e.Key = fixtureIdentities(t)("userB").PublicKey },
	} {
		c := *e
		mutate(&c)
		ok, err := oplog.VerifyEntry(&c)
		require.NoError(t, err, name)
		require.False(t, ok, name)
	}

	c := *e
	c.Sig = ""
	_, err = oplog.VerifyEntry(&c)
	require.ErrorContains(t, err, "signature")
	_, err = oplog.VerifyEntry(&oplog.Entry{})
	require.ErrorContains(t, err, "invalid log entry")
}

func TestDecodeEntryRejectsGarbage(t *testing.T) {
	ctx := context.Background()
	for name, data := range map[string][]byte{
		"empty":     nil,
		"not cbor":  []byte{0xff, 0x00},
		"not a map": {0x01},
		"no id":     {0xa1, 0x61, 0x76, 0x02}, // {"v": 2}
	} {
		_, err := oplog.DecodeEntry(ctx, data, oplog.Encryption{})
		require.Error(t, err, name)
	}
}

func TestJoinTwoWriters(t *testing.T) {
	ctx := context.Background()
	identity := fixtureIdentities(t)
	log1 := newLog(t, identity("userA"), oplog.Options{LogID: "X"})
	log2 := newLog(t, identity("userB"), oplog.Options{LogID: "X"})

	for i := 1; i <= 10; i++ {
		_, err := log1.Append(ctx, fmt.Sprint("A", i), oplog.AppendOptions{})
		require.NoError(t, err)
		_, err = log2.Append(ctx, fmt.Sprint("B", i), oplog.AppendOptions{})
		require.NoError(t, err)
	}
	require.NoError(t, log1.Join(ctx, log2))
	require.NoError(t, log2.Join(ctx, log1))

	v1, v2 := payloads(t, log1), payloads(t, log2)
	require.Len(t, v1, 20)
	require.Equal(t, v1, v2, "both logs converge to the same order")
	heads, err := log1.Heads(ctx)
	require.NoError(t, err)
	require.Len(t, heads, 2, "concurrent writers leave two heads until the next append")

	e, err := log1.Append(ctx, "merge", oplog.AppendOptions{})
	require.NoError(t, err)
	require.Len(t, e.Next, 2, "an append points at every head")
	require.Equal(t, int64(11), e.Clock.Time)

	// Joining again changes nothing.
	require.NoError(t, log2.Join(ctx, log1))
	require.NoError(t, log2.Join(ctx, log1))
	require.Len(t, payloads(t, log2), 21)
}

func TestJoinEntryFetchesMissingAncestors(t *testing.T) {
	ctx := context.Background()
	identity := fixtureIdentities(t)
	shared := storage.NewMemoryStorage()
	log1 := newLog(t, identity("userA"), oplog.Options{LogID: "X", EntryStorage: shared})
	log2 := newLog(t, identity("userB"), oplog.Options{LogID: "X", EntryStorage: shared})

	var last *oplog.Entry
	for i := range 5 {
		var err error
		last, err = log1.Append(ctx, fmt.Sprint("A", i), oplog.AppendOptions{ReferencesCount: 2})
		require.NoError(t, err)
	}
	updated, err := log2.JoinEntry(ctx, last)
	require.NoError(t, err)
	require.True(t, updated)
	require.Equal(t, []any{"A0", "A1", "A2", "A3", "A4"}, payloads(t, log2))

	updated, err = log2.JoinEntry(ctx, last)
	require.NoError(t, err)
	require.False(t, updated, "joining an entry twice is a no-op")
}

func TestJoinEntryErrors(t *testing.T) {
	ctx := context.Background()
	identity := fixtureIdentities(t)
	logA := newLog(t, identity("userA"), oplog.Options{LogID: "AAA"})
	logB := newLog(t, identity("userA"), oplog.Options{LogID: "BBB"})
	_, err := logA.Append(ctx, "entryA", oplog.AppendOptions{})
	require.NoError(t, err)
	eb, err := logB.Append(ctx, "entryB", oplog.AppendOptions{})
	require.NoError(t, err)

	_, err = logA.JoinEntry(ctx, eb)
	require.EqualError(t, err, "entry's id (BBB) doesn't match the log's id (AAA)")
	require.EqualError(t, logA.Join(ctx, logB), "entry's id (BBB) doesn't match the log's id (AAA)")
	require.EqualError(t, logA.Join(ctx, nil), "log instance not defined")

	// An entry whose ancestors are nowhere to be found cannot be joined.
	isolated := newLog(t, identity("userB"), oplog.Options{LogID: "X"})
	src := newLog(t, identity("userA"), oplog.Options{LogID: "X"})
	_, err = src.Append(ctx, "one", oplog.AppendOptions{})
	require.NoError(t, err)
	two, err := src.Append(ctx, "two", oplog.AppendOptions{})
	require.NoError(t, err)
	_, err = isolated.JoinEntry(ctx, two)
	require.ErrorIs(t, err, storage.ErrNotFound)
	require.Empty(t, payloads(t, isolated), "a failed join leaves the log unchanged")

	// A tampered block, as a malicious peer would send it, is rejected.
	tampered := *two
	tampered.Payload = "evil"
	_, data, err := oplog.EncodeEntry(ctx, &tampered, oplog.Encryption{})
	require.NoError(t, err)
	received, err := oplog.DecodeEntry(ctx, data, oplog.Encryption{})
	require.NoError(t, err)
	_, err = newLog(t, identity("userB"), oplog.Options{LogID: "X"}).JoinEntry(ctx, received)
	require.ErrorContains(t, err, "could not validate signature")

	_, err = isolated.JoinEntry(ctx, &oplog.Entry{ID: "X"})
	require.ErrorContains(t, err, "no hash")
}

func TestJoinEntryVerifiesWhatItStores(t *testing.T) {
	ctx := context.Background()
	identity := fixtureIdentities(t)
	shared := storage.NewMemoryStorage()
	src := newLog(t, identity("userA"), oplog.Options{LogID: "X", EntryStorage: shared})
	e, err := src.Append(ctx, "original", oplog.AppendOptions{})
	require.NoError(t, err)
	data, err := shared.Get(ctx, e.Hash)
	require.NoError(t, err)
	decoded, err := oplog.DecodeEntry(ctx, data, oplog.Encryption{})
	require.NoError(t, err)

	// Changing a decoded entry does not change what is joined: the log
	// works from the block the entry was decoded from.
	decoded.Payload = "changed"
	decoded.Identity = "zdpuArx43BnXdDff5rjrGLYrxUomxNroc2uaocTgcWK76UfQT"
	dst := newLog(t, identity("userB"), oplog.Options{LogID: "X"})
	updated, err := dst.JoinEntry(ctx, decoded)
	require.NoError(t, err)
	require.True(t, updated)
	require.Equal(t, []any{"original"}, payloads(t, dst))
	stored, err := dst.Storage().Get(ctx, e.Hash)
	require.NoError(t, err)
	require.Equal(t, data, stored, "the original block is stored under its hash")
}

type denyWriter struct{ denied string }

func (d denyWriter) CanAppend(_ context.Context, e *oplog.Entry) (bool, error) {
	return e.Identity != d.denied, nil
}

type failingAccess struct{}

func (failingAccess) CanAppend(context.Context, *oplog.Entry) (bool, error) {
	return false, errors.New("acl unavailable")
}

func TestAccessController(t *testing.T) {
	ctx := context.Background()
	identity := fixtureIdentities(t)
	userB := identity("userB")
	access := denyWriter{denied: userB.Hash}

	logB := newLog(t, userB, oplog.Options{LogID: "X", AccessController: access})
	_, err := logB.Append(ctx, "nope", oplog.AppendOptions{})
	require.ErrorContains(t, err, "is not allowed to write to the log")
	require.ErrorContains(t, err, userB.Hash)

	openB := newLog(t, userB, oplog.Options{LogID: "X"})
	entry, err := openB.Append(ctx, "from B", oplog.AppendOptions{})
	require.NoError(t, err)
	logA := newLog(t, identity("userA"), oplog.Options{LogID: "X", AccessController: access})
	require.ErrorContains(t, logA.Join(ctx, openB), "is not allowed to write to the log")
	_, err = logA.JoinEntry(ctx, entry)
	require.ErrorContains(t, err, "is not allowed to write to the log")

	failing := newLog(t, identity("userA"), oplog.Options{LogID: "X", AccessController: failingAccess{}})
	_, err = failing.Append(ctx, "x", oplog.AppendOptions{})
	require.ErrorContains(t, err, "acl unavailable")
}

func TestHeadsPersistAcrossReopen(t *testing.T) {
	ctx := context.Background()
	identity := fixtureIdentities(t)("userA")
	dir := t.TempDir()
	entries := storage.NewMemoryStorage() // stands in for IPFS, which outlives the log
	open := func() *oplog.Log {
		heads, err := storage.NewLevelStorage(dir + "/heads")
		require.NoError(t, err)
		index, err := storage.NewLevelStorage(dir + "/index")
		require.NoError(t, err)
		return newLog(t, identity, oplog.Options{LogID: "P", EntryStorage: entriesNoClose{entries}, HeadsStorage: heads, IndexStorage: index})
	}
	l := open()
	for i := range 3 {
		_, err := l.Append(ctx, fmt.Sprint("p", i), oplog.AppendOptions{})
		require.NoError(t, err)
	}
	require.NoError(t, l.Close())

	l = open()
	defer l.Close()
	require.Equal(t, []any{"p0", "p1", "p2"}, payloads(t, l))
	e, err := l.Append(ctx, "p3", oplog.AppendOptions{})
	require.NoError(t, err)
	require.Equal(t, int64(4), e.Clock.Time, "the clock continues from the persisted heads")
}

type entriesNoClose struct{ storage.Storage }

func (entriesNoClose) Close() error { return nil }

func TestLogHeadsOption(t *testing.T) {
	ctx := context.Background()
	identity := fixtureIdentities(t)("userA")
	shared := storage.NewMemoryStorage()
	l1 := newLog(t, identity, oplog.Options{LogID: "H", EntryStorage: shared})
	var entries []*oplog.Entry
	for i := range 3 {
		e, err := l1.Append(ctx, fmt.Sprint("h", i), oplog.AppendOptions{})
		require.NoError(t, err)
		entries = append(entries, e)
	}
	l2 := newLog(t, identity, oplog.Options{LogID: "H", EntryStorage: shared, LogHeads: entries[1:2]})
	require.Equal(t, []any{"h0", "h1"}, payloads(t, l2), "the log starts from the given heads")
}

func TestClear(t *testing.T) {
	ctx := context.Background()
	l := newLog(t, fixtureIdentities(t)("userA"), oplog.Options{LogID: "C"})
	_, err := l.Append(ctx, "x", oplog.AppendOptions{})
	require.NoError(t, err)
	require.NoError(t, l.Clear(ctx))
	require.Empty(t, payloads(t, l))
	heads, err := l.Heads(ctx)
	require.NoError(t, err)
	require.Empty(t, heads)
}

func TestTraverseStopsAndBreaks(t *testing.T) {
	ctx := context.Background()
	l := newLog(t, fixtureIdentities(t)("userA"), oplog.Options{LogID: "T"})
	for i := range 10 {
		_, err := l.Append(ctx, i, oplog.AppendOptions{})
		require.NoError(t, err)
	}
	var seen []any
	stop := func(e *oplog.Entry) (bool, error) { return e.Payload == int64(6), nil }
	for e, err := range l.Traverse(ctx, nil, stop) {
		require.NoError(t, err)
		seen = append(seen, e.Payload)
	}
	require.Equal(t, []any{int64(9), int64(8), int64(7), int64(6)}, seen)

	count := 0
	for range l.Traverse(ctx, nil, nil) {
		count++
		if count == 2 {
			break
		}
	}
	require.Equal(t, 2, count)

	boom := errors.New("boom")
	var gotErr error
	for _, err := range l.Traverse(ctx, nil, func(*oplog.Entry) (bool, error) { return false, boom }) {
		if err != nil {
			gotErr = err
		}
	}
	require.ErrorIs(t, gotErr, boom)

	empty := 0
	for range l.Traverse(ctx, []*oplog.Entry{}, nil) {
		empty++
	}
	require.Zero(t, empty, "an empty, non-nil root set traverses nothing")
}

func TestConcurrentAppendAndJoin(t *testing.T) {
	ctx := context.Background()
	identity := fixtureIdentities(t)
	shared := storage.NewMemoryStorage()
	log1 := newLog(t, identity("userA"), oplog.Options{LogID: "R", EntryStorage: shared})
	log2 := newLog(t, identity("userB"), oplog.Options{LogID: "R", EntryStorage: shared})

	var wg sync.WaitGroup
	for w, l := range []*oplog.Log{log1, log2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 25 {
				_, err := l.Append(ctx, fmt.Sprint(w, "-", i), oplog.AppendOptions{ReferencesCount: 4})
				require.NoError(t, err)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 10 {
			require.NoError(t, log1.Join(ctx, log2))
			for range log1.Traverse(ctx, nil, nil) {
			}
		}
	}()
	wg.Wait()
	require.NoError(t, log1.Join(ctx, log2))
	require.NoError(t, log2.Join(ctx, log1))
	require.Len(t, payloads(t, log1), 50)
	require.Equal(t, payloads(t, log1), payloads(t, log2))
}

func TestClockAndConflictResolution(t *testing.T) {
	a, b := oplog.NewClock("A", 1), oplog.NewClock("B", 1)
	require.Negative(t, oplog.CompareClocks(a, b))
	require.Positive(t, oplog.CompareClocks(b, a))
	require.Zero(t, oplog.CompareClocks(a, a))
	require.Negative(t, oplog.CompareClocks(oplog.NewClock("B", 1), oplog.NewClock("A", 2)), "time wins over id")
	require.Equal(t, oplog.NewClock("A", 2), oplog.TickClock(a))

	e := func(id string, time int64) *oplog.Entry { return &oplog.Entry{Clock: oplog.NewClock(id, time)} }
	require.Negative(t, oplog.LastWriteWins(e("A", 1), e("A", 2)))
	require.Positive(t, oplog.LastWriteWins(e("A", 3), e("A", 2)))
	require.Negative(t, oplog.LastWriteWins(e("A", 1), e("B", 1)))
	require.Zero(t, oplog.LastWriteWins(e("A", 1), e("A", 1)))

	byID := func(a, b *oplog.Entry) int {
		return oplog.SortByClockID(a, b, func(*oplog.Entry, *oplog.Entry) int { return 7 })
	}
	require.Equal(t, 7, byID(e("A", 1), e("A", 9)), "same id defers to the resolver")
	require.Negative(t, byID(e("A", 9), e("B", 1)))
}

func TestFindHeads(t *testing.T) {
	a := &oplog.Entry{Hash: "a"}
	b := &oplog.Entry{Hash: "b", Next: []string{"a"}}
	c := &oplog.Entry{Hash: "c", Next: []string{"a"}}
	d := &oplog.Entry{Hash: "d", Next: []string{"b"}}
	require.Equal(t, []*oplog.Entry{c, d}, oplog.FindHeads([]*oplog.Entry{a, b, c, d}))
	require.Empty(t, oplog.FindHeads(nil))
}

func TestCustomSortFn(t *testing.T) {
	ctx := context.Background()
	identity := fixtureIdentities(t)
	// Reverse the default order: first write wins.
	reverse := func(a, b *oplog.Entry) int { return -oplog.LastWriteWins(a, b) }
	l := newLog(t, identity("userA"), oplog.Options{LogID: "S", SortFn: reverse})
	for i := range 3 {
		_, err := l.Append(ctx, i, oplog.AppendOptions{})
		require.NoError(t, err)
	}
	// A linear log still traverses newest to oldest because entries are
	// only reachable through their successors.
	require.Equal(t, []any{int64(0), int64(1), int64(2)}, payloads(t, l))
}
