package databases_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/amirradjou/go-orbitdb/databases"
	"github.com/amirradjou/go-orbitdb/identities"
	"github.com/amirradjou/go-orbitdb/identities/identitytypes"
	"github.com/amirradjou/go-orbitdb/internal/testutil"
	"github.com/amirradjou/go-orbitdb/ipfs"
	"github.com/amirradjou/go-orbitdb/oplog"
)

type env struct {
	node     *ipfs.Node
	identity *identitytypes.Identity
	dir      string
}

func newEnv(t *testing.T, user string) *env {
	t.Helper()
	node, err := ipfs.New(context.Background(), ipfs.Options{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = node.Close() })
	ids, err := identities.New(identities.Options{Keystore: testutil.Keystore(t)})
	require.NoError(t, err)
	identity, err := ids.CreateIdentity(context.Background(), identities.CreateOptions{ID: user})
	require.NoError(t, err)
	return &env{node: node, identity: identity, dir: t.TempDir()}
}

func (e *env) params(address string) databases.Params {
	return databases.Params{IPFS: e.node, Identity: e.identity, Address: address, Name: address, Directory: e.dir}
}

func closeOnCleanup(t *testing.T, s interface{ Close() error }) {
	t.Cleanup(func() { _ = s.Close() })
}

func TestKeyValue(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "userA")
	db, err := databases.NewKeyValue(ctx, e.params("/orbitdb/kv"))
	require.NoError(t, err)
	closeOnCleanup(t, db)
	require.Equal(t, "keyvalue", db.Type())
	require.Equal(t, "/orbitdb/kv", db.Address())

	hash, err := db.Put(ctx, "key1", "value1")
	require.NoError(t, err)
	require.NotEmpty(t, hash)
	entry, err := db.Log().Get(ctx, hash)
	require.NoError(t, err)
	require.Equal(t, map[string]any{"op": "PUT", "key": "key1", "value": "value1"}, entry.Payload, "payloads are {op, key, value} maps, as in JS")

	v, err := db.Get(ctx, "key1")
	require.NoError(t, err)
	require.Equal(t, "value1", v)

	_, err = db.Set(ctx, "key1", map[string]any{"n": 2})
	require.NoError(t, err)
	v, err = db.Get(ctx, "key1")
	require.NoError(t, err)
	require.Equal(t, map[string]any{"n": int64(2)}, v)

	_, err = db.Put(ctx, "key2", []any{1, "x"})
	require.NoError(t, err)
	_, err = db.Put(ctx, "key3", nil)
	require.NoError(t, err)
	v, err = db.Get(ctx, "key3")
	require.NoError(t, err)
	require.Nil(t, v, "a stored null is found")

	_, err = db.Del(ctx, "key2")
	require.NoError(t, err)
	_, err = db.Get(ctx, "key2")
	require.ErrorIs(t, err, databases.ErrNotFound)
	_, err = db.Get(ctx, "never")
	require.ErrorIs(t, err, databases.ErrNotFound)

	all, err := db.All(ctx)
	require.NoError(t, err)
	require.Len(t, all, 2)
	require.Equal(t, "key1", all[0].Key)
	require.Equal(t, "key3", all[1].Key)

	var keys []string
	for kv, err := range db.Iterator(ctx, 1) {
		require.NoError(t, err)
		keys = append(keys, kv.Key)
	}
	require.Equal(t, []string{"key3"}, keys, "the most recent write comes first")

	_, err = db.Put(ctx, "", "x")
	require.Error(t, err)
}

func TestKeyValuePersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "userA")
	db, err := databases.NewKeyValue(ctx, e.params("/orbitdb/persist"))
	require.NoError(t, err)
	for i := range 5 {
		_, err := db.Put(ctx, fmt.Sprint("k", i), i)
		require.NoError(t, err)
	}
	require.NoError(t, db.Close())

	// Heads and index are on disk, entries in the node's blockstore.
	db, err = databases.NewKeyValue(ctx, e.params("/orbitdb/persist"))
	require.NoError(t, err)
	closeOnCleanup(t, db)
	all, err := db.All(ctx)
	require.NoError(t, err)
	require.Len(t, all, 5)
	v, err := db.Get(ctx, "k3")
	require.NoError(t, err)
	require.Equal(t, int64(3), v)
}

func TestEvents(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "userA")
	db, err := databases.NewEvents(ctx, e.params("/orbitdb/events"))
	require.NoError(t, err)
	closeOnCleanup(t, db)

	var hashes []string
	for i := range 10 {
		h, err := db.Add(ctx, fmt.Sprint("hello", i))
		require.NoError(t, err)
		hashes = append(hashes, h)
	}
	entry, err := db.Log().Get(ctx, hashes[0])
	require.NoError(t, err)
	require.Equal(t, map[string]any{"op": "ADD", "key": nil, "value": "hello0"}, entry.Payload)

	v, err := db.Get(ctx, hashes[3])
	require.NoError(t, err)
	require.Equal(t, "hello3", v)

	all, err := db.All(ctx)
	require.NoError(t, err)
	require.Len(t, all, 10)
	require.Equal(t, "hello0", all[0].Value)
	require.Equal(t, hashes[9], all[9].Hash)

	var got []any
	for ev, err := range db.Iterator(ctx, oplog.IteratorOptions{LTE: hashes[5], Amount: 3}) {
		require.NoError(t, err)
		got = append(got, ev.Value)
	}
	require.Equal(t, []any{"hello5", "hello4", "hello3"}, got)

	// As in JS, a null event is fine: the payload is the {op, key, value}
	// map, never null itself.
	h, err := db.Add(ctx, nil)
	require.NoError(t, err)
	v, err = db.Get(ctx, h)
	require.NoError(t, err)
	require.Nil(t, v)
}

func TestDocuments(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "userA")
	db, err := databases.NewDocuments(ctx, e.params("/orbitdb/docs"), databases.DocumentsOptions{})
	require.NoError(t, err)
	closeOnCleanup(t, db)
	require.Equal(t, "_id", db.IndexBy())

	_, err = db.Put(ctx, map[string]any{"_id": "hello world", "doc": "all the things"})
	require.NoError(t, err)
	type post struct {
		ID    string   `json:"_id"`
		Title string   `json:"title"`
		Tags  []string `json:"tags"`
	}
	_, err = db.Put(ctx, post{ID: "p1", Title: "first", Tags: []string{"go"}})
	require.NoError(t, err)
	_, err = db.Put(ctx, map[string]any{"_id": "p2", "title": "second", "views": 10})
	require.NoError(t, err)

	doc, err := db.Get(ctx, "p1")
	require.NoError(t, err)
	require.Equal(t, map[string]any{"_id": "p1", "title": "first", "tags": []any{"go"}}, doc.Value)

	_, err = db.Put(ctx, map[string]any{"_id": "p1", "title": "updated"})
	require.NoError(t, err)
	doc, err = db.Get(ctx, "p1")
	require.NoError(t, err)
	require.Equal(t, "updated", doc.Value["title"])

	res, err := db.Query(ctx, func(d map[string]any) bool { return d["views"] == int64(10) })
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.Equal(t, "p2", res[0]["_id"])

	_, err = db.Del(ctx, "p2")
	require.NoError(t, err)
	_, err = db.Get(ctx, "p2")
	require.ErrorIs(t, err, databases.ErrNotFound)
	res, err = db.Query(ctx, func(map[string]any) bool { return true })
	require.NoError(t, err)
	require.Len(t, res, 2, "a deleted document is gone from queries")

	_, err = db.Del(ctx, "p2")
	require.ErrorContains(t, err, "no document with key")
	_, err = db.Put(ctx, map[string]any{"title": "no key"})
	require.ErrorContains(t, err, "doesn't contain field")
	_, err = db.Put(ctx, "not a document")
	require.Error(t, err)

	all, err := db.All(ctx)
	require.NoError(t, err)
	require.Len(t, all, 2)
	require.Equal(t, "hello world", all[0].Key)
	require.Equal(t, "p1", all[1].Key)
}

func TestDocumentsCustomIndex(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "userA")
	db, err := databases.NewDocuments(ctx, e.params("/orbitdb/docs-by-email"), databases.DocumentsOptions{IndexBy: "email"})
	require.NoError(t, err)
	closeOnCleanup(t, db)
	_, err = db.Put(ctx, map[string]any{"email": "a@example.com", "name": "A"})
	require.NoError(t, err)
	doc, err := db.Get(ctx, "a@example.com")
	require.NoError(t, err)
	require.Equal(t, "A", doc.Value["name"])
	_, err = db.Put(ctx, map[string]any{"_id": "x"})
	require.ErrorContains(t, err, `"email"`)
}

func TestKeyValueIndexed(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "userA")
	updates := 0
	p := e.params("/orbitdb/kvi")
	p.OnUpdate = func(context.Context, *oplog.Log, *oplog.Entry) error { updates++; return nil }
	db, err := databases.NewKeyValueIndexed(ctx, p)
	require.NoError(t, err)

	for i := range 5 {
		_, err := db.Put(ctx, fmt.Sprint("key", i), i)
		require.NoError(t, err)
	}
	require.Equal(t, 5, updates, "a user OnUpdate still runs")
	_, err = db.Put(ctx, "key1", "changed")
	require.NoError(t, err)
	_, err = db.Del(ctx, "key3")
	require.NoError(t, err)

	v, err := db.Get(ctx, "key1")
	require.NoError(t, err)
	require.Equal(t, "changed", v)
	_, err = db.Get(ctx, "key3")
	require.ErrorIs(t, err, databases.ErrNotFound)

	all, err := db.All(ctx)
	require.NoError(t, err)
	var keys []string
	for _, kv := range all {
		keys = append(keys, kv.Key)
	}
	require.Equal(t, []string{"key0", "key1", "key2", "key4"}, keys)
	require.NoError(t, db.Close())

	// The index is on disk: reopening reads it without walking the log.
	db, err = databases.NewKeyValueIndexed(ctx, e.params("/orbitdb/kvi"))
	require.NoError(t, err)
	closeOnCleanup(t, db)
	v, err = db.Get(ctx, "key4")
	require.NoError(t, err)
	require.Equal(t, int64(4), v)

	require.NoError(t, db.Drop(ctx))
	_, err = db.Get(ctx, "key4")
	require.ErrorIs(t, err, databases.ErrNotFound)
}

func TestEventsEmitted(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "userA")
	db, err := databases.NewKeyValue(ctx, e.params("/orbitdb/ev"))
	require.NoError(t, err)
	sub := db.Events().Subscribe()

	hash, err := db.Put(ctx, "k", "v")
	require.NoError(t, err)
	ev := <-sub.Events()
	require.Equal(t, databases.EventUpdate, ev.Type)
	require.Equal(t, hash, ev.Entry.Hash)

	require.NoError(t, db.Drop(ctx))
	require.Equal(t, databases.EventDrop, (<-sub.Events()).Type)

	require.NoError(t, db.Close())
	require.Equal(t, databases.EventClose, (<-sub.Events()).Type)
	_, open := <-sub.Events()
	require.False(t, open, "the channel closes after EventClose")
	require.NoError(t, db.Close(), "closing twice is fine")

	late := db.Events().Subscribe()
	_, open = <-late.Events()
	require.False(t, open, "subscribing to a closed database yields a closed channel")

	unsub := newEnv(t, "userB")
	db2, err := databases.NewEvents(ctx, unsub.params("/orbitdb/ev2"))
	require.NoError(t, err)
	closeOnCleanup(t, db2)
	s2 := db2.Events().Subscribe()
	s2.Close()
	_, err = db2.Add(ctx, "x") // must not block on the closed subscription
	require.NoError(t, err)
	require.Equal(t, "update", databases.EventUpdate.String())
}

type denyAll struct{}

func (denyAll) CanAppend(context.Context, *oplog.Entry) (bool, error) { return false, nil }

func TestAccessControllerIsEnforced(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "userA")
	p := e.params("/orbitdb/denied")
	p.AccessController = denyAll{}
	db, err := databases.NewEvents(ctx, p)
	require.NoError(t, err)
	closeOnCleanup(t, db)
	_, err = db.Add(ctx, "x")
	require.ErrorContains(t, err, "not allowed to write")
}

func TestParamsValidation(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "userA")
	_, err := databases.New(ctx, databases.Params{Address: "a"})
	require.Error(t, err)
	_, err = databases.New(ctx, databases.Params{Identity: e.identity})
	require.Error(t, err)
	_, err = databases.New(ctx, databases.Params{Identity: e.identity, Address: "a", Directory: e.dir})
	require.ErrorContains(t, err, "IPFS is required")
}

func TestRegistry(t *testing.T) {
	for _, typ := range []string{"events", "keyvalue", "documents"} {
		_, err := databases.GetDatabaseType(typ)
		require.NoError(t, err, typ)
	}
	_, err := databases.GetDatabaseType("nope")
	require.Error(t, err)
	_, err = databases.GetDatabaseType("")
	require.Error(t, err)
	require.Error(t, databases.UseDatabaseType("", databases.KeyValueIndexedFactory))
	require.NoError(t, databases.UseDatabaseType("indexed-kv", databases.KeyValueIndexedFactory))
	f, err := databases.GetDatabaseType("indexed-kv")
	require.NoError(t, err)

	ctx := context.Background()
	e := newEnv(t, "userA")
	store, err := f(ctx, e.params("/orbitdb/custom"))
	require.NoError(t, err)
	closeOnCleanup(t, store)
	_, ok := store.(*databases.KeyValueIndexed)
	require.True(t, ok)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	require.Eventually(t, cond, 30*time.Second, 50*time.Millisecond)
}

func TestReplication(t *testing.T) {
	ctx := context.Background()
	a, b := newEnv(t, "userA"), newEnv(t, "userB")
	require.NoError(t, b.node.Connect(ctx, a.node.AddrInfo()))

	dbA, err := databases.NewKeyValue(ctx, a.params("/orbitdb/replicated"))
	require.NoError(t, err)
	closeOnCleanup(t, dbA)
	for i := range 10 {
		_, err := dbA.Put(ctx, fmt.Sprint("k", i), i)
		require.NoError(t, err)
	}

	dbB, err := databases.NewKeyValue(ctx, b.params("/orbitdb/replicated"))
	require.NoError(t, err)
	closeOnCleanup(t, dbB)
	events := dbB.Events().Subscribe()
	defer events.Close()

	waitFor(t, func() bool {
		all, err := dbB.All(ctx)
		return err == nil && len(all) == 10
	})
	joined := false
	for !joined {
		select {
		case ev := <-events.Events():
			if ev.Type == databases.EventJoin {
				require.Equal(t, a.node.Host.ID(), ev.Peer)
				joined = true
			}
			require.NotEqual(t, databases.EventError, ev.Type, "%v", ev.Err)
		case <-time.After(30 * time.Second):
			t.Fatal("no join event")
		}
	}

	_, err = dbB.Put(ctx, "from-b", true)
	require.NoError(t, err)
	_, err = dbA.Del(ctx, "k0")
	require.NoError(t, err)
	waitFor(t, func() bool {
		v, err := dbA.Get(ctx, "from-b")
		_, gone := dbB.Get(ctx, "k0")
		return err == nil && v == true && errors.Is(gone, databases.ErrNotFound)
	})
	allA, err := dbA.All(ctx)
	require.NoError(t, err)
	allB, err := dbB.All(ctx)
	require.NoError(t, err)
	require.Equal(t, allA, allB)
	require.Contains(t, dbA.Peers(), b.node.Host.ID())
}
