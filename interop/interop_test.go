//go:build interop

// Package interop runs go-orbitdb against a live @orbitdb/core 4.0.0 peer
// (Helia over TCP) and checks that databases replicate both ways.
//
//	cd interop/js-peer && npm ci && cd ../..
//	go test -tags interop ./interop/
package interop

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	orbitdb "github.com/orbitdb/go-orbitdb"
	"github.com/orbitdb/go-orbitdb/accesscontrollers"
	"github.com/orbitdb/go-orbitdb/databases"
	"github.com/orbitdb/go-orbitdb/encryption"
	"github.com/orbitdb/go-orbitdb/ipfs"
	"github.com/orbitdb/go-orbitdb/oplog"
)

// goPeer is a go-orbitdb node connected to a JS peer.
func goPeer(t *testing.T, js *jsPeer) *orbitdb.OrbitDB {
	t.Helper()
	ctx := context.Background()
	node, err := ipfs.New(ctx, ipfs.Options{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = node.Close() })
	odb, err := orbitdb.New(ctx, orbitdb.Options{IPFS: node, ID: "go-peer", Directory: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = odb.Stop() })
	require.NoError(t, node.Connect(ctx, js.addrInfo()))
	return odb
}

var anyone = orbitdb.WithAccessController(accesscontrollers.IPFS(accesscontrollers.IPFSOptions{Write: []string{"*"}}))

type jsOpened struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Name    string `json:"name"`
}

type jsKV struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
	Hash  string `json:"hash"`
}

type jsValue struct {
	Hash    string `json:"hash"`
	Payload any    `json:"payload"`
}

// requireSameLog checks that both peers hold the same entries in the same
// order.
func requireSameLog(t *testing.T, js *jsPeer, db databases.Store, address string) {
	t.Helper()
	ctx := context.Background()
	var jsValues []jsValue
	js.call("values", map[string]any{"address": address}, &jsValues)
	goValues, err := db.Log().Values(ctx)
	require.NoError(t, err)
	require.Len(t, goValues, len(jsValues))
	for i := range goValues {
		require.Equal(t, jsValues[i].Hash, goValues[i].Hash, "entry %d", i)
	}
}

func TestJSCreatesGoReplicates(t *testing.T) {
	ctx := context.Background()
	js := startJSPeer(t)
	odb := goPeer(t, js)

	var opened jsOpened
	js.call("open", map[string]any{"address": "js-kv", "type": "keyvalue", "write": []string{"*"}}, &opened)
	addr := map[string]any{"address": opened.Address}
	js.call("put", merge(addr, map[string]any{"key": "string", "value": "hello"}), nil)
	js.call("put", merge(addr, map[string]any{"key": "nested", "value": map[string]any{"list": []any{1, 2.5, "x"}, "flag": true, "nothing": nil}}), nil)
	js.call("put", merge(addr, map[string]any{"key": "number", "value": 42}), nil)
	js.call("put", merge(addr, map[string]any{"key": "gone", "value": "soon deleted"}), nil)
	js.call("del", merge(addr, map[string]any{"key": "gone"}), nil)

	// Go knows only the address: manifest, access controller, heads,
	// ancestors and the writer's identity all come from the JS peer.
	db, err := odb.OpenKeyValue(ctx, opened.Address)
	require.NoError(t, err)
	require.Equal(t, "js-kv", db.Name())
	waitFor(t, "the JS entries", func() bool {
		all, err := db.All(ctx)
		return err == nil && len(all) == 3
	})
	v, err := db.Get(ctx, "nested")
	require.NoError(t, err)
	require.Equal(t, map[string]any{"list": []any{int64(1), 2.5, "x"}, "flag": true, "nothing": nil}, v)
	v, err = db.Get(ctx, "number")
	require.NoError(t, err)
	require.Equal(t, int64(42), v)
	_, err = db.Get(ctx, "gone")
	require.ErrorIs(t, err, databases.ErrNotFound)

	_, err = db.Put(ctx, "from-go", map[string]any{"lang": "go", "n": 1.5})
	require.NoError(t, err)
	var jsAll []jsKV
	js.call("waitAll", merge(addr, map[string]any{"count": 4}), &jsAll)
	var fromGo any
	js.call("get", merge(addr, map[string]any{"key": "from-go"}), &fromGo)
	require.Equal(t, map[string]any{"lang": "go", "n": 1.5}, fromGo)

	requireSameLog(t, js, db, opened.Address)
	js.requireNoErrors()
}

func TestGoCreatesJSReplicates(t *testing.T) {
	ctx := context.Background()
	js := startJSPeer(t)
	odb := goPeer(t, js)

	db, err := odb.OpenEvents(ctx, "go-events", anyone)
	require.NoError(t, err)
	for i := range 10 {
		_, err := db.Add(ctx, fmt.Sprint("event ", i))
		require.NoError(t, err)
	}

	var opened jsOpened
	js.call("open", map[string]any{"address": db.Address()}, &opened)
	require.Equal(t, db.Address(), opened.Address)
	require.Equal(t, "events", opened.Type)
	require.Equal(t, "go-events", opened.Name)
	addr := map[string]any{"address": db.Address()}

	var jsAll []struct {
		Hash  string `json:"hash"`
		Value string `json:"value"`
	}
	js.call("waitAll", merge(addr, map[string]any{"count": 10}), &jsAll)
	goAll, err := db.All(ctx)
	require.NoError(t, err)
	require.Len(t, jsAll, 10)
	for i := range goAll {
		require.Equal(t, goAll[i].Hash, jsAll[i].Hash)
		require.Equal(t, goAll[i].Value, jsAll[i].Value)
	}

	js.call("add", merge(addr, map[string]any{"value": "from js"}), nil)
	waitFor(t, "the JS event", func() bool {
		all, err := db.All(ctx)
		return err == nil && len(all) == 11 && all[10].Value == "from js"
	})
	requireSameLog(t, js, db, db.Address())
	js.requireNoErrors()
}

func TestConcurrentWritesConverge(t *testing.T) {
	ctx := context.Background()
	js := startJSPeer(t)
	odb := goPeer(t, js)

	db, err := odb.OpenKeyValue(ctx, "concurrent", anyone)
	require.NoError(t, err)
	_, err = db.Put(ctx, "start", true)
	require.NoError(t, err)
	js.call("open", map[string]any{"address": db.Address()}, nil)
	addr := map[string]any{"address": db.Address()}
	js.call("waitAll", merge(addr, map[string]any{"count": 1}), nil)

	const n = 25
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range n {
			_, err := db.Put(ctx, fmt.Sprint("go-", i), i)
			require.NoError(t, err)
			// Overwrite a shared key so last-write-wins has work to do.
			_, err = db.Put(ctx, "shared", fmt.Sprint("go-", i))
			require.NoError(t, err)
		}
	}()
	for i := range n {
		js.call("put", merge(addr, map[string]any{"key": fmt.Sprint("js-", i), "value": i}), nil)
		js.call("put", merge(addr, map[string]any{"key": "shared", "value": fmt.Sprint("js-", i)}), nil)
	}
	wg.Wait()

	total := 2*n + 2 // go-*, js-*, start, shared
	js.call("waitAll", merge(addr, map[string]any{"count": total}), nil)
	waitFor(t, "all JS writes in Go", func() bool {
		all, err := db.All(ctx)
		return err == nil && len(all) == total
	})
	// Replication is eventually consistent: wait until both sides hold
	// every entry, then require the same order and the same winner.
	waitFor(t, "identical logs", func() bool {
		var jsValues []jsValue
		js.call("values", addr, &jsValues)
		goValues, err := db.Log().Values(ctx)
		return err == nil && len(goValues) == len(jsValues) && len(goValues) == 4*n+1
	})
	requireSameLog(t, js, db, db.Address())
	var jsShared any
	js.call("get", merge(addr, map[string]any{"key": "shared"}), &jsShared)
	goShared, err := db.Get(ctx, "shared")
	require.NoError(t, err)
	require.Equal(t, jsShared, goShared, "both peers pick the same last write")
	js.requireNoErrors()
}

func TestDocumentsBothWays(t *testing.T) {
	ctx := context.Background()
	js := startJSPeer(t)
	odb := goPeer(t, js)

	var opened jsOpened
	js.call("open", map[string]any{"address": "js-docs", "type": "documents", "write": []string{"*"}}, &opened)
	addr := map[string]any{"address": opened.Address}
	js.call("putDoc", merge(addr, map[string]any{"doc": map[string]any{"_id": "a", "title": "from js", "tags": []string{"x"}}}), nil)

	db, err := odb.OpenDocuments(ctx, opened.Address)
	require.NoError(t, err)
	waitFor(t, "the JS document", func() bool {
		doc, err := db.Get(ctx, "a")
		return err == nil && doc.Value["title"] == "from js"
	})
	_, err = db.Put(ctx, map[string]any{"_id": "b", "title": "from go"})
	require.NoError(t, err)
	_, err = db.Del(ctx, "a")
	require.NoError(t, err)

	waitFor(t, "the Go changes in JS", func() bool {
		var docs []map[string]any
		js.call("all", addr, &docs)
		return len(docs) == 1 && docs[0]["key"] == "b"
	})
	requireSameLog(t, js, db, opened.Address)
	js.requireNoErrors()
}

func TestWriteAccessIsShared(t *testing.T) {
	ctx := context.Background()
	js := startJSPeer(t)
	odb := goPeer(t, js)

	// The JS default: only the creator may write.
	var opened jsOpened
	js.call("open", map[string]any{"address": "js-only", "type": "keyvalue"}, &opened)
	js.call("put", map[string]any{"address": opened.Address, "key": "k", "value": "v"}, nil)

	db, err := odb.OpenKeyValue(ctx, opened.Address)
	require.NoError(t, err)
	waitFor(t, "the JS entry", func() bool {
		v, err := db.Get(ctx, "k")
		return err == nil && v == "v"
	})
	_, err = db.Put(ctx, "k", "go was here")
	require.ErrorContains(t, err, "not allowed to write", "Go enforces the JS access controller")
	js.requireNoErrors()
}

func TestOrbitDBAccessControllerGrant(t *testing.T) {
	ctx := context.Background()
	js := startJSPeer(t)
	odb := goPeer(t, js)

	var opened jsOpened
	js.call("open", map[string]any{"address": "managed", "type": "events", "access": "orbitdb"}, &opened)
	addr := map[string]any{"address": opened.Address}
	js.call("add", merge(addr, map[string]any{"value": "first"}), nil)

	db, err := odb.OpenEvents(ctx, opened.Address)
	require.NoError(t, err)
	ac, ok := db.AccessController().(*accesscontrollers.OrbitDBAccessController)
	require.True(t, ok, "Go loads the JS orbitdb access controller from the manifest")
	waitFor(t, "the first event", func() bool {
		all, err := db.All(ctx)
		return err == nil && len(all) == 1
	})
	_, err = db.Add(ctx, "denied")
	require.ErrorContains(t, err, "not allowed to write")

	js.call("grant", merge(addr, map[string]any{"capability": "write", "id": odb.Identity().ID}), nil)
	waitFor(t, "the grant to replicate", func() bool {
		ok, err := ac.HasCapability(ctx, accesscontrollers.CapabilityWrite, odb.Identity().ID)
		return err == nil && ok
	})
	_, err = db.Add(ctx, "granted")
	require.NoError(t, err)
	var jsAll []map[string]any
	js.call("waitAll", merge(addr, map[string]any{"count": 2}), &jsAll)
	require.Equal(t, "granted", jsAll[1]["value"])
	js.requireNoErrors()
}

func TestEncryptedDatabase(t *testing.T) {
	ctx := context.Background()
	js := startJSPeer(t)
	odb := goPeer(t, js)

	const password = "correct horse battery staple"
	var opened jsOpened
	js.call("open", map[string]any{"address": "secret", "type": "keyvalue", "write": []string{"*"}, "password": password}, &opened)
	addr := map[string]any{"address": opened.Address}
	js.call("put", merge(addr, map[string]any{"key": "js", "value": "encrypted by js"}), nil)

	data, err := encryption.NewSimple([]byte(password))
	require.NoError(t, err)
	replication, err := encryption.NewSimple([]byte(password))
	require.NoError(t, err)
	db, err := odb.OpenKeyValue(ctx, opened.Address, orbitdb.WithEncryption(oplog.Encryption{Data: data, Replication: replication}))
	require.NoError(t, err)
	waitFor(t, "the encrypted JS entry", func() bool {
		v, err := db.Get(ctx, "js")
		return err == nil && v == "encrypted by js"
	})

	hash, err := db.Put(ctx, "go", "encrypted by go")
	require.NoError(t, err)
	raw, err := db.Log().Storage().Get(ctx, hash)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "encrypted by go")
	var jsAll []jsKV
	js.call("waitAll", merge(addr, map[string]any{"count": 2}), &jsAll)
	var fromGo any
	js.call("get", merge(addr, map[string]any{"key": "go"}), &fromGo)
	require.Equal(t, "encrypted by go", fromGo)
	requireSameLog(t, js, db, opened.Address)
	js.requireNoErrors()
}

func merge(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}
