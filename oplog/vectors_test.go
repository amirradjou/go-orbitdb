package oplog_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/amirradjou/go-orbitdb/identities"
	"github.com/amirradjou/go-orbitdb/identities/identitytypes"
	"github.com/amirradjou/go-orbitdb/internal/testutil"
	"github.com/amirradjou/go-orbitdb/oplog"
)

// These tests replay the scenarios of tools/jsvectors/generate.mjs and
// require byte-for-byte the results @orbitdb/core 4.0.0 produced.

func fixtureIdentities(t *testing.T) func(name string) *identitytypes.Identity {
	t.Helper()
	ids, err := identities.New(identities.Options{Keystore: testutil.Keystore(t)})
	require.NoError(t, err)
	cache := map[string]*identitytypes.Identity{}
	return func(name string) *identitytypes.Identity {
		if id, ok := cache[name]; ok {
			return id
		}
		id, err := ids.CreateIdentity(context.Background(), identities.CreateOptions{ID: name})
		require.NoError(t, err)
		cache[name] = id
		return id
	}
}

func TestIdentityVectors(t *testing.T) {
	identity := fixtureIdentities(t)
	for name, want := range testutil.JSVectors(t).Identities {
		got := identity(name)
		require.Equal(t, want.ID, got.ID, name)
		require.Equal(t, want.PublicKey, got.PublicKey, name)
		require.Equal(t, want.Signatures["id"], got.Signatures.ID, name)
		require.Equal(t, want.Signatures["publicKey"], got.Signatures.PublicKey, name)
		require.Equal(t, want.Hash, got.Hash, name)
		require.Equal(t, []byte(want.Bytes), got.Bytes, name)
	}
}

// entryPayloads are the Go values for the payloads named in the vectors.
var entryPayloads = map[string]any{
	"string":         "hello",
	"string2":        "hello world",
	"unicode":        "héllo 世界 🌍",
	"int":            42,
	"negative":       -7,
	"zero":           0,
	"maxSafeInteger": int64(1<<53 - 1),
	"float":          3.25,
	"bool":           true,
	"bytes":          []byte{1, 2, 3},
	"list":           []any{1, "two", nil, []any{3}},
	"map": map[string]any{"op": "PUT", "key": "k", "value": map[string]any{
		"nested": []any{1, 2.5, "x"}, "flag": false, "nothing": nil,
	}},
	"eventsAdd":   map[string]any{"op": "ADD", "key": nil, "value": "x"},
	"documentPut": map[string]any{"op": "PUT", "key": "doc1", "value": map[string]any{"_id": "doc1", "title": "hi", "views": 10}},
}

func TestEntryVectors(t *testing.T) {
	ctx := context.Background()
	identity := fixtureIdentities(t)
	for _, v := range testutil.JSVectors(t).Entries {
		t.Run(v.Name, func(t *testing.T) {
			opts := oplog.EntryOptions{Next: v.Next, Refs: v.Refs}
			payload, ok := entryPayloads[v.Name]
			if v.Name == "withClockNextRefs" {
				payload, ok = v.Payload, true
				clock := oplog.NewClock(identity(v.Writer).PublicKey, v.ClockTime)
				opts.Clock = &clock
			}
			require.True(t, ok, "no Go payload for %s", v.Name)

			// Creating the entry in Go gives the JS bytes and hash.
			entry, err := oplog.CreateEntry(ctx, identity(v.Writer), v.LogID, payload, opts)
			require.NoError(t, err)
			hash, data, err := oplog.EncodeEntry(ctx, entry, oplog.Encryption{})
			require.NoError(t, err)
			require.Equal(t, v.Hash, hash)
			require.Equal(t, []byte(v.Bytes), data)

			// Decoding the JS bytes gives a verifiable entry that re-encodes
			// identically.
			decoded, err := oplog.DecodeEntry(ctx, v.Bytes, oplog.Encryption{})
			require.NoError(t, err)
			require.Equal(t, v.Hash, decoded.Hash)
			ok, err = oplog.VerifyEntry(decoded)
			require.NoError(t, err)
			require.True(t, ok)
			_, again, err := oplog.EncodeEntry(ctx, decoded, oplog.Encryption{})
			require.NoError(t, err)
			require.Equal(t, []byte(v.Bytes), again)
		})
	}
}

func jsonEqual(t *testing.T, want, got any, msgAndArgs ...any) {
	t.Helper()
	w, err := json.Marshal(want)
	require.NoError(t, err)
	g, err := json.Marshal(got)
	require.NoError(t, err)
	require.JSONEq(t, string(w), string(g), msgAndArgs...)
}

func TestLogScenarioVectors(t *testing.T) {
	for name, sc := range testutil.JSVectors(t).Logs {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			identity := fixtureIdentities(t)
			logs := map[string]*oplog.Log{}
			for key, writer := range sc.Writers {
				l, err := oplog.NewLog(ctx, identity(writer), oplog.Options{LogID: sc.LogID})
				require.NoError(t, err)
				logs[key] = l
			}
			for i, op := range sc.Ops {
				switch op[0] {
				case "append":
					e, err := logs[op[1].(string)].Append(ctx, op[2], oplog.AppendOptions{ReferencesCount: int(op[3].(float64))})
					require.NoError(t, err)
					require.Equal(t, sc.Results[i], e.Hash, "op %d %v", i, op)
				case "join":
					require.NoError(t, logs[op[1].(string)].Join(ctx, logs[op[2].(string)]), "op %d", i)
				case "joinEntry":
					into, from := logs[op[1].(string)], logs[op[2].(string)]
					values, err := from.Values(ctx)
					require.NoError(t, err)
					idx := int(op[3].(float64))
					if idx < 0 {
						idx += len(values)
					}
					require.NoError(t, into.Storage().Merge(ctx, from.Storage()))
					updated, err := into.JoinEntry(ctx, values[idx])
					require.NoError(t, err)
					require.Equal(t, sc.Results[i], updated, "op %d", i)
				default:
					t.Fatalf("unknown op %v", op)
				}
			}
			for key, want := range sc.Final {
				l := logs[key]
				values, err := l.Values(ctx)
				require.NoError(t, err)
				require.Len(t, values, len(want.Values), key)
				for i, w := range want.Values {
					got := values[i]
					require.Equal(t, w.Hash, got.Hash, "%s value %d", key, i)
					require.Equal(t, w.Next, got.Next, "%s value %d next", key, i)
					require.Equal(t, w.Refs, got.Refs, "%s value %d refs", key, i)
					require.Equal(t, w.Clock.ID, got.Clock.ID)
					require.Equal(t, w.Clock.Time, got.Clock.Time)
					jsonEqual(t, w.Payload, got.Payload, "%s value %d payload", key, i)
				}
				heads, err := l.Heads(ctx)
				require.NoError(t, err)
				headHashes := make([]string, len(heads))
				for i, h := range heads {
					headHashes[i] = h.Hash
				}
				require.Equal(t, want.Heads, headHashes, "%s heads", key)
				clock, err := l.Clock(ctx)
				require.NoError(t, err)
				require.Equal(t, want.Clock.Time, clock.Time)
				require.Equal(t, want.Clock.ID, clock.ID)
			}
		})
	}
}

func TestIteratorVectors(t *testing.T) {
	ctx := context.Background()
	v := testutil.JSVectors(t).Iterators
	identity := fixtureIdentities(t)
	l, err := oplog.NewLog(ctx, identity(v.Writer), oplog.Options{LogID: v.LogID})
	require.NoError(t, err)
	for i := range v.Size {
		e, err := l.Append(ctx, fmt.Sprint("entry", i), oplog.AppendOptions{})
		require.NoError(t, err)
		require.Equal(t, v.Hashes[i], e.Hash)
	}
	for _, c := range v.Cases {
		opts := oplog.IteratorOptions{}
		at := func(i *int) string {
			if i == nil {
				return ""
			}
			return v.Hashes[*i]
		}
		opts.GT, opts.GTE, opts.LT, opts.LTE = at(c.Options.GT), at(c.Options.GTE), at(c.Options.LT), at(c.Options.LTE)
		if c.Options.Amount != nil {
			opts.Amount = *c.Options.Amount
		}
		var got []string
		for e, err := range l.Iterator(ctx, opts) {
			require.NoError(t, err)
			got = append(got, e.Payload.(string))
		}
		want := c.Payloads
		if len(want) == 0 {
			want = nil
		}
		desc, _ := json.Marshal(c.Options)
		require.Equal(t, want, got, "options %s", desc)
	}
}

// toyCipher matches the deterministic cipher of the vector generator.
type toyCipher struct{}

func (toyCipher) Encrypt(_ context.Context, b []byte) ([]byte, error) {
	out := []byte{0xde, 0xad, 0xbe, 0xef}
	for _, c := range b {
		out = append(out, c^0x5a)
	}
	return out, nil
}

func (toyCipher) Decrypt(_ context.Context, b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("short ciphertext")
	}
	out := make([]byte, 0, len(b)-4)
	for _, c := range b[4:] {
		out = append(out, c^0x5a)
	}
	return out, nil
}

func TestEncryptionVectors(t *testing.T) {
	ctx := context.Background()
	identity := fixtureIdentities(t)
	modes := map[string]oplog.Encryption{
		"data":        {Data: toyCipher{}},
		"replication": {Replication: toyCipher{}},
		"both":        {Data: toyCipher{}, Replication: toyCipher{}},
	}
	for name, want := range testutil.JSVectors(t).Encryption {
		t.Run(name, func(t *testing.T) {
			l, err := oplog.NewLog(ctx, identity(want.Writer), oplog.Options{LogID: want.LogID, Encryption: modes[name]})
			require.NoError(t, err)
			payloads := []any{"secret", map[string]any{"op": "PUT", "key": "k", "value": 1}, "last"}
			for i, p := range payloads {
				e, err := l.Append(ctx, p, oplog.AppendOptions{ReferencesCount: 16})
				require.NoError(t, err)
				require.Equal(t, want.Appended[i].Hash, e.Hash)
				stored, err := l.Storage().Get(ctx, e.Hash)
				require.NoError(t, err)
				require.Equal(t, []byte(want.Appended[i].Bytes), stored)
			}
			values, err := l.Values(ctx)
			require.NoError(t, err)
			got := make([]any, len(values))
			for i, v := range values {
				got[i] = v.Payload
				ok, err := oplog.VerifyEntry(v)
				require.NoError(t, err)
				require.True(t, ok, "decrypted entries still verify")
			}
			jsonEqual(t, want.Payloads, got)
		})
	}
}
