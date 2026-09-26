package block

import (
	"encoding/hex"
	"math"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
)

func encodeHex(t *testing.T, v any) string {
	t.Helper()
	_, data, err := Encode(v)
	require.NoError(t, err)
	return hex.EncodeToString(data)
}

func TestEncodingMatchesJavaScript(t *testing.T) {
	// Expected bytes produced by @ipld/dag-cbor 9 in Node.js.
	require.Equal(t, "fb3ff8000000000000", encodeHex(t, 1.5), "floats are always 64-bit")
	require.Equal(t, "02", encodeHex(t, 2.0), "integral floats encode as integers, like JS numbers")
	require.Equal(t, "00", encodeHex(t, math.Copysign(0, -1)), "-0 encodes as 0, like JS")
	require.Equal(t,
		"a3626f7063414444636b6579f66576616c75656178",
		encodeHex(t, map[string]any{"op": "ADD", "key": nil, "value": "x"}),
		"map keys are sorted canonically (length first)")
}

func TestRoundTrip(t *testing.T) {
	c, err := cid.Decode("zdpuAsKzwUEa8cz9pkJxxFMxLuP3cutA9PDGoLZytrg4RSVEa")
	require.NoError(t, err)
	in := map[string]any{
		"null":   nil,
		"bool":   true,
		"int":    int64(-42),
		"float":  3.25,
		"string": "hello",
		"bytes":  []byte{0, 1, 2},
		"link":   c,
		"list":   []any{int64(1), "two", []any{}},
		"map":    map[string]any{"nested": map[string]any{}},
	}
	hash, data, err := Encode(in)
	require.NoError(t, err)
	out, err := Decode(data)
	require.NoError(t, err)
	require.Equal(t, in, out)

	hash2, data2, err := Encode(out)
	require.NoError(t, err)
	require.Equal(t, data, data2, "decode then encode is byte-identical")
	require.Equal(t, hash, hash2)
	require.Equal(t, "zdpu", hash[:4], "base58btc CIDv1 dag-cbor")
}

type doc struct {
	ID    string `json:"_id"`
	Count int    `json:"count"`
	Skip  string `json:"-"`
}

func TestEncodeGoTypes(t *testing.T) {
	cases := []struct {
		in   any
		want any
	}{
		{[]string{"a", "b"}, []any{"a", "b"}},
		{[]int{1, 2}, []any{int64(1), int64(2)}},
		{map[string]int{"a": 1}, map[string]any{"a": int64(1)}},
		{uint8(7), int64(7)},
		{float32(0.5), 0.5},
		{doc{ID: "x", Count: 3, Skip: "no"}, map[string]any{"_id": "x", "count": int64(3)}},
		{&doc{ID: "y"}, map[string]any{"_id": "y", "count": int64(0)}},
		{(*doc)(nil), nil},
		{[]byte(nil), []byte{}},
	}
	for _, tc := range cases {
		_, data, err := Encode(tc.in)
		require.NoError(t, err, "%#v", tc.in)
		out, err := Decode(data)
		require.NoError(t, err)
		require.Equal(t, tc.want, out, "%#v", tc.in)
	}
}

func TestEncodeRejects(t *testing.T) {
	for _, v := range []any{math.NaN(), math.Inf(1), uint64(math.MaxUint64), map[int]string{1: "a"}, cid.Undef, make(chan int)} {
		_, _, err := Encode(v)
		require.Error(t, err, "%#v", v)
	}
}

func TestDecodeRejects(t *testing.T) {
	_, err := Decode(nil)
	require.Error(t, err)
	_, err = Decode([]byte{0xff})
	require.Error(t, err)
	_, err = Decode([]byte{0x01, 0x02})
	require.Error(t, err, "trailing bytes after the first item")
}

func TestFieldHelpers(t *testing.T) {
	v, err := Decode(mustEncode(t, map[string]any{"s": "x", "i": 3, "l": []string{"a"}, "bad": []any{1}}))
	require.NoError(t, err)
	m, err := Map(v)
	require.NoError(t, err)

	s, err := String(m, "s")
	require.NoError(t, err)
	require.Equal(t, "x", s)
	i, err := Int(m, "i")
	require.NoError(t, err)
	require.EqualValues(t, 3, i)
	l, err := Strings(m, "l")
	require.NoError(t, err)
	require.Equal(t, []string{"a"}, l)

	_, err = String(m, "i")
	require.Error(t, err)
	_, err = Int(m, "missing")
	require.Error(t, err)
	_, err = Strings(m, "bad")
	require.Error(t, err)
	_, err = Map("not a map")
	require.Error(t, err)
}

func mustEncode(t *testing.T, v any) []byte {
	t.Helper()
	_, data, err := Encode(v)
	require.NoError(t, err)
	return data
}
