// Package block encodes and decodes OrbitDB's dag-cbor blocks.
//
// It plays the role multiformats/block plays in @orbitdb/core: values are
// encoded as canonical dag-cbor and addressed by a CIDv1 (dag-cbor codec,
// sha2-256) rendered in base58btc, e.g. "zdpu...".
//
// Values are plain Go values. Encoding accepts nil, bool, integers, floats,
// string, []byte, cid.Cid, slices, arrays, maps with string keys and
// datamodel.Node; other types (structs, pointers) are converted through
// encoding/json first. Decoding produces nil, bool, int64, float64, string,
// []byte, cid.Cid, []any and map[string]any.
//
// Numbers follow JavaScript semantics so blocks re-encode identically on
// both sides: a float with an integral value in the safe-integer range is
// encoded as an integer, exactly as @ipld/dag-cbor encodes a JS number.
package block

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"

	"github.com/ipfs/go-cid"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/datamodel"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/multiformats/go-multibase"
	mh "github.com/multiformats/go-multihash"
)

// maxSafeInteger is JavaScript's Number.MAX_SAFE_INTEGER.
const maxSafeInteger = 1<<53 - 1

// Encode encodes v as dag-cbor and returns its hash and bytes.
func Encode(v any) (hash string, data []byte, err error) {
	n, err := ToNode(v)
	if err != nil {
		return "", nil, err
	}
	var buf bytes.Buffer
	if err := dagcbor.Encode(n, &buf); err != nil {
		return "", nil, fmt.Errorf("block: encode: %w", err)
	}
	data = buf.Bytes()
	hash, err = Hash(data)
	return hash, data, err
}

// Decode decodes a dag-cbor block into a Go value.
func Decode(data []byte) (any, error) {
	if len(data) == 0 {
		return nil, errors.New("block: empty block")
	}
	nb := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(nb, bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("block: decode: %w", err)
	}
	return FromNode(nb.Build())
}

// CID returns the CIDv1 (dag-cbor, sha2-256) of data.
func CID(data []byte) (cid.Cid, error) {
	sum, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.DagCBOR, sum), nil
}

// Hash returns the base58btc string of the CID of data, the form OrbitDB
// uses for entry, identity and manifest hashes.
func Hash(data []byte) (string, error) {
	c, err := CID(data)
	if err != nil {
		return "", err
	}
	return c.StringOfBase(multibase.Base58BTC)
}

// ToNode converts a Go value to an IPLD data model node.
func ToNode(v any) (datamodel.Node, error) {
	nb := basicnode.Prototype.Any.NewBuilder()
	if err := assemble(nb, v); err != nil {
		return nil, err
	}
	return nb.Build(), nil
}

func assemble(na datamodel.NodeAssembler, v any) error {
	switch x := v.(type) {
	case nil:
		return na.AssignNull()
	case datamodel.Node:
		return na.AssignNode(x)
	case bool:
		return na.AssignBool(x)
	case string:
		return na.AssignString(x)
	case []byte:
		return na.AssignBytes(x)
	case cid.Cid:
		if !x.Defined() {
			return errors.New("block: undefined CID")
		}
		return na.AssignLink(cidlink.Link{Cid: x})
	case *cid.Cid:
		if x == nil {
			return na.AssignNull()
		}
		return assemble(na, *x)
	case int:
		return na.AssignInt(int64(x))
	case int8:
		return na.AssignInt(int64(x))
	case int16:
		return na.AssignInt(int64(x))
	case int32:
		return na.AssignInt(int64(x))
	case int64:
		return na.AssignInt(x)
	case uint8:
		return na.AssignInt(int64(x))
	case uint16:
		return na.AssignInt(int64(x))
	case uint32:
		return na.AssignInt(int64(x))
	case uint:
		return assembleUint(na, uint64(x))
	case uint64:
		return assembleUint(na, x)
	case float32:
		return assembleFloat(na, float64(x))
	case float64:
		return assembleFloat(na, x)
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return na.AssignInt(i)
		}
		f, err := x.Float64()
		if err != nil {
			return fmt.Errorf("block: invalid number %q", x)
		}
		return assembleFloat(na, f)
	case []any:
		la, err := na.BeginList(int64(len(x)))
		if err != nil {
			return err
		}
		for _, item := range x {
			if err := assemble(la.AssembleValue(), item); err != nil {
				return err
			}
		}
		return la.Finish()
	case []string:
		la, err := na.BeginList(int64(len(x)))
		if err != nil {
			return err
		}
		for _, item := range x {
			if err := la.AssembleValue().AssignString(item); err != nil {
				return err
			}
		}
		return la.Finish()
	case map[string]any:
		return assembleMap(na, len(x), sortedKeys(x), func(k string) any { return x[k] })
	case map[string]string:
		return assembleMap(na, len(x), sortedKeys(x), func(k string) any { return x[k] })
	}
	return assembleReflect(na, v)
}

func assembleUint(na datamodel.NodeAssembler, x uint64) error {
	if x > math.MaxInt64 {
		return fmt.Errorf("block: integer %d overflows int64", x)
	}
	return na.AssignInt(int64(x))
}

func assembleFloat(na datamodel.NodeAssembler, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("block: %v cannot be encoded", f)
	}
	if f == math.Trunc(f) && math.Abs(f) <= maxSafeInteger {
		return na.AssignInt(int64(f))
	}
	return na.AssignFloat(f)
}

func assembleMap(na datamodel.NodeAssembler, n int, keys []string, get func(string) any) error {
	ma, err := na.BeginMap(int64(n))
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := ma.AssembleKey().AssignString(k); err != nil {
			return err
		}
		if err := assemble(ma.AssembleValue(), get(k)); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
	}
	return ma.Finish()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// assembleReflect handles slices, arrays and string-keyed maps of any
// element type, and falls back to JSON for everything else.
func assembleReflect(na datamodel.NodeAssembler, v any) error {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return na.AssignNull()
		}
		la, err := na.BeginList(int64(rv.Len()))
		if err != nil {
			return err
		}
		for i := range rv.Len() {
			if err := assemble(la.AssembleValue(), rv.Index(i).Interface()); err != nil {
				return err
			}
		}
		return la.Finish()
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("block: map keys must be strings, got %s", rv.Type().Key())
		}
		if rv.IsNil() {
			return na.AssignNull()
		}
		keys := make([]string, 0, rv.Len())
		for _, k := range rv.MapKeys() {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		return assembleMap(na, len(keys), keys, func(k string) any {
			return rv.MapIndex(reflect.ValueOf(k).Convert(rv.Type().Key())).Interface()
		})
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return na.AssignNull()
		}
	}
	// Structs and anything else: go through JSON so struct tags apply.
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("block: cannot encode %T: %w", v, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return err
	}
	return assemble(na, generic)
}

// FromNode converts an IPLD data model node to a Go value.
func FromNode(n datamodel.Node) (any, error) {
	switch n.Kind() {
	case datamodel.Kind_Null:
		return nil, nil
	case datamodel.Kind_Bool:
		return n.AsBool()
	case datamodel.Kind_Int:
		return n.AsInt()
	case datamodel.Kind_Float:
		return n.AsFloat()
	case datamodel.Kind_String:
		return n.AsString()
	case datamodel.Kind_Bytes:
		b, err := n.AsBytes()
		if b == nil && err == nil {
			b = []byte{} // keep empty bytes distinct from null
		}
		return b, err
	case datamodel.Kind_Link:
		l, err := n.AsLink()
		if err != nil {
			return nil, err
		}
		cl, ok := l.(cidlink.Link)
		if !ok {
			return nil, fmt.Errorf("block: unsupported link type %T", l)
		}
		return cl.Cid, nil
	case datamodel.Kind_List:
		out := make([]any, 0, n.Length())
		it := n.ListIterator()
		for !it.Done() {
			_, item, err := it.Next()
			if err != nil {
				return nil, err
			}
			v, err := FromNode(item)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case datamodel.Kind_Map:
		out := make(map[string]any, n.Length())
		it := n.MapIterator()
		for !it.Done() {
			k, item, err := it.Next()
			if err != nil {
				return nil, err
			}
			key, err := k.AsString()
			if err != nil {
				return nil, err
			}
			v, err := FromNode(item)
			if err != nil {
				return nil, err
			}
			out[key] = v
		}
		return out, nil
	}
	return nil, fmt.Errorf("block: unsupported kind %s", n.Kind())
}

// Map asserts that v is a map, as a decoded block's root usually is.
func Map(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("block: expected a map, got %T", v)
	}
	return m, nil
}

// String returns m[key] as a string.
func String(m map[string]any, key string) (string, error) {
	s, ok := m[key].(string)
	if !ok {
		return "", fmt.Errorf("block: field %q: expected a string, got %T", key, m[key])
	}
	return s, nil
}

// Int returns m[key] as an int64.
func Int(m map[string]any, key string) (int64, error) {
	i, ok := m[key].(int64)
	if !ok {
		return 0, fmt.Errorf("block: field %q: expected an integer, got %T", key, m[key])
	}
	return i, nil
}

// Strings returns m[key] as a []string.
func Strings(m map[string]any, key string) ([]string, error) {
	list, ok := m[key].([]any)
	if !ok {
		return nil, fmt.Errorf("block: field %q: expected a list, got %T", key, m[key])
	}
	out := make([]string, len(list))
	for i, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("block: field %q[%d]: expected a string, got %T", key, i, item)
		}
		out[i] = s
	}
	return out, nil
}
