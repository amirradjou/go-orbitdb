package databases

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/orbitdb/go-orbitdb/identities/identitytypes"
	"github.com/orbitdb/go-orbitdb/oplog"
	"github.com/orbitdb/go-orbitdb/syncutils"
)

// Store is what every database type provides. OrbitDB.Open returns one;
// type-assert it to *Events, *KeyValue, *KeyValueIndexed or *Documents, or
// use the typed Open helpers of package orbitdb.
type Store interface {
	Type() string
	Address() string
	Name() string
	Identity() *identitytypes.Identity
	Meta() any
	Log() *oplog.Log
	Sync() *syncutils.Sync
	Peers() []peer.ID
	Events() *Emitter
	AccessController() oplog.AccessController
	AddOperation(ctx context.Context, op any) (string, error)
	Close() error
	Drop(ctx context.Context) error
}

// Factory opens a database of one type.
type Factory func(ctx context.Context, p Params) (Store, error)

var (
	typesMu sync.RWMutex
	types   = map[string]Factory{
		EventsType:    func(ctx context.Context, p Params) (Store, error) { return NewEvents(ctx, p) },
		KeyValueType:  func(ctx context.Context, p Params) (Store, error) { return NewKeyValue(ctx, p) },
		DocumentsType: DocumentsFactory(DocumentsOptions{}),
	}
)

// UseDatabaseType registers a database type, replacing any factory
// registered under the same name.
func UseDatabaseType(typ string, f Factory) error {
	if typ == "" {
		return fmt.Errorf("database type does not contain required field 'type'")
	}
	if f == nil {
		return fmt.Errorf("database type %q has no factory", typ)
	}
	typesMu.Lock()
	defer typesMu.Unlock()
	types[typ] = f
	return nil
}

// GetDatabaseType returns the factory registered for typ.
func GetDatabaseType(typ string) (Factory, error) {
	if typ == "" {
		return nil, fmt.Errorf("type not specified")
	}
	typesMu.RLock()
	defer typesMu.RUnlock()
	f, ok := types[typ]
	if !ok {
		return nil, fmt.Errorf("unsupported database type: %q", typ)
	}
	return f, nil
}

// Operation is the payload database types append: {op, key, value}.
type Operation struct {
	Op    string
	Key   any
	Value any
}

func (o Operation) payload() map[string]any {
	return map[string]any{"op": o.Op, "key": o.Key, "value": o.Value}
}

// ParseOperation reads an {op, key, value} payload. ok is false for
// payloads of another shape.
func ParseOperation(payload any) (op Operation, ok bool) {
	m, isMap := payload.(map[string]any)
	if !isMap {
		return Operation{}, false
	}
	o, isString := m["op"].(string)
	if !isString {
		return Operation{}, false
	}
	return Operation{Op: o, Key: m["key"], Value: m["value"]}, true
}

// keyString renders a key the way a JavaScript object key would be: strings
// as they are, numbers in their shortest form.
func keyString(k any) (string, bool) {
	switch v := k.(type) {
	case string:
		return v, true
	case int64:
		return strconv.FormatInt(v, 10), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(v), true
	}
	return "", false
}
