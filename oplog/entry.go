package oplog

import (
	"context"
	"errors"
	"fmt"

	"github.com/orbitdb/go-orbitdb/identities/identitytypes"
	"github.com/orbitdb/go-orbitdb/internal/block"
	"github.com/orbitdb/go-orbitdb/keystore"
)

// EntryVersion is the version tag of the entry format ("v" field).
const EntryVersion = 2

// Entry is a signed, content-addressed log entry.
//
// Its dag-cbor encoding is byte-compatible with @orbitdb/core 4: the map
// {id, payload, next, refs, clock: {id, time}, v, key, identity, sig},
// where sig signs the encoding of the first six fields.
type Entry struct {
	// ID is the id of the log the entry belongs to.
	ID string
	// Payload is any value dag-cbor can encode; see package block for the
	// Go types it maps to.
	Payload any
	// Next holds the hashes of the log heads the entry was appended on.
	Next []string
	// Refs holds hashes of older entries, to speed up traversal.
	Refs  []string
	Clock Clock
	V     int64
	// Key is the public key of the writer's identity.
	Key string
	// Identity is the hash of the writer's identity block.
	Identity string
	// Sig is the writer's signature of the entry.
	Sig string
	// Hash is the base58btc CID of the stored entry block. It is set once
	// the entry has been stored or decoded.
	Hash string

	// encryptedPayload is the ciphertext stored in place of Payload when
	// the log encrypts payloads.
	encryptedPayload []byte
	// block is the stored block Hash addresses, once known. Joined entries
	// are stored with these exact bytes: re-encoding an encrypted entry
	// would produce different ciphertext and so a different hash.
	block []byte
}

// Encrypter encrypts and decrypts bytes. An implementation is given to a log
// through Encryption.
type Encrypter interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

// Encryption configures the optional encryption hooks of @orbitdb/core 4.
// Both are off when nil.
type Encryption struct {
	// Replication encrypts whole entry blocks, so storage and the network
	// only see ciphertext. The stored block is the dag-cbor byte string of
	// the ciphertext.
	Replication Encrypter
	// Data encrypts entry payloads. The payload is encoded as dag-cbor,
	// encrypted, and the ciphertext is what gets signed and stored.
	Data Encrypter
}

// EntryOptions configures CreateEntry.
type EntryOptions struct {
	// Clock of the entry. Defaults to time 0 on the identity's public key.
	Clock *Clock
	Next  []string
	Refs  []string
	// EncryptPayload, if set, encrypts the payload (see Encryption.Data).
	EncryptPayload Encrypter
}

// CreateEntry creates and signs an entry for log logID. The entry is not
// stored; its Hash is empty until it is.
func CreateEntry(ctx context.Context, identity *identitytypes.Identity, logID string, payload any, opts EntryOptions) (*Entry, error) {
	if identity == nil {
		return nil, errors.New("identity is required, cannot create entry")
	}
	if logID == "" {
		return nil, errors.New("entry requires an id")
	}
	if payload == nil {
		return nil, errors.New("entry requires a payload")
	}
	clock := NewClock(identity.PublicKey, 0)
	if opts.Clock != nil {
		clock = *opts.Clock
	}
	entry := &Entry{
		ID:      logID,
		Payload: payload,
		Next:    nonNil(opts.Next),
		Refs:    nonNil(opts.Refs),
		Clock:   clock,
		V:       EntryVersion,
	}
	if opts.EncryptPayload != nil {
		_, plain, err := block.Encode(payload)
		if err != nil {
			return nil, fmt.Errorf("encode payload: %w", err)
		}
		if entry.encryptedPayload, err = opts.EncryptPayload.Encrypt(ctx, plain); err != nil {
			return nil, fmt.Errorf("encrypt payload: %w", err)
		}
	}
	_, signed, err := block.Encode(entry.signedValue())
	if err != nil {
		return nil, err
	}
	sig, err := identity.Sign(ctx, signed)
	if err != nil {
		return nil, err
	}
	entry.Key = identity.PublicKey
	entry.Identity = identity.Hash
	entry.Sig = sig
	return entry, nil
}

// storedPayload is the payload as it appears in the block.
func (e *Entry) storedPayload() any {
	if e.encryptedPayload != nil {
		return e.encryptedPayload
	}
	return e.Payload
}

// signedValue is the part of the entry the signature covers.
func (e *Entry) signedValue() map[string]any {
	return map[string]any{
		"id":      e.ID,
		"payload": e.storedPayload(),
		"next":    nonNil(e.Next),
		"refs":    nonNil(e.Refs),
		"clock":   map[string]any{"id": e.Clock.ID, "time": e.Clock.Time},
		"v":       e.V,
	}
}

// VerifyEntry reports whether the entry's signature was made by the key in
// entry.Key. It does not check that the key belongs to entry.Identity; an
// access controller does that.
func VerifyEntry(entry *Entry) (bool, error) {
	if !IsEntry(entry) {
		return false, errors.New("invalid log entry")
	}
	if entry.Key == "" {
		return false, errors.New("entry doesn't have a key")
	}
	if entry.Sig == "" {
		return false, errors.New("entry doesn't have a signature")
	}
	_, signed, err := block.Encode(entry.signedValue())
	if err != nil {
		return false, err
	}
	return keystore.VerifyMessage(entry.Sig, entry.Key, signed), nil
}

// IsEntry reports whether entry has the fields every entry must have.
func IsEntry(entry *Entry) bool {
	return entry != nil && entry.ID != "" && entry.Payload != nil && entry.V != 0
}

// IsEqual reports whether a and b are the same stored entry.
func IsEqual(a, b *Entry) bool {
	return a != nil && b != nil && a.Hash != "" && a.Hash == b.Hash
}

// EncodeEntry returns the hash and bytes of the block entry is stored as.
func EncodeEntry(ctx context.Context, entry *Entry, enc Encryption) (hash string, data []byte, err error) {
	value := entry.signedValue()
	value["key"] = entry.Key
	value["identity"] = entry.Identity
	value["sig"] = entry.Sig
	hash, data, err = block.Encode(value)
	if err != nil || enc.Replication == nil {
		return hash, data, err
	}
	ciphertext, err := enc.Replication.Encrypt(ctx, data)
	if err != nil {
		return "", nil, fmt.Errorf("encrypt entry: %w", err)
	}
	return block.Encode(ciphertext)
}

// DecodeEntry parses an entry block, decrypting it if enc says so. The
// returned entry's Hash is the CID of data.
func DecodeEntry(ctx context.Context, data []byte, enc Encryption) (*Entry, error) {
	hash, err := block.Hash(data)
	if err != nil {
		return nil, err
	}
	stored := data
	if enc.Replication != nil {
		v, err := block.Decode(data)
		if err != nil {
			return nil, err
		}
		ciphertext, ok := v.([]byte)
		if !ok {
			return nil, errors.New("could not decrypt entry: block is not a byte string")
		}
		if data, err = enc.Replication.Decrypt(ctx, ciphertext); err != nil {
			return nil, fmt.Errorf("could not decrypt entry: %w", err)
		}
	}
	v, err := block.Decode(data)
	if err != nil {
		return nil, err
	}
	m, err := block.Map(v)
	if err != nil {
		return nil, err
	}
	entry, err := entryFromMap(m)
	if err != nil {
		return nil, fmt.Errorf("entry %s: %w", hash, err)
	}
	if enc.Data != nil {
		ciphertext, ok := entry.Payload.([]byte)
		if !ok {
			return nil, errors.New("could not decrypt payload: payload is not a byte string")
		}
		plain, err := enc.Data.Decrypt(ctx, ciphertext)
		if err != nil {
			return nil, fmt.Errorf("could not decrypt payload: %w", err)
		}
		if entry.Payload, err = block.Decode(plain); err != nil {
			return nil, fmt.Errorf("could not decrypt payload: %w", err)
		}
		entry.encryptedPayload = ciphertext
	}
	entry.Hash = hash
	entry.block = stored
	return entry, nil
}

func entryFromMap(m map[string]any) (*Entry, error) {
	var (
		e   Entry
		err error
	)
	if e.ID, err = block.String(m, "id"); err != nil {
		return nil, err
	}
	payload, ok := m["payload"]
	if !ok {
		return nil, errors.New(`missing field "payload"`)
	}
	e.Payload = payload
	if e.Next, err = block.Strings(m, "next"); err != nil {
		return nil, err
	}
	if e.Refs, err = block.Strings(m, "refs"); err != nil {
		return nil, err
	}
	clock, err := block.Map(m["clock"])
	if err != nil {
		return nil, fmt.Errorf("clock: %w", err)
	}
	if e.Clock.ID, err = block.String(clock, "id"); err != nil {
		return nil, fmt.Errorf("clock: %w", err)
	}
	if e.Clock.Time, err = block.Int(clock, "time"); err != nil {
		return nil, fmt.Errorf("clock: %w", err)
	}
	if e.V, err = block.Int(m, "v"); err != nil {
		return nil, err
	}
	// key, identity and sig are checked by verification, not decoding.
	e.Key, _ = m["key"].(string)
	e.Identity, _ = m["identity"].(string)
	e.Sig, _ = m["sig"].(string)
	return &e, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
