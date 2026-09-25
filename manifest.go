package orbitdb

import (
	"context"
	"errors"
	"fmt"

	"github.com/amirradjou/go-orbitdb/internal/block"
	"github.com/amirradjou/go-orbitdb/storage"
)

// Manifest describes a database. Its hash is the database address.
type Manifest struct {
	Name string
	Type string
	// AccessController is the address of the access controller, e.g.
	// "/ipfs/zdpu...".
	AccessController string
	// Meta is optional metadata; nil means the manifest has no meta field.
	Meta any
}

// manifestStore reads and writes manifest blocks, like
// src/manifest-store.js.
type manifestStore struct {
	storage storage.Storage
}

func (m *manifestStore) create(ctx context.Context, manifest Manifest) (string, error) {
	switch {
	case manifest.Name == "":
		return "", errors.New("name is required")
	case manifest.Type == "":
		return "", errors.New("type is required")
	case manifest.AccessController == "":
		return "", errors.New("accessController is required")
	}
	value := map[string]any{
		"name":             manifest.Name,
		"type":             manifest.Type,
		"accessController": manifest.AccessController,
	}
	if manifest.Meta != nil {
		value["meta"] = manifest.Meta
	}
	hash, data, err := block.Encode(value)
	if err != nil {
		return "", err
	}
	if err := m.storage.Put(ctx, hash, data); err != nil {
		return "", err
	}
	return hash, nil
}

func (m *manifestStore) get(ctx context.Context, hash string) (Manifest, error) {
	data, err := m.storage.Get(ctx, hash)
	if err != nil {
		return Manifest{}, fmt.Errorf("fetch manifest %s: %w", hash, err)
	}
	manifest, err := decodeManifest(data)
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest %s: %w", hash, err)
	}
	// Store it again so it is pinned on this node too.
	if err := m.storage.Put(ctx, hash, data); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func decodeManifest(data []byte) (Manifest, error) {
	v, err := block.Decode(data)
	if err != nil {
		return Manifest{}, err
	}
	m, err := block.Map(v)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if manifest.Name, err = block.String(m, "name"); err != nil {
		return Manifest{}, err
	}
	if manifest.Type, err = block.String(m, "type"); err != nil {
		return Manifest{}, err
	}
	if manifest.AccessController, err = block.String(m, "accessController"); err != nil {
		return Manifest{}, err
	}
	manifest.Meta = m["meta"]
	return manifest, nil
}

func (m *manifestStore) close() error { return m.storage.Close() }
