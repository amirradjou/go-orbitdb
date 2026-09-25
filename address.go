package orbitdb

import (
	"fmt"
	"strings"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multibase"
)

// Address is a database address, "/orbitdb/<manifest hash>".
type Address struct {
	// Hash is the base58btc CID of the database manifest.
	Hash string
}

// String returns the address in its canonical "/orbitdb/<hash>" form.
func (a Address) String() string {
	return "/orbitdb/" + a.Hash
}

// IsValidAddress reports whether address is an OrbitDB address: it starts
// with /orbitdb (or \orbitdb) and the rest is a base58btc CID. It accepts
// what @orbitdb/core's isValidAddress accepts.
func IsValidAddress(address string) bool {
	if !strings.HasPrefix(address, "/orbitdb") && !strings.HasPrefix(address, `\orbitdb`) {
		return false
	}
	s := strings.ReplaceAll(address, "/orbitdb/", "")
	s = strings.ReplaceAll(s, `\orbitdb\`, "")
	s = strings.ReplaceAll(s, "/", "")
	s = strings.ReplaceAll(s, `\`, "")
	return parseBase58CID(s) == nil
}

func parseBase58CID(s string) error {
	if s == "" {
		return fmt.Errorf("empty CID")
	}
	// CIDv0 strings are bare base58btc; CIDv1 strings carry the "z"
	// multibase prefix. Anything in another base is rejected, as in JS.
	if strings.HasPrefix(s, "Qm") {
		_, err := cid.Decode(s)
		return err
	}
	enc, _, err := multibase.Decode(s)
	if err != nil {
		return err
	}
	if enc != multibase.Base58BTC {
		return fmt.Errorf("CID %q is not base58btc", s)
	}
	_, err = cid.Decode(s)
	return err
}

// ParseAddress parses a database address.
func ParseAddress(address string) (Address, error) {
	if !IsValidAddress(address) {
		return Address{}, fmt.Errorf("not a valid OrbitDB address: %s", address)
	}
	hash := strings.Replace(address, "/orbitdb/", "", 1)
	hash = strings.Replace(hash, `\orbitdb\`, "", 1)
	return Address{Hash: hash}, nil
}
