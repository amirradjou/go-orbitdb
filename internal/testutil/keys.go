// Package testutil holds fixtures shared by the package tests.
package testutil

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/orbitdb/go-orbitdb/keystore"
	"github.com/orbitdb/go-orbitdb/storage"
)

// JSKeys are the raw secp256k1 private keys in the keystore fixture of the
// @orbitdb/core 4.0.0 test suite (test/fixtures/newtestkeys2), by keystore
// id. Loading them makes Go derive the same identities as the JavaScript
// tests, so the hashes those tests assert can be asserted here too.
var JSKeys = map[string]string{
	"020863639c1793cdc32abffca1c903f96d282de5530ab3167d661caf96b827369c": "8b0d3e5ee88edea5314eca1ae8d4f9e276bdc08ac163ba540dc312014b568e37",
	"023d1ef7a14d2d4c901afb3a244875c988f4e69ccd3df1575ae08097a314ccf8c0": "fa9b7df085feccaff5a83f74cb46381c623dc6dc652e598277a22d7659c37066",
	"02c322b7edb44fe8e0f4d8d70feb8a9c30b30721110a355ec9f200b4e49a4637d4": "0b43ca53b8875baf229faed396f0efdd21498984210bb3f4df04364299ee430b",
	"02e7247a4c155b63d182a23c70cb6fe8ba2e44bc9e9d62dc45d4c4167ccde95944": "5c557f3ca56651e22e68ee770da8e7cc6f12d30081f60a3ca4b5f9f3a9a5f9df",
	"031e1ec273bc1badb26164a4394b20e587c484ad9409ae20d0545a0976ec7d44b6": "c6a97e6b53e0f966e97cd91c58344ca1745c2a6dd64790eb0ee3adb3cd11d4d3",
	"03602a3da3eb35f1148e8028f141ec415ef7f6d4103443edbfec2a0711d716f53f": "1b57d51eec137085753bd911bd874024cd5d91edd8802809023666675635290b",
	"03c2c4887bb3fbc131f6874959a0fbe646d43a200cf81056e22f9405c1f58ba611": "4ba52f65ada1d2ca5f70c562202c1a9d9cbef125df78525b0737aff3d13653f4",
	"03eea986152805dcfe9292be7aa3560949e1db0f0972be4290824c11c661f419de": "b235eede06363471087291ddefeb31ce74209d43c29c87475d0ebb5397fd2c90",
	"0x01234567890abcdefghijklmnopqrstuvwxyz":                            "9c5d99a925257730d70ae64af9169d8f7e3aac27a211416698a00bfe8cd2e4bd",
	"QmFoo":  "efa068bfa5bd6d63ddbef943c55618f163f204b824be8a135de6c660a2a73d34",
	"key1":   "be88e7bb43ae78fa596966bf24d97ddfd0d17b88a1aafb9f22dd8b1d8c525d7f",
	"pubKey": "2dff73c70964e8cb9c7bcb1edfdd8ce327ef55ebdad92b2d2656a10f8583c57b",
	"userA":  "5f74f154ac4591ccf8a67f7edc98971759d684c07f53037ea0d361e2ba3f4683",
	"userB":  "7824c1579131baa6d6c34736b95c596c6c81afdb2f84654228eb2c75403e4c65",
	"userC":  "81f78e97259ce190f46141cb5a3d9a9c006557126e8bb752bc78d62d07c1bb3e",
	"userX":  "dfe24b20dbcb02217cf0a487f1db3004397160091ba6539dfb8042e94568f47e",
}

// Keystore returns an in-memory keystore preloaded with JSKeys.
func Keystore(t testing.TB) *keystore.KeyStore {
	t.Helper()
	ks, err := keystore.New(keystore.Options{Storage: storage.NewMemoryStorage()})
	if err != nil {
		t.Fatal(err)
	}
	for id, h := range JSKeys {
		raw, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		key, err := keystore.UnmarshalPrivateKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := ks.AddKey(context.Background(), id, key); err != nil {
			t.Fatal(err)
		}
	}
	return ks
}
