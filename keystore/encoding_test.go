package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"orbitdb/go-orbitdb/storage"
)

// manyKeys is the number of fresh key pairs the loop tests exercise. With
// big.Int.Bytes() (the pre-fix encoding) roughly 1 in 128 signatures and
// 1 in 128 public keys lose a leading zero byte, so 3000 iterations catch a
// regression with probability > 1 - 1e-10.
const manyKeys = 3000

func loopCount(t *testing.T) int {
	t.Helper()
	if testing.Short() {
		return manyKeys / 10
	}
	return manyKeys
}

// mustHexBig parses a hex string into a big.Int or fails the test.
func mustHexBig(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatalf("bad hex big.Int %q", s)
	}
	return v
}

func p256Key(t *testing.T, d, x, y string) *ecdsa.PrivateKey {
	t.Helper()
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: mustHexBig(t, x), Y: mustHexBig(t, y)},
		D:         mustHexBig(t, d),
	}
}

// Throwaway P-256 test vectors, generated once with crypto/rand. They are
// chosen so that big.Int.Bytes() would drop a leading zero byte, which is
// exactly the case the fixed-width encoding must handle.
var (
	// X coordinate has a leading zero byte (X.Bytes() is 31 bytes long).
	shortXKey = [3]string{
		"a2efbc232cdfddbec6856c095dfb27be7c0a2d069e201313d2e99941a750feba", // D
		"7fc2bbae50e6e31de98304145f57ab65d4a097654988fd59657e45ccf9ad1b",   // X
		"d724255d1c5ecb3a171bbb0cdda6b3380edc28c52be6f576968cbb906b87ed8c", // Y
	}
	// Y coordinate has a leading zero byte (Y.Bytes() is 31 bytes long).
	shortYKey = [3]string{
		"ad080854fd70aee3c36546f895f6894d2e8f8d1383d7a0298660c40cc7a77501", // D
		"5bb2dfb5410615c0abde49e81393e39e3362658c812c7e7083baf05c8536319d", // X
		"8c172e9614cd567fc349de73a1ad4c16599d9768d09463755884dd3aa4aa22",   // Y
	}
	// A key with full-width X and Y, used for the known-signature vectors.
	vectorKey = [3]string{
		"c55506ddd7d1b9913dc42a10da76af03a13ced3661cf48f1ec1d5c1a4f64bdc0", // D
		"82bc273e4d3a33cf64cb2626a93060e16c60f9bca47a22616b2b54394cb6229d", // X
		"2a66ad49954cb93794f46d18d6427e7abbe74de42e5754690a195be4a4b4cbc9", // Y
	}
	vectorMessage = []byte("go-orbitdb leading-zero regression vector")

	// Valid signatures over sha256(vectorMessage) by vectorKey whose r
	// (resp. s) has a leading zero byte. "fixed" is the 64-byte r || s
	// encoding this package produces; "legacy" is the 63-byte
	// r.Bytes() || s.Bytes() form the old code emitted, which cannot be
	// split back into r and s and must be rejected.
	shortRSigFixed  = "00ffb4c25118b7bd2e57c31915f767fbef98730bdcfde101915aa78aa91bcade70e4a08b5301c04e7bcd3ea5737905eb7f5110739ad1f6a4aa96895c6081e69c"
	shortRSigLegacy = "ffb4c25118b7bd2e57c31915f767fbef98730bdcfde101915aa78aa91bcade70e4a08b5301c04e7bcd3ea5737905eb7f5110739ad1f6a4aa96895c6081e69c"
	shortSSigFixed  = "9c3e9133418d4df13b46929542d506e53ba8f654c37cad4e40e0d50942472e0f00c39d308e717b8632928bdf8c676f91047996820bddbb30c2e2aee5f6d64efe"
	shortSSigLegacy = "9c3e9133418d4df13b46929542d506e53ba8f654c37cad4e40e0d50942472e0fc39d308e717b8632928bdf8c676f91047996820bddbb30c2e2aee5f6d64efe"
)

func TestMarshalSignatureZeroPads(t *testing.T) {
	sig := marshalSignature(big.NewInt(1), big.NewInt(2))
	if len(sig) != SignatureSize {
		t.Fatalf("len = %d, want %d", len(sig), SignatureSize)
	}
	want := strings.Repeat("00", CoordinateSize-1) + "01" + strings.Repeat("00", CoordinateSize-1) + "02"
	if got := hex.EncodeToString(sig); got != want {
		t.Fatalf("marshalSignature(1, 2) = %s, want %s", got, want)
	}

	r, s, err := unmarshalSignature(sig)
	if err != nil {
		t.Fatalf("unmarshalSignature: %v", err)
	}
	if r.Int64() != 1 || s.Int64() != 2 {
		t.Fatalf("round trip gave r=%v s=%v, want 1, 2", r, s)
	}

	for _, n := range []int{0, SignatureSize - 1, SignatureSize + 1, 2 * SignatureSize} {
		if _, _, err := unmarshalSignature(make([]byte, n)); err == nil {
			t.Errorf("unmarshalSignature accepted %d bytes, want error", n)
		}
	}
}

func TestVerifyMessageKnownShortRS(t *testing.T) {
	ks := newTestKeyStore(t)
	key := p256Key(t, vectorKey[0], vectorKey[1], vectorKey[2])

	for name, sig := range map[string]string{"short-r": shortRSigFixed, "short-s": shortSSigFixed} {
		ok, err := ks.VerifyMessage(key.PublicKey, vectorMessage, sig)
		if err != nil {
			t.Fatalf("%s: VerifyMessage returned error: %v", name, err)
		}
		if !ok {
			t.Fatalf("%s: fixed-width signature did not verify", name)
		}
		// Tampered data must still fail.
		if ok, _ := ks.VerifyMessage(key.PublicKey, []byte("tampered"), sig); ok {
			t.Fatalf("%s: signature verified against tampered data", name)
		}
	}

	// The pre-fix encoding dropped the leading zero byte, producing a 63-byte
	// signature that cannot be split into r and s. It must be rejected with
	// an error, never silently mis-verified.
	for name, sig := range map[string]string{"short-r": shortRSigLegacy, "short-s": shortSSigLegacy} {
		if len(sig) != 2*(SignatureSize-1) {
			t.Fatalf("%s: legacy vector is %d hex chars, want %d", name, len(sig), 2*(SignatureSize-1))
		}
		ok, err := ks.VerifyMessage(key.PublicKey, vectorMessage, sig)
		if err == nil {
			t.Fatalf("%s: expected an error for a %d-byte legacy signature", name, SignatureSize-1)
		}
		if ok {
			t.Fatalf("%s: legacy signature must not verify", name)
		}
	}
}

func TestEncodePublicKeyKnownShortCoordinate(t *testing.T) {
	cases := []struct {
		name    string
		key     [3]string
		wantHex string
	}{
		{"short-x", shortXKey, "00" + shortXKey[1] + shortXKey[2]},
		{"short-y", shortYKey, shortYKey[1] + "00" + shortYKey[2]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := p256Key(t, tc.key[0], tc.key[1], tc.key[2])

			got, err := EncodePublicKey(&key.PublicKey)
			if err != nil {
				t.Fatalf("EncodePublicKey: %v", err)
			}
			if len(got) != 2*PublicKeySize {
				t.Fatalf("encoded public key is %d hex chars, want %d", len(got), 2*PublicKeySize)
			}
			if got != tc.wantHex {
				t.Fatalf("EncodePublicKey = %s, want %s", got, tc.wantHex)
			}

			back, err := ReconstructPublicKeyFromHex(got)
			if err != nil {
				t.Fatalf("ReconstructPublicKeyFromHex: %v", err)
			}
			if back.X.Cmp(key.X) != 0 || back.Y.Cmp(key.Y) != 0 {
				t.Fatalf("round trip changed the point: got (%s, %s)", back.X.Text(16), back.Y.Text(16))
			}

			// The pre-fix encoding (X.Bytes() || Y.Bytes()) is 63 bytes here
			// and must be rejected rather than split at the wrong midpoint.
			legacy := hex.EncodeToString(append(key.X.Bytes(), key.Y.Bytes()...))
			if len(legacy) != 2*(PublicKeySize-1) {
				t.Fatalf("legacy encoding is %d hex chars, want %d", len(legacy), 2*(PublicKeySize-1))
			}
			if _, err := ReconstructPublicKeyFromHex(legacy); err == nil {
				t.Fatalf("ReconstructPublicKeyFromHex accepted the %d-byte legacy encoding", PublicKeySize-1)
			}

			// And the key must sign and verify end to end through the keystore.
			ks := NewKeyStore(storage.NewMemoryStorage())
			if err := ks.AddKey(tc.name, key); err != nil {
				t.Fatalf("AddKey: %v", err)
			}
			sig, err := ks.SignMessage(tc.name, vectorMessage)
			if err != nil {
				t.Fatalf("SignMessage: %v", err)
			}
			ok, err := ks.VerifyMessage(*back, vectorMessage, sig)
			if err != nil || !ok {
				t.Fatalf("VerifyMessage with reconstructed key: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestEncodePublicKeyRejectsBadInput(t *testing.T) {
	if _, err := EncodePublicKey(nil); err == nil {
		t.Error("EncodePublicKey(nil) returned no error")
	}
	tooBig := new(big.Int).Lsh(big.NewInt(1), 8*CoordinateSize) // 2^256 does not fit in 32 bytes
	if _, err := EncodePublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: tooBig, Y: big.NewInt(1)}); err == nil {
		t.Error("EncodePublicKey accepted an oversized X coordinate")
	}
	if _, err := EncodePublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(-1), Y: big.NewInt(1)}); err == nil {
		t.Error("EncodePublicKey accepted a negative X coordinate")
	}
}

// TestSignVerifyManyFreshKeys is the statistical regression test for the
// leading-zero bug: every one of many fresh keys must produce a
// fixed-width public key and signature that verifies.
func TestSignVerifyManyFreshKeys(t *testing.T) {
	ks := NewKeyStore(storage.NewMemoryStorage())
	n := loopCount(t)
	data := []byte("leading-zero regression")

	var shortSigs, shortKeys int
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("key-%d", i)
		priv, err := ks.CreateKey(id)
		if err != nil {
			t.Fatalf("[%d] CreateKey: %v", i, err)
		}
		if len(priv.X.Bytes()) < CoordinateSize || len(priv.Y.Bytes()) < CoordinateSize {
			shortKeys++
		}

		pubHex, err := EncodePublicKey(&priv.PublicKey)
		if err != nil {
			t.Fatalf("[%d] EncodePublicKey: %v", i, err)
		}
		if len(pubHex) != 2*PublicKeySize {
			t.Fatalf("[%d] public key is %d hex chars, want %d", i, len(pubHex), 2*PublicKeySize)
		}
		pub, err := ReconstructPublicKeyFromHex(pubHex)
		if err != nil {
			t.Fatalf("[%d] ReconstructPublicKeyFromHex: %v", i, err)
		}

		sig, err := ks.SignMessage(id, data)
		if err != nil {
			t.Fatalf("[%d] SignMessage: %v", i, err)
		}
		if len(sig) != 2*SignatureSize {
			t.Fatalf("[%d] signature is %d hex chars, want %d", i, len(sig), 2*SignatureSize)
		}
		if strings.HasPrefix(sig, "00") || sig[2*CoordinateSize:2*CoordinateSize+2] == "00" {
			shortSigs++
		}

		ok, err := ks.VerifyMessage(*pub, data, sig)
		if err != nil {
			t.Fatalf("[%d] VerifyMessage: %v", i, err)
		}
		if !ok {
			t.Fatalf("[%d] signature %s did not verify for key %s", i, sig, pubHex)
		}
	}
	t.Logf("%d keys: %d had a leading-zero coordinate, %d signatures had a leading-zero r or s (all verified)", n, shortKeys, shortSigs)
}

// TestSignMessageProducesDistinctValidSignatures checks that two signatures
// of the same message differ (ECDSA nonces are random) yet both verify.
func TestSignMessageProducesDistinctValidSignatures(t *testing.T) {
	ks := NewKeyStore(storage.NewMemoryStorage())
	priv, err := ks.CreateKey("id")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("same message")
	a, _ := ks.SignMessage("id", data)
	b, _ := ks.SignMessage("id", data)
	if a == b {
		t.Fatal("two ECDSA signatures of the same message were identical")
	}
	for _, sig := range []string{a, b} {
		if ok, err := ks.VerifyMessage(priv.PublicKey, data, sig); err != nil || !ok {
			t.Fatalf("signature did not verify: ok=%v err=%v", ok, err)
		}
	}
}
