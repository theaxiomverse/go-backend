// go-backend/pkg/crypto/hasher/blake3.go
package hasher

import (
	"bytes"
	"encoding/hex"

	"github.com/zeebo/blake3"
)

// Domain separation contexts
const (
	ContextCertificate   = "axiom-certificate-v1"
	ContextNode          = "axiom-node-v1"
	ContextVector        = "axiom-vector-v1"
	ContextTransaction   = "axiom-transaction-v1"
	ContextKeyDerivation = "axiom-key-v1"
	ContextSignature     = "axiom-sig-v1"
)

// Blake3Hasher provides a consistent interface for Blake3 hashing operations
type Blake3Hasher struct {
	context string
}

// NewHasher creates a new Blake3Hasher with a specific context
func NewHasher(context string) *Blake3Hasher {
	return &Blake3Hasher{
		context: context,
	}
}

// Hash generates a Blake3 hash of the input data with the configured context
func (h *Blake3Hasher) Hash(data []byte) []byte {
	hasher := blake3.New()

	// Add domain separation
	hasher.Write([]byte(h.context))
	hasher.Write(data)

	return hasher.Sum(nil)
}

// HashHex generates a hex-encoded Blake3 hash
func (h *Blake3Hasher) HashHex(data []byte) string {
	return hex.EncodeToString(h.Hash(data))
}

// DeriveKey derives a new key using Blake3's key derivation
func (h *Blake3Hasher) DeriveKey(keyMaterial []byte, keyLength int) []byte {
	hasher := blake3.New()

	// Use a specific context for key derivation
	hasher.Write([]byte(ContextKeyDerivation))
	hasher.Write([]byte(h.context))
	hasher.Write(keyMaterial)

	derived := hasher.Sum(nil)
	if len(derived) < keyLength {
		return derived
	}
	return derived[:keyLength]
}

// VerifyHash verifies that a hash matches the given data
func (h *Blake3Hasher) VerifyHash(data []byte, expectedHash []byte) bool {
	actualHash := h.Hash(data)
	return bytes.Equal(actualHash, expectedHash)
}

// KeyedHash generates a keyed hash using Blake3
func (h *Blake3Hasher) KeyedHash(data, key []byte) []byte {
	hasher := blake3.New()

	// Use a specific order for keyed hashing
	hasher.Write([]byte(h.context))
	hasher.Write(key)
	hasher.Write(data)

	return hasher.Sum(nil)
}

// VerifyKeyedHash verifies a keyed hash
func (h *Blake3Hasher) VerifyKeyedHash(data, key, expectedHash []byte) bool {
	actualHash := h.KeyedHash(data, key)
	return bytes.Equal(actualHash, expectedHash)
}

// HashMulti hashes multiple pieces of data together
func (h *Blake3Hasher) HashMulti(data ...[]byte) []byte {
	hasher := blake3.New()

	// Add context first
	hasher.Write([]byte(h.context))

	// Hash each piece of data
	for _, d := range data {
		hasher.Write(d)
	}

	return hasher.Sum(nil)
}

// HashWithPrefix hashes data with a specific prefix for additional domain separation
func (h *Blake3Hasher) HashWithPrefix(prefix string, data []byte) []byte {
	hasher := blake3.New()

	// Order: context -> prefix -> data
	hasher.Write([]byte(h.context))
	hasher.Write([]byte(prefix))
	hasher.Write(data)

	return hasher.Sum(nil)
}
