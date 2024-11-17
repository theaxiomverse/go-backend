package hasher

import (
	"bytes"
	"testing"
)

func TestBlake3Hasher_Hash(t *testing.T) {
	h := NewHasher(ContextCertificate)
	data := []byte("test data")

	hash1 := h.Hash(data)
	hash2 := h.Hash(data)

	if !bytes.Equal(hash1, hash2) {
		t.Error("Same data should produce same hash")
	}

	// Different context should produce different hash
	h2 := NewHasher(ContextNode)
	hash3 := h2.Hash(data)

	if bytes.Equal(hash1, hash3) {
		t.Error("Different contexts should produce different hashes")
	}
}

func TestBlake3Hasher_KeyedHash(t *testing.T) {
	h := NewHasher(ContextCertificate)
	data := []byte("test data")
	key := []byte("test key")

	hash1 := h.KeyedHash(data, key)
	hash2 := h.Hash(data) // Regular hash

	if bytes.Equal(hash1, hash2) {
		t.Error("Keyed hash should be different from regular hash")
	}

	// Verify keyed hash
	if !h.VerifyKeyedHash(data, key, hash1) {
		t.Error("Keyed hash verification failed")
	}
}

func TestBlake3Hasher_DeriveKey(t *testing.T) {
	h := NewHasher(ContextKeyDerivation)
	keyMaterial := []byte("secret key material")

	key1 := h.DeriveKey(keyMaterial, 32)
	key2 := h.DeriveKey(keyMaterial, 32)

	if !bytes.Equal(key1, key2) {
		t.Error("Same key material should derive same key")
	}

	// Test key length
	key3 := h.DeriveKey(keyMaterial, 16)
	if len(key3) != 16 {
		t.Errorf("Expected key length 16, got %d", len(key3))
	}
}

func TestBlake3Hasher_HashMulti(t *testing.T) {
	h := NewHasher(ContextTransaction)
	data1 := []byte("data1")
	data2 := []byte("data2")

	hash1 := h.HashMulti(data1, data2)
	hash2 := h.HashMulti(data1, data2)

	if !bytes.Equal(hash1, hash2) {
		t.Error("Same multi-data should produce same hash")
	}

	// Order should matter
	hash3 := h.HashMulti(data2, data1)
	if bytes.Equal(hash1, hash3) {
		t.Error("Different order should produce different hash")
	}
}

func TestBlake3Hasher_HashWithPrefix(t *testing.T) {
	h := NewHasher(ContextVector)
	data := []byte("test data")
	prefix := "test-prefix"

	hash1 := h.HashWithPrefix(prefix, data)
	hash2 := h.HashWithPrefix(prefix, data)

	if !bytes.Equal(hash1, hash2) {
		t.Error("Same prefix and data should produce same hash")
	}

	// Different prefix should produce different hash
	hash3 := h.HashWithPrefix("different-prefix", data)
	if bytes.Equal(hash1, hash3) {
		t.Error("Different prefixes should produce different hashes")
	}
}
