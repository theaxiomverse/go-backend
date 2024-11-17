package crypto

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/peer" // Use Blake3 for hashing
	"github.com/theaxiomverse/go-backend/hasher"
)

// CertificateRole defines the role of a node in the network
type CertificateRole string

const (
	RoleNode      CertificateRole = "node"
	RoleValidator CertificateRole = "validator"
	RoleBootstrap CertificateRole = "bootstrap"
)

// KyberCertificate represents a certificate containing Kyber keys and node information
type KyberCertificate struct {
	// Node identification
	NodeID    peer.ID `json:"node_id"`
	PublicKey []byte  `json:"public_key"` // Kyber public key
	LibP2PKey []byte  `json:"libp2p_key"` // LibP2P public key

	// Certificate metadata
	IssuedAt  time.Time         `json:"issued_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	Roles     []CertificateRole `json:"roles"`
	Version   uint64            `json:"version"` // Certificate version for updates

	// Certificate verification
	Signature []byte `json:"signature"` // Signed by Python backend's Kyber key
	Hash      []byte `json:"hash"`      // Blake3 hash of certificate content
}

// NewKyberCertificate creates a new certificate for a node
func NewKyberCertificate(
	nodeID peer.ID,
	kyberPubKey, libp2pPubKey []byte,
	roles []CertificateRole,
	validityDays int,
) (*KyberCertificate, error) {
	if len(kyberPubKey) == 0 || len(libp2pPubKey) == 0 {
		return nil, fmt.Errorf("invalid public keys")
	}

	now := time.Now()
	cert := &KyberCertificate{
		NodeID:    nodeID,
		PublicKey: kyberPubKey,
		LibP2PKey: libp2pPubKey,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(0, 0, validityDays),
		Roles:     roles,
		Version:   1,
	}

	// Calculate certificate hash
	if err := cert.calculateHash(); err != nil {
		return nil, fmt.Errorf("failed to calculate hash: %w", err)
	}

	return cert, nil
}

// certificateContent represents the content to be hashed
type certificateContent struct {
	NodeID    peer.ID           `json:"node_id"`
	PublicKey []byte            `json:"public_key"`
	LibP2PKey []byte            `json:"libp2p_key"`
	IssuedAt  time.Time         `json:"issued_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	Roles     []CertificateRole `json:"roles"`
	Version   uint64            `json:"version"`
}

// Use in certificate
func (kc *KyberCertificate) calculateHash() error {
	content := certificateContent{
		NodeID:    kc.NodeID,
		PublicKey: kc.PublicKey,
		LibP2PKey: kc.LibP2PKey,
		IssuedAt:  kc.IssuedAt,
		ExpiresAt: kc.ExpiresAt,
		Roles:     kc.Roles,
		Version:   kc.Version,
	}

	data, err := json.Marshal(content)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate content: %w", err)
	}

	h := hasher.NewHasher(hasher.ContextCertificate)
	kc.Hash = h.Hash(data)
	return nil
}

// Verify certificate
func (kc *KyberCertificate) Verify(pythonPubKey []byte) error {
	h := hasher.NewHasher(hasher.ContextCertificate)
	data, err := json.Marshal(certificateContent{})
	if err != nil {
		return err
	}

	if !h.VerifyHash(data, kc.Hash) {
		return fmt.Errorf("certificate hash mismatch")
	}
	return nil
}

// ToJSON serializes the certificate
func (kc *KyberCertificate) ToJSON() ([]byte, error) {
	return json.Marshal(kc)
}

// FromJSON deserializes the certificate
func FromJSON(data []byte) (*KyberCertificate, error) {
	var cert KyberCertificate
	if err := json.Unmarshal(data, &cert); err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificate: %w", err)
	}
	return &cert, nil
}

// Update updates the certificate with new information while maintaining its chain of trust
func (kc *KyberCertificate) Update(
	newRoles []CertificateRole,
	newValidityDays int,
	signingKey []byte,
) error {
	kc.Roles = newRoles
	kc.ExpiresAt = time.Now().AddDate(0, 0, newValidityDays)
	kc.Version++

	if err := kc.calculateHash(); err != nil {
		return fmt.Errorf("failed to calculate hash for update: %w", err)
	}

	// TODO: Implement signing with Kyber key
	// kc.Signature = sign(kc.Hash, signingKey)

	return nil
}

// ValidateRole checks if the certificate has a specific role
func (kc *KyberCertificate) HasRole(role CertificateRole) bool {
	for _, r := range kc.Roles {
		if r == role {
			return true
		}
	}
	return false
}
