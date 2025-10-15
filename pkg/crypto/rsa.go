package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/google/uuid"
)

const (
	// RSAKeySize is the recommended key size for RSA keys
	RSAKeySize = 4096
)

// GenerateRSAKeyPair generates a new RSA key pair
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	if bits < 2048 {
		return nil, fmt.Errorf("key size must be at least 2048 bits")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa key: %w", err)
	}

	return privateKey, nil
}

// EncodePrivateKeyToPEM encodes RSA private key to PEM format
func EncodePrivateKeyToPEM(privateKey *rsa.PrivateKey) (string, error) {
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	return string(privPEM), nil
}

// EncodePublicKeyToPEM encodes RSA public key to PEM format
func EncodePublicKeyToPEM(publicKey *rsa.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return string(pubPEM), nil
}

// DecodePrivateKeyFromPEM decodes RSA private key from PEM format
func DecodePrivateKeyFromPEM(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 format
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA private key")
	}

	return rsaKey, nil
}

// DecodePublicKeyFromPEM decodes RSA public key from PEM format
func DecodePublicKeyFromPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA public key")
	}

	return rsaPub, nil
}

// GenerateKeyID generates a unique key identifier
func GenerateKeyID() string {
	return uuid.New().String()
}

// KeyPair holds a complete RSA key pair with metadata
type KeyPair struct {
	PrivateKey    *rsa.PrivateKey
	PublicKey     *rsa.PublicKey
	PrivateKeyPEM string
	PublicKeyPEM  string
	KeyID         string
}

// NewKeyPair generates a new RSA key pair with PEM encoding
func NewKeyPair(bits int) (*KeyPair, error) {
	privateKey, err := GenerateRSAKeyPair(bits)
	if err != nil {
		return nil, err
	}

	privatePEM, err := EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		return nil, err
	}

	publicPEM, err := EncodePublicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		PrivateKeyPEM: privatePEM,
		PublicKeyPEM:  publicPEM,
		KeyID:         GenerateKeyID(),
	}, nil
}
