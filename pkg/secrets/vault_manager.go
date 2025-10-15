package secrets

import (
	"context"
	"fmt"
	"strconv"

	"github.com/victoralfred/kube_manager/pkg/crypto"
	"github.com/victoralfred/kube_manager/pkg/logger"
	"github.com/victoralfred/kube_manager/pkg/vault"
)

// VaultManager implements Manager using HashiCorp Vault
type VaultManager struct {
	client *vault.Client
	log    *logger.Logger
}

// NewVaultManager creates a new Vault-based secrets manager
func NewVaultManager(client *vault.Client, log *logger.Logger) *VaultManager {
	return &VaultManager{
		client: client,
		log:    log,
	}
}

// GetDatabaseCredentials retrieves database credentials from Vault
func (v *VaultManager) GetDatabaseCredentials(ctx context.Context) (*DatabaseCredentials, error) {
	data, err := v.client.GetSecret(ctx, "database")
	if err != nil {
		return nil, fmt.Errorf("failed to get database credentials: %w", err)
	}

	port, _ := strconv.Atoi(getString(data, "port", "5432"))

	creds := &DatabaseCredentials{
		Host:     getString(data, "host", "localhost"),
		Port:     port,
		Username: getString(data, "username", ""),
		Password: getString(data, "password", ""),
		Database: getString(data, "database", ""),
		SSLMode:  getString(data, "sslmode", "disable"),
	}

	if creds.Username == "" || creds.Password == "" {
		return nil, fmt.Errorf("invalid database credentials: username or password missing")
	}

	v.log.Debug("retrieved database credentials from vault")
	return creds, nil
}

// GetRedisCredentials retrieves Redis credentials from Vault
func (v *VaultManager) GetRedisCredentials(ctx context.Context) (*RedisCredentials, error) {
	data, err := v.client.GetSecret(ctx, "redis")
	if err != nil {
		return nil, fmt.Errorf("failed to get redis credentials: %w", err)
	}

	port, _ := strconv.Atoi(getString(data, "port", "6379"))
	db, _ := strconv.Atoi(getString(data, "db", "0"))
	useTLS := getBool(data, "use_tls", false)

	creds := &RedisCredentials{
		Host:     getString(data, "host", "localhost"),
		Port:     port,
		Password: getString(data, "password", ""),
		DB:       db,
		UseTLS:   useTLS,
	}

	v.log.Debug("retrieved redis credentials from vault")
	return creds, nil
}

// GetJWTKeys retrieves RSA keys for JWT from Vault
func (v *VaultManager) GetJWTKeys(ctx context.Context) (*JWTKeys, error) {
	data, err := v.client.GetSecret(ctx, "jwt")
	if err != nil {
		return nil, fmt.Errorf("failed to get jwt keys: %w", err)
	}

	privateKeyPEM := getString(data, "private_key", "")
	publicKeyPEM := getString(data, "public_key", "")
	keyID := getString(data, "key_id", "default")

	if privateKeyPEM == "" || publicKeyPEM == "" {
		return nil, fmt.Errorf("jwt keys not found in vault")
	}

	privateKey, err := crypto.DecodePrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwt private key: %w", err)
	}

	publicKey, err := crypto.DecodePublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwt public key: %w", err)
	}

	v.log.WithField("key_id", keyID).Debug("retrieved jwt keys from vault")
	return &JWTKeys{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		KeyID:      keyID,
	}, nil
}

// GetCSRFKey retrieves RSA keys for CSRF from Vault
func (v *VaultManager) GetCSRFKey(ctx context.Context) (*CSRFKey, error) {
	data, err := v.client.GetSecret(ctx, "csrf")
	if err != nil {
		return nil, fmt.Errorf("failed to get csrf key: %w", err)
	}

	privateKeyPEM := getString(data, "private_key", "")
	publicKeyPEM := getString(data, "public_key", "")
	keyID := getString(data, "key_id", "default")

	if privateKeyPEM == "" || publicKeyPEM == "" {
		return nil, fmt.Errorf("csrf keys not found in vault")
	}

	privateKey, err := crypto.DecodePrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse csrf private key: %w", err)
	}

	publicKey, err := crypto.DecodePublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse csrf public key: %w", err)
	}

	v.log.WithField("key_id", keyID).Debug("retrieved csrf key from vault")
	return &CSRFKey{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		KeyID:      keyID,
	}, nil
}

// GetAPIKeys retrieves external API keys from Vault
func (v *VaultManager) GetAPIKeys(ctx context.Context, service string) (string, error) {
	path := fmt.Sprintf("api_keys/%s", service)
	data, err := v.client.GetSecret(ctx, path)
	if err != nil {
		return "", fmt.Errorf("failed to get api key for %s: %w", service, err)
	}

	apiKey := getString(data, "key", "")
	if apiKey == "" {
		return "", fmt.Errorf("api key for %s not found", service)
	}

	v.log.WithField("service", service).Debug("retrieved api key from vault")
	return apiKey, nil
}

// Health checks Vault connection health
func (v *VaultManager) Health(ctx context.Context) error {
	return v.client.Health(ctx)
}

// Close performs cleanup
func (v *VaultManager) Close() error {
	return v.client.Close()
}

// Helper functions

func getString(data map[string]interface{}, key, defaultValue string) string {
	if val, ok := data[key].(string); ok {
		return val
	}
	return defaultValue
}

func getBool(data map[string]interface{}, key string, defaultValue bool) bool {
	if val, ok := data[key].(bool); ok {
		return val
	}
	return defaultValue
}
