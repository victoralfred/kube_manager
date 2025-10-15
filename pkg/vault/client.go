package vault

import (
	"context"
	"fmt"
	"os"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/victoralfred/kube_manager/pkg/logger"
)

// Client wraps HashiCorp Vault client
type Client struct {
	client *vaultapi.Client
	log    *logger.Logger
	config Config
}

// Config holds Vault configuration
type Config struct {
	Address          string
	Token            string // For development
	KubernetesRole   string // For production with k8s auth
	KubernetesPath   string // K8s auth mount path
	TokenPath        string // Path to k8s service account token
	MountPath        string // KV mount path (e.g., "secret")
	SecretPath       string // Path to secrets (e.g., "kube_manager")
	RenewToken       bool
	RenewInterval    time.Duration
	UseKubernetes    bool // Use k8s auth instead of token
}

// NewClient creates a new Vault client
func NewClient(cfg Config, log *logger.Logger) (*Client, error) {
	config := vaultapi.DefaultConfig()
	config.Address = cfg.Address

	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	vClient := &Client{
		client: client,
		log:    log,
		config: cfg,
	}

	// Authenticate
	if err := vClient.authenticate(); err != nil {
		return nil, fmt.Errorf("failed to authenticate with vault: %w", err)
	}

	// Start token renewal if enabled
	if cfg.RenewToken {
		go vClient.startTokenRenewer()
	}

	log.Info("vault client initialized successfully")
	return vClient, nil
}

// authenticate handles Vault authentication
func (c *Client) authenticate() error {
	if c.config.UseKubernetes {
		return c.authenticateKubernetes()
	}
	return c.authenticateToken()
}

// authenticateToken uses a static token for authentication
func (c *Client) authenticateToken() error {
	if c.config.Token == "" {
		return fmt.Errorf("vault token is required")
	}
	c.client.SetToken(c.config.Token)
	c.log.Info("authenticated with vault using token")
	return nil
}

// authenticateKubernetes uses Kubernetes service account for authentication
func (c *Client) authenticateKubernetes() error {
	// Read service account JWT token
	jwtBytes, err := os.ReadFile(c.config.TokenPath)
	if err != nil {
		return fmt.Errorf("failed to read service account token: %w", err)
	}

	// Login with Kubernetes auth method
	options := map[string]interface{}{
		"jwt":  string(jwtBytes),
		"role": c.config.KubernetesRole,
	}

	path := fmt.Sprintf("auth/%s/login", c.config.KubernetesPath)
	secret, err := c.client.Logical().Write(path, options)
	if err != nil {
		return fmt.Errorf("kubernetes auth failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("kubernetes auth returned no token")
	}

	c.client.SetToken(secret.Auth.ClientToken)
	c.log.Info("authenticated with vault using kubernetes service account")
	return nil
}

// startTokenRenewer periodically renews the Vault token
func (c *Client) startTokenRenewer() {
	ticker := time.NewTicker(c.config.RenewInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := c.renewToken(); err != nil {
			c.log.Error("failed to renew vault token", err)
		} else {
			c.log.Debug("vault token renewed successfully")
		}
	}
}

// renewToken renews the current Vault token
func (c *Client) renewToken() error {
	secret, err := c.client.Auth().Token().RenewSelf(0)
	if err != nil {
		return fmt.Errorf("token renewal failed: %w", err)
	}

	if secret == nil {
		return fmt.Errorf("token renewal returned nil")
	}

	return nil
}

// GetSecret retrieves a secret from Vault KV v2
func (c *Client) GetSecret(ctx context.Context, path string) (map[string]interface{}, error) {
	fullPath := fmt.Sprintf("%s/data/%s/%s", c.config.MountPath, c.config.SecretPath, path)

	secret, err := c.client.Logical().ReadWithContext(ctx, fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret at %s: %w", path, err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no secret found at %s", path)
	}

	// KV v2 stores data under "data" key
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid secret format at %s", path)
	}

	return data, nil
}

// PutSecret stores a secret in Vault KV v2
func (c *Client) PutSecret(ctx context.Context, path string, data map[string]interface{}) error {
	fullPath := fmt.Sprintf("%s/data/%s/%s", c.config.MountPath, c.config.SecretPath, path)

	// KV v2 requires data to be nested under "data" key
	payload := map[string]interface{}{
		"data": data,
	}

	_, err := c.client.Logical().WriteWithContext(ctx, fullPath, payload)
	if err != nil {
		return fmt.Errorf("failed to write secret at %s: %w", path, err)
	}

	c.log.WithField("path", path).Debug("secret written successfully")
	return nil
}

// DeleteSecret deletes a secret from Vault
func (c *Client) DeleteSecret(ctx context.Context, path string) error {
	fullPath := fmt.Sprintf("%s/data/%s/%s", c.config.MountPath, c.config.SecretPath, path)

	_, err := c.client.Logical().DeleteWithContext(ctx, fullPath)
	if err != nil {
		return fmt.Errorf("failed to delete secret at %s: %w", path, err)
	}

	c.log.WithField("path", path).Debug("secret deleted successfully")
	return nil
}

// Health checks Vault server health
func (c *Client) Health(ctx context.Context) error {
	health, err := c.client.Sys().HealthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("vault health check failed: %w", err)
	}

	if health.Sealed {
		return fmt.Errorf("vault is sealed")
	}

	return nil
}

// Close performs cleanup
func (c *Client) Close() error {
	c.log.Info("vault client closed")
	return nil
}
