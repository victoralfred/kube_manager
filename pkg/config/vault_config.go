package config

import (
	"context"
	"fmt"
	"time"

	"github.com/victoralfred/kube_manager/pkg/crypto"
	"github.com/victoralfred/kube_manager/pkg/logger"
	"github.com/victoralfred/kube_manager/pkg/secrets"
	"github.com/victoralfred/kube_manager/pkg/vault"
)

// VaultConfig holds Vault-specific configuration
type VaultConfig struct {
	Address        string
	Token          string
	KubernetesRole string
	KubernetesPath string
	TokenPath      string
	MountPath      string
	SecretPath     string
	RenewToken     bool
	RenewInterval  time.Duration
	UseKubernetes  bool
}

// SecureConfig holds configuration with Vault-managed secrets
type SecureConfig struct {
	Server        ServerConfig
	Database      DatabaseConfig
	Redis         RedisConfig
	JWT           SecureJWTConfig
	CSRF          SecureCSRFConfig
	App           AppConfig
	SecretsManager secrets.Manager
}

// SecureJWTConfig holds JWT configuration with RSA keys
type SecureJWTConfig struct {
	PrivateKey      *crypto.PrivateKey
	PublicKey       *crypto.PublicKey
	KeyID           string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

// SecureCSRFConfig holds CSRF configuration with RSA keys
type SecureCSRFConfig struct {
	PrivateKey *crypto.PrivateKey
	PublicKey  *crypto.PublicKey
	KeyID      string
}

// LoadVaultConfig loads Vault configuration from environment
func LoadVaultConfig() VaultConfig {
	useK8s := getEnv("VAULT_USE_KUBERNETES", "false") == "true"

	return VaultConfig{
		Address:        getEnv("VAULT_ADDR", "http://localhost:8200"),
		Token:          getEnv("VAULT_TOKEN", ""),
		KubernetesRole: getEnv("VAULT_KUBERNETES_ROLE", "kube-manager"),
		KubernetesPath: getEnv("VAULT_KUBERNETES_PATH", "kubernetes"),
		TokenPath:      getEnv("VAULT_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
		MountPath:      getEnv("VAULT_MOUNT_PATH", "secret"),
		SecretPath:     getEnv("VAULT_SECRET_PATH", "kube_manager"),
		RenewToken:     getEnv("VAULT_RENEW_TOKEN", "true") == "true",
		RenewInterval:  getEnvAsDuration("VAULT_RENEW_INTERVAL", 1*time.Hour),
		UseKubernetes:  useK8s,
	}
}

// LoadWithVault loads configuration using Vault for secrets
func LoadWithVault(ctx context.Context, log *logger.Logger) (*SecureConfig, error) {
	// Load Vault configuration
	vaultCfg := LoadVaultConfig()

	// Log Vault configuration (without sensitive data)
	log.WithField("vault_address", vaultCfg.Address).
		WithField("mount_path", vaultCfg.MountPath).
		WithField("secret_path", vaultCfg.SecretPath).
		WithField("use_kubernetes_auth", vaultCfg.UseKubernetes).
		WithField("token_renewal_enabled", vaultCfg.RenewToken).
		Info("vault configuration loaded")

	// Create Vault client
	vaultClient, err := vault.NewClient(vault.Config{
		Address:        vaultCfg.Address,
		Token:          vaultCfg.Token,
		KubernetesRole: vaultCfg.KubernetesRole,
		KubernetesPath: vaultCfg.KubernetesPath,
		TokenPath:      vaultCfg.TokenPath,
		MountPath:      vaultCfg.MountPath,
		SecretPath:     vaultCfg.SecretPath,
		RenewToken:     vaultCfg.RenewToken,
		RenewInterval:  vaultCfg.RenewInterval,
		UseKubernetes:  vaultCfg.UseKubernetes,
	}, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Create secrets manager
	secretsManager := secrets.NewVaultManager(vaultClient, log)

	// Check Vault health
	log.Info("checking vault health")
	if err := secretsManager.Health(ctx); err != nil {
		return nil, fmt.Errorf("vault health check failed: %w", err)
	}
	log.Info("vault health check passed")

	// Load database credentials from Vault
	log.Info("fetching database credentials from vault")
	dbCreds, err := secretsManager.GetDatabaseCredentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get database credentials: %w", err)
	}
	log.WithField("db_host", dbCreds.Host).
		WithField("db_port", dbCreds.Port).
		WithField("db_name", dbCreds.Database).
		WithField("db_user", dbCreds.Username).
		WithField("ssl_mode", dbCreds.SSLMode).
		Info("database credentials loaded from vault")

	// Load Redis credentials from Vault
	log.Info("fetching redis credentials from vault")
	redisCreds, err := secretsManager.GetRedisCredentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get redis credentials: %w", err)
	}
	log.WithField("redis_host", redisCreds.Host).
		WithField("redis_port", redisCreds.Port).
		WithField("redis_db", redisCreds.DB).
		WithField("auth_enabled", redisCreds.Password != "").
		Info("redis credentials loaded from vault")

	// Load JWT keys from Vault
	log.Info("fetching jwt keys from vault")
	jwtKeys, err := secretsManager.GetJWTKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get jwt keys: %w", err)
	}
	log.WithField("key_id", jwtKeys.KeyID).
		WithField("private_key_loaded", jwtKeys.PrivateKey != nil).
		WithField("public_key_loaded", jwtKeys.PublicKey != nil).
		Info("jwt keys loaded from vault")

	// Load CSRF keys from Vault
	log.Info("fetching csrf keys from vault")
	csrfKeys, err := secretsManager.GetCSRFKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get csrf keys: %w", err)
	}
	log.WithField("key_id", csrfKeys.KeyID).
		WithField("private_key_loaded", csrfKeys.PrivateKey != nil).
		WithField("public_key_loaded", csrfKeys.PublicKey != nil).
		Info("csrf keys loaded from vault")

	// Get token TTL configuration
	accessTTL := getEnvAsDuration("JWT_ACCESS_TOKEN_TTL", 15*time.Minute)
	refreshTTL := getEnvAsDuration("JWT_REFRESH_TOKEN_TTL", 7*24*time.Hour)

	// Build configuration
	cfg := &SecureConfig{
		Server: ServerConfig{
			Host:         getEnv("SERVER_HOST", "0.0.0.0"),
			Port:         getEnvAsInt("SERVER_PORT", 8080),
			ReadTimeout:  getEnvAsDuration("SERVER_READ_TIMEOUT", 10*time.Second),
			WriteTimeout: getEnvAsDuration("SERVER_WRITE_TIMEOUT", 10*time.Second),
			IdleTimeout:  getEnvAsDuration("SERVER_IDLE_TIMEOUT", 120*time.Second),
		},
		Database: DatabaseConfig{
			Host:            dbCreds.Host,
			Port:            dbCreds.Port,
			User:            dbCreds.Username,
			Password:        dbCreds.Password,
			DBName:          dbCreds.Database,
			SSLMode:         dbCreds.SSLMode,
			MaxOpenConns:    getEnvAsInt("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvAsInt("DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getEnvAsDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
		},
		Redis: RedisConfig{
			Host:     redisCreds.Host,
			Port:     redisCreds.Port,
			Password: redisCreds.Password,
			DB:       redisCreds.DB,
		},
		JWT: SecureJWTConfig{
			PrivateKey:      jwtKeys.PrivateKey,
			PublicKey:       jwtKeys.PublicKey,
			KeyID:           jwtKeys.KeyID,
			AccessTokenTTL:  accessTTL,
			RefreshTokenTTL: refreshTTL,
		},
		CSRF: SecureCSRFConfig{
			PrivateKey: csrfKeys.PrivateKey,
			PublicKey:  csrfKeys.PublicKey,
			KeyID:      csrfKeys.KeyID,
		},
		App: AppConfig{
			Environment: getEnv("APP_ENV", "development"),
			LogLevel:    getEnv("LOG_LEVEL", "info"),
			Name:        getEnv("APP_NAME", "kube_manager"),
			Version:     getEnv("APP_VERSION", "1.0.0"),
		},
		SecretsManager: secretsManager,
	}

	// Log final configuration summary (without sensitive data)
	log.WithField("environment", cfg.App.Environment).
		WithField("app_version", cfg.App.Version).
		WithField("server_address", cfg.Server.ServerAddr()).
		WithField("db_connection", fmt.Sprintf("%s:%d/%s", cfg.Database.Host, cfg.Database.Port, cfg.Database.DBName)).
		WithField("redis_connection", fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port)).
		WithField("jwt_access_ttl", accessTTL).
		WithField("jwt_refresh_ttl", refreshTTL).
		WithField("jwt_key_id", jwtKeys.KeyID).
		WithField("csrf_key_id", csrfKeys.KeyID).
		WithField("db_max_open_conns", cfg.Database.MaxOpenConns).
		WithField("db_max_idle_conns", cfg.Database.MaxIdleConns).
		Info("configuration loaded successfully with vault integration")

	return cfg, nil
}

// ValidateSecureConfig validates the secure configuration
func ValidateSecureConfig(cfg *SecureConfig) error {
	if cfg.Database.User == "" || cfg.Database.Password == "" {
		return fmt.Errorf("database credentials are invalid")
	}

	if cfg.JWT.PrivateKey == nil || cfg.JWT.PublicKey == nil {
		return fmt.Errorf("jwt keys are missing")
	}

	if cfg.CSRF.PrivateKey == nil || cfg.CSRF.PublicKey == nil {
		return fmt.Errorf("csrf keys are missing")
	}

	if cfg.App.Environment == "production" {
		if cfg.Database.SSLMode == "disable" {
			return fmt.Errorf("SSL must be enabled for database in production")
		}
	}

	return nil
}

// Close performs cleanup on the secure configuration
func (c *SecureConfig) Close() error {
	if c.SecretsManager != nil {
		return c.SecretsManager.Close()
	}
	return nil
}

// GetAPIKey retrieves an API key for external services
func (c *SecureConfig) GetAPIKey(ctx context.Context, service string) (string, error) {
	return c.SecretsManager.GetAPIKeys(ctx, service)
}
