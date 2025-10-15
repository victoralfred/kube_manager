package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/victoralfred/kube_manager/pkg/crypto"
	"github.com/victoralfred/kube_manager/pkg/logger"
	"github.com/victoralfred/kube_manager/pkg/vault"
)

func main() {
	// Parse command line flags
	vaultAddr := flag.String("vault-addr", "http://localhost:8200", "Vault server address")
	vaultToken := flag.String("vault-token", "", "Vault token")
	mountPath := flag.String("mount-path", "secret", "Vault KV mount path")
	secretPath := flag.String("secret-path", "kube_manager", "Base secret path")
	keySize := flag.Int("key-size", crypto.RSAKeySize, "RSA key size in bits")
	generateJWT := flag.Bool("jwt", true, "Generate JWT keys")
	generateCSRF := flag.Bool("csrf", true, "Generate CSRF keys")

	flag.Parse()

	if *vaultToken == "" {
		*vaultToken = os.Getenv("VAULT_TOKEN")
		if *vaultToken == "" {
			fmt.Println("Error: vault token is required (use --vault-token or VAULT_TOKEN env var)")
			os.Exit(1)
		}
	}

	// Create logger
	log := logger.New("info", "keygen")

	// Create Vault client
	vaultClient, err := vault.NewClient(vault.Config{
		Address:    *vaultAddr,
		Token:      *vaultToken,
		MountPath:  *mountPath,
		SecretPath: *secretPath,
		RenewToken: false,
	}, log)
	if err != nil {
		fmt.Printf("Error: failed to create vault client: %v\n", err)
		os.Exit(1)
	}
	defer vaultClient.Close()

	ctx := context.Background()

	// Check Vault health
	if err := vaultClient.Health(ctx); err != nil {
		fmt.Printf("Error: vault health check failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Vault connection established successfully")
	fmt.Printf("Generating RSA keys with %d bits...\n", *keySize)

	// Generate JWT keys
	if *generateJWT {
		fmt.Println("\nGenerating JWT RSA key pair...")
		jwtKeys, err := crypto.NewKeyPair(*keySize)
		if err != nil {
			fmt.Printf("Error: failed to generate JWT keys: %v\n", err)
			os.Exit(1)
		}

		// Store in Vault
		jwtData := map[string]interface{}{
			"private_key": jwtKeys.PrivateKeyPEM,
			"public_key":  jwtKeys.PublicKeyPEM,
			"key_id":      jwtKeys.KeyID,
		}

		if err := vaultClient.PutSecret(ctx, "jwt", jwtData); err != nil {
			fmt.Printf("Error: failed to store JWT keys in Vault: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✓ JWT keys generated and stored successfully (Key ID: %s)\n", jwtKeys.KeyID)
		fmt.Printf("  Path: %s/data/%s/jwt\n", *mountPath, *secretPath)
	}

	// Generate CSRF keys
	if *generateCSRF {
		fmt.Println("\nGenerating CSRF RSA key pair...")
		csrfKeys, err := crypto.NewKeyPair(*keySize)
		if err != nil {
			fmt.Printf("Error: failed to generate CSRF keys: %v\n", err)
			os.Exit(1)
		}

		// Store in Vault
		csrfData := map[string]interface{}{
			"private_key": csrfKeys.PrivateKeyPEM,
			"public_key":  csrfKeys.PublicKeyPEM,
			"key_id":      csrfKeys.KeyID,
		}

		if err := vaultClient.PutSecret(ctx, "csrf", csrfData); err != nil {
			fmt.Printf("Error: failed to store CSRF keys in Vault: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✓ CSRF keys generated and stored successfully (Key ID: %s)\n", csrfKeys.KeyID)
		fmt.Printf("  Path: %s/data/%s/csrf\n", *mountPath, *secretPath)
	}

	fmt.Println("\n✓ All keys generated and stored successfully!")
	fmt.Println("\nNext steps:")
	fmt.Println("1. Store your database credentials in Vault:")
	fmt.Printf("   vault kv put %s/%s/database host=localhost port=5432 username=dbuser password=dbpass database=kube_manager sslmode=disable\n", *mountPath, *secretPath)
	fmt.Println("\n2. Store your Redis credentials in Vault:")
	fmt.Printf("   vault kv put %s/%s/redis host=localhost port=6379 password= db=0 use_tls=false\n", *mountPath, *secretPath)
	fmt.Println("\n3. Set the following environment variables:")
	fmt.Println("   export VAULT_ADDR=" + *vaultAddr)
	fmt.Println("   export VAULT_TOKEN=" + *vaultToken)
	fmt.Println("   export VAULT_MOUNT_PATH=" + *mountPath)
	fmt.Println("   export VAULT_SECRET_PATH=" + *secretPath)
}
