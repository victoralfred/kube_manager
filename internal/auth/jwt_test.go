package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/victoralfred/kube_manager/pkg/crypto"
)

func setupTestJWTService(t *testing.T) *JWTService {
	t.Helper()

	// Generate test RSA keys
	keyPair, err := crypto.NewKeyPair(2048)
	require.NoError(t, err)

	privateKey, err := crypto.DecodePrivateKeyFromPEM(keyPair.PrivateKeyPEM)
	require.NoError(t, err)

	publicKey, err := crypto.DecodePublicKeyFromPEM(keyPair.PublicKeyPEM)
	require.NoError(t, err)

	return NewJWTService(
		privateKey,
		publicKey,
		keyPair.KeyID,
		15*time.Minute,
		7*24*time.Hour,
	)
}

func TestJWTService_GenerateAccessToken(t *testing.T) {
	svc := setupTestJWTService(t)
	userID := uuid.New().String()
	tenantID := uuid.New().String()
	email := "test@example.com"
	roles := []string{"user", "admin"}

	token, err := svc.GenerateAccessToken(userID, tenantID, email, roles)

	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJWTService_GenerateRefreshToken(t *testing.T) {
	svc := setupTestJWTService(t)
	userID := uuid.New().String()
	tenantID := uuid.New().String()
	email := "test@example.com"

	token, err := svc.GenerateRefreshToken(userID, tenantID, email)

	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJWTService_VerifyAccessToken(t *testing.T) {
	svc := setupTestJWTService(t)
	userID := uuid.New().String()
	tenantID := uuid.New().String()
	email := "test@example.com"
	roles := []string{"user"}

	token, err := svc.GenerateAccessToken(userID, tenantID, email, roles)
	require.NoError(t, err)

	claims, err := svc.VerifyToken(token)

	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, tenantID, claims.TenantID)
	assert.Equal(t, email, claims.Email)
	assert.Equal(t, "access", claims.TokenType)
	assert.Equal(t, roles, claims.Roles)
}

func TestJWTService_VerifyRefreshToken(t *testing.T) {
	svc := setupTestJWTService(t)
	userID := uuid.New().String()
	tenantID := uuid.New().String()
	email := "test@example.com"

	token, err := svc.GenerateRefreshToken(userID, tenantID, email)
	require.NoError(t, err)

	claims, err := svc.VerifyToken(token)

	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, tenantID, claims.TenantID)
	assert.Equal(t, email, claims.Email)
	assert.Equal(t, "refresh", claims.TokenType)
}

func TestJWTService_VerifyToken_ExpiredToken(t *testing.T) {
	// Create service with very short TTL
	keyPair, err := crypto.NewKeyPair(2048)
	require.NoError(t, err)

	privateKey, err := crypto.DecodePrivateKeyFromPEM(keyPair.PrivateKeyPEM)
	require.NoError(t, err)

	publicKey, err := crypto.DecodePublicKeyFromPEM(keyPair.PublicKeyPEM)
	require.NoError(t, err)

	svc := NewJWTService(
		privateKey,
		publicKey,
		keyPair.KeyID,
		1*time.Second, // Short TTL
		1*time.Second,
	)

	userID := uuid.New().String()
	tenantID := uuid.New().String()
	email := "test@example.com"
	roles := []string{"user"}

	token, err := svc.GenerateAccessToken(userID, tenantID, email, roles)
	require.NoError(t, err)

	// Wait for token to expire (wait 2 seconds to ensure expiration)
	time.Sleep(2 * time.Second)

	claims, err := svc.VerifyToken(token)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Equal(t, ErrTokenExpired, err)
}

func TestJWTService_VerifyToken_InvalidSignature(t *testing.T) {
	svc := setupTestJWTService(t)
	userID := uuid.New().String()
	tenantID := uuid.New().String()
	email := "test@example.com"
	roles := []string{"user"}

	token, err := svc.GenerateAccessToken(userID, tenantID, email, roles)
	require.NoError(t, err)

	// Tamper with the token
	tamperedToken := token[:len(token)-10] + "xxxxxxxxxx"

	claims, err := svc.VerifyToken(tamperedToken)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Equal(t, ErrTokenSignature, err)
}

func TestJWTService_VerifyToken_MalformedToken(t *testing.T) {
	svc := setupTestJWTService(t)

	testCases := []struct {
		name        string
		token       string
		expectedErr error
	}{
		{"empty token", "", ErrTokenMalformed},
		{"single part", "onepartonly", ErrTokenMalformed},
		{"two parts", "two.parts", ErrTokenMalformed},
		{"invalid base64", "invalid!@#.base64$%^.signature&*(", nil}, // Will get decode error, not ErrTokenMalformed
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := svc.VerifyToken(tc.token)

			assert.Error(t, err)
			assert.Nil(t, claims)

			// For specific errors, check exact match
			if tc.expectedErr != nil {
				assert.Equal(t, tc.expectedErr, err)
			}
		})
	}
}

func TestJWTService_VerifyToken_DifferentKeys(t *testing.T) {
	// Create two services with different keys
	svc1 := setupTestJWTService(t)
	svc2 := setupTestJWTService(t)

	userID := uuid.New().String()
	tenantID := uuid.New().String()
	email := "test@example.com"
	roles := []string{"user"}

	// Generate token with svc1
	token, err := svc1.GenerateAccessToken(userID, tenantID, email, roles)
	require.NoError(t, err)

	// Try to verify with svc2 (different keys)
	claims, err := svc2.VerifyToken(token)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Equal(t, ErrTokenSignature, err)
}

func TestJWTService_GenerateTokenPair(t *testing.T) {
	svc := setupTestJWTService(t)
	userID := uuid.New().String()
	tenantID := uuid.New().String()
	email := "test@example.com"
	roles := []string{"user", "admin"}

	pair, err := svc.GenerateTokenPair(userID, tenantID, email, roles)

	assert.NoError(t, err)
	assert.NotNil(t, pair)
	assert.NotEmpty(t, pair.AccessToken)
	assert.NotEmpty(t, pair.RefreshToken)
	assert.Equal(t, "Bearer", pair.TokenType)
	assert.Greater(t, pair.ExpiresIn, int64(0))

	// Verify both tokens
	accessClaims, err := svc.VerifyToken(pair.AccessToken)
	assert.NoError(t, err)
	assert.Equal(t, "access", accessClaims.TokenType)

	refreshClaims, err := svc.VerifyToken(pair.RefreshToken)
	assert.NoError(t, err)
	assert.Equal(t, "refresh", refreshClaims.TokenType)
}

func TestJWTService_TokenLifecycle(t *testing.T) {
	svc := setupTestJWTService(t)
	userID := uuid.New().String()
	tenantID := uuid.New().String()
	email := "test@example.com"
	roles := []string{"user"}

	// Generate access token
	accessToken, err := svc.GenerateAccessToken(userID, tenantID, email, roles)
	require.NoError(t, err)

	// Verify it immediately
	claims, err := svc.VerifyToken(accessToken)
	assert.NoError(t, err)
	assert.Equal(t, "access", claims.TokenType)
	assert.Equal(t, userID, claims.UserID)

	// Generate refresh token
	refreshToken, err := svc.GenerateRefreshToken(userID, tenantID, email)
	require.NoError(t, err)

	// Verify it
	refreshClaims, err := svc.VerifyToken(refreshToken)
	assert.NoError(t, err)
	assert.Equal(t, "refresh", refreshClaims.TokenType)
	assert.Equal(t, userID, refreshClaims.UserID)
}

func TestJWTService_GetTTLs(t *testing.T) {
	accessTTL := 15 * time.Minute
	refreshTTL := 7 * 24 * time.Hour

	keyPair, err := crypto.NewKeyPair(2048)
	require.NoError(t, err)

	privateKey, err := crypto.DecodePrivateKeyFromPEM(keyPair.PrivateKeyPEM)
	require.NoError(t, err)

	publicKey, err := crypto.DecodePublicKeyFromPEM(keyPair.PublicKeyPEM)
	require.NoError(t, err)

	svc := NewJWTService(privateKey, publicKey, keyPair.KeyID, accessTTL, refreshTTL)

	assert.Equal(t, accessTTL, svc.GetAccessTokenTTL())
	assert.Equal(t, refreshTTL, svc.GetRefreshTokenTTL())
}
