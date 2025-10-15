package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/victoralfred/kube_manager/pkg/crypto"
)

// JWTService handles JWT token operations using RSA
type JWTService struct {
	privateKey       *crypto.PrivateKey
	publicKey        *crypto.PublicKey
	keyID            string
	accessTokenTTL   time.Duration
	refreshTokenTTL  time.Duration
}

// NewJWTService creates a new JWT service with RSA keys
func NewJWTService(
	privateKey *crypto.PrivateKey,
	publicKey *crypto.PublicKey,
	keyID string,
	accessTTL,
	refreshTTL time.Duration,
) *JWTService {
	return &JWTService{
		privateKey:      privateKey,
		publicKey:       publicKey,
		keyID:           keyID,
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
	}
}

// GenerateAccessToken generates an access JWT token
func (j *JWTService) GenerateAccessToken(userID, tenantID, email string, roles []string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:    userID,
		TenantID:  tenantID,
		Email:     email,
		Roles:     roles,
		TokenType: "access",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(j.accessTokenTTL).Unix(),
		NotBefore: now.Unix(),
		Subject:   userID,
		KeyID:     j.keyID,
	}

	return j.generateToken(claims)
}

// GenerateRefreshToken generates a refresh JWT token
func (j *JWTService) GenerateRefreshToken(userID, tenantID, email string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:    userID,
		TenantID:  tenantID,
		Email:     email,
		TokenType: "refresh",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(j.refreshTokenTTL).Unix(),
		NotBefore: now.Unix(),
		Subject:   userID,
		KeyID:     j.keyID,
	}

	return j.generateToken(claims)
}

// GenerateTokenPair generates both access and refresh tokens
func (j *JWTService) GenerateTokenPair(userID, tenantID, email string, roles []string) (*TokenPair, error) {
	accessToken, err := j.GenerateAccessToken(userID, tenantID, email, roles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := j.GenerateRefreshToken(userID, tenantID, email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	expiresAt := time.Now().Add(j.accessTokenTTL)

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(j.accessTokenTTL.Seconds()),
		ExpiresAt:    expiresAt,
	}, nil
}

// VerifyToken verifies and parses a JWT token
func (j *JWTService) VerifyToken(tokenString string) (*Claims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrTokenMalformed
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Verify algorithm
	if alg, ok := header["alg"].(string); !ok || alg != "RS256" {
		return nil, fmt.Errorf("unsupported algorithm: %v", header["alg"])
	}

	// Decode claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Verify signature using our crypto package
	message := []byte(parts[0] + "." + parts[1])
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	err = crypto.VerifyRSAPKCS1v15(j.publicKey, message, signature)
	if err != nil {
		return nil, ErrTokenSignature
	}

	// Verify expiration
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, ErrTokenExpired
	}

	// Verify not before
	if time.Now().Unix() < claims.NotBefore {
		return nil, ErrInvalidToken
	}

	return &claims, nil
}

// generateToken creates a JWT token with RSA signature
func (j *JWTService) generateToken(claims Claims) (string, error) {
	// Create header
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": j.keyID,
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Encode header and claims
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsBytes)

	// Create message to sign
	message := []byte(headerEncoded + "." + claimsEncoded)

	// Sign with RSA private key using our crypto package
	signature, err := crypto.SignSHA256(j.privateKey, message)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	// Encode signature
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	// Combine all parts
	token := headerEncoded + "." + claimsEncoded + "." + signatureEncoded

	return token, nil
}

// GetAccessTokenTTL returns the access token TTL
func (j *JWTService) GetAccessTokenTTL() time.Duration {
	return j.accessTokenTTL
}

// GetRefreshTokenTTL returns the refresh token TTL
func (j *JWTService) GetRefreshTokenTTL() time.Duration {
	return j.refreshTokenTTL
}
