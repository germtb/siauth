package siauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var ErrProviderNotFound = errors.New("OIDC provider not found")

// OIDCProvider represents a configured OIDC provider (Google, GitHub, Okta, etc.)
type OIDCProvider struct {
	Name         string
	ClientID     string
	ClientSecret string
	IssuerURL    string
	RedirectURL  string
	Scopes       []string

	// Initialized at runtime
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
}

// OIDCProviderStore manages all configured OIDC providers
type OIDCProviderStore struct {
	providers map[string]*OIDCProvider // keyed by provider name (e.g., "google")
	mutex     sync.RWMutex
}

// OIDCUserInfo contains user information extracted from ID token
type OIDCUserInfo struct {
	Sub           string // Unique provider user ID
	Email         string
	EmailVerified bool
	Name          string
}

// NewOIDCProviderStore creates a new provider store
func NewOIDCProviderStore() *OIDCProviderStore {
	return &OIDCProviderStore{
		providers: make(map[string]*OIDCProvider),
	}
}

// AddProvider adds an already-initialized OIDC provider to the store
func (s *OIDCProviderStore) AddProvider(provider *OIDCProvider) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.providers[provider.Name] = provider
}

// MakeOIDCProvider creates a generic OIDC provider
func MakeOIDCProvider(ctx context.Context, name string, clientID string, clientSecret string, issuerURL string, redirectURL string, scopes []string) (*OIDCProvider, error) {
	// Initialize OIDC provider
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OIDC provider %s: %w", name, err)
	}

	// Create verifier for ID tokens
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	// Create OAuth2 config
	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	return &OIDCProvider{
		Name:         name,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		IssuerURL:    issuerURL,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		provider:     provider,
		verifier:     verifier,
		oauth2Config: oauth2Config,
	}, nil
}

var DEFAULT_OIDC_SCOPES = []string{"openid", "email", "profile"}

// MakeGoogleOIDCProvider creates a Google OIDC provider
func MakeGoogleOIDCProvider(ctx context.Context, clientID string, clientSecret string, redirectURL string, scopes *[]string) (*OIDCProvider, error) {
	if scopes == nil {
		scopes = &DEFAULT_OIDC_SCOPES
	}
	return MakeOIDCProvider(
		ctx,
		"google",
		clientID,
		clientSecret,
		"https://accounts.google.com",
		redirectURL,
		*scopes,
	)
}

// MakeGitHubOIDCProvider creates a GitHub OIDC provider
// Note: GitHub uses OAuth 2.0, not pure OIDC
func MakeGitHubOIDCProvider(ctx context.Context, clientID string, clientSecret string, redirectURL string, scopes *[]string) (*OIDCProvider, error) {
	if scopes == nil {
		scopes = &DEFAULT_OIDC_SCOPES
	}
	return MakeOIDCProvider(
		ctx,
		"github",
		clientID,
		clientSecret,
		"https://github.com",
		redirectURL,
		*scopes,
	)
}

// MakeOktaOIDCProvider creates an Okta OIDC provider
func MakeOktaOIDCProvider(ctx context.Context, clientID string, clientSecret string, issuerURL string, redirectURL string, scopes *[]string) (*OIDCProvider, error) {
	if scopes == nil {
		scopes = &DEFAULT_OIDC_SCOPES
	}
	return MakeOIDCProvider(
		ctx,
		"okta",
		clientID,
		clientSecret,
		issuerURL,
		redirectURL,
		*scopes,
	)
}

// MakeAzureOIDCProvider creates an Azure AD OIDC provider
func MakeAzureOIDCProvider(ctx context.Context, clientID string, clientSecret string, tenantID string, redirectURL string, scopes *[]string) (*OIDCProvider, error) {
	issuerURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)
	if scopes == nil {
		scopes = &DEFAULT_OIDC_SCOPES
	}
	return MakeOIDCProvider(
		ctx,
		"azure",
		clientID,
		clientSecret,
		issuerURL,
		redirectURL,
		*scopes,
	)
}

// MakeAuth0OIDCProvider creates an Auth0 OIDC provider
func MakeAuth0OIDCProvider(ctx context.Context, clientID string, clientSecret string, domain string, redirectURL string, scopes *[]string) (*OIDCProvider, error) {
	if scopes == nil {
		scopes = &DEFAULT_OIDC_SCOPES
	}
	issuerURL := fmt.Sprintf("https://%s/", domain)
	return MakeOIDCProvider(
		ctx,
		"auth0",
		clientID,
		clientSecret,
		issuerURL,
		redirectURL,
		*scopes,
	)
}

// GetProvider retrieves a provider by name
func (s *OIDCProviderStore) GetProvider(name string) (*OIDCProvider, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	provider, ok := s.providers[name]
	if !ok {
		return nil, ErrProviderNotFound
	}

	return provider, nil
}

// ListProviders returns all provider names
func (s *OIDCProviderStore) ListProviders() []string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	names := make([]string, 0, len(s.providers))
	for name := range s.providers {
		names = append(names, name)
	}

	return names
}

// GetAuthCodeURL returns the OAuth2 authorization URL for initiating login
func (p *OIDCProvider) GetAuthCodeURL(state string, codeChallenge *string) string {
	opts := []oauth2.AuthCodeOption{}

	// Add PKCE challenge if provided (for CLI flows)
	if codeChallenge != nil {
		opts = append(opts, oauth2.SetAuthURLParam("code_challenge", *codeChallenge))
		opts = append(opts, oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	}

	return p.oauth2Config.AuthCodeURL(state, opts...)
}

// ExchangeCode exchanges authorization code for ID token and user info
func (p *OIDCProvider) ExchangeCode(ctx context.Context, code string, codeVerifier *string) (*OIDCUserInfo, error) {
	opts := []oauth2.AuthCodeOption{}

	// Add PKCE verifier if provided
	if codeVerifier != nil {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", *codeVerifier))
	}

	// Exchange code for OAuth2 token
	oauth2Token, err := p.oauth2Config.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Extract ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("no id_token field in oauth2 token")
	}

	// Verify ID token
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Extract claims
	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return &OIDCUserInfo{
		Sub:           claims.Sub,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
	}, nil
}

// GeneratePKCEChallenge generates a code challenge for PKCE
// Returns (verifier, challenge)
func GeneratePKCEChallenge() (string, string, error) {
	// Generate random verifier (43-128 characters)
	verifierBytes := make([]byte, 32)
	err := secureRandom(verifierBytes)
	if err != nil {
		return "", "", err
	}

	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	// Generate S256 challenge
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return verifier, challenge, nil
}
