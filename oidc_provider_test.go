package siauth

import (
	"testing"
)

func TestAddProvider(t *testing.T) {
	store := NewOIDCProviderStore()

	// Note: This will fail without a real OIDC provider endpoint
	// For testing, we'd need to mock the OIDC discovery or use a test server
	// For now, testing the store management only

	// Test GetProvider before adding
	_, err := store.GetProvider("test")
	if err != ErrProviderNotFound {
		t.Errorf("Expected ErrProviderNotFound, got %v", err)
	}
}

func TestListProviders(t *testing.T) {
	store := NewOIDCProviderStore()

	// Test with empty store
	providers := store.ListProviders()
	if len(providers) != 0 {
		t.Errorf("Expected empty list, got %d providers", len(providers))
	}

	// TODO: Add test with actual providers once we have mock OIDC server
}

func TestGeneratePKCEChallenge(t *testing.T) {
	verifier, challenge, err := GeneratePKCEChallenge()
	if err != nil {
		t.Fatalf("Failed to generate PKCE challenge: %v", err)
	}

	// Verifier should be base64url encoded, at least 43 chars
	if len(verifier) < 43 {
		t.Errorf("Verifier too short: %d chars", len(verifier))
	}

	// Challenge should be base64url encoded SHA256 hash
	if len(challenge) != 43 {
		t.Errorf("Challenge should be 43 chars (base64url SHA256), got %d", len(challenge))
	}

	// Should not contain padding
	if verifier[len(verifier)-1] == '=' || challenge[len(challenge)-1] == '=' {
		t.Error("PKCE values should not contain padding (base64url)")
	}

	// Generating again should produce different values
	verifier2, challenge2, err := GeneratePKCEChallenge()
	if err != nil {
		t.Fatalf("Failed to generate second PKCE challenge: %v", err)
	}

	if verifier == verifier2 {
		t.Error("PKCE verifiers should be unique")
	}

	if challenge == challenge2 {
		t.Error("PKCE challenges should be unique")
	}
}

func TestGetAuthCodeURL(t *testing.T) {
	// This test would require a mock OIDC provider
	// Skipping for now, as it requires network calls
	t.Skip("Requires mock OIDC provider")
}

func TestExchangeCode(t *testing.T) {
	// This test would require a mock OIDC provider
	// Skipping for now, as it requires network calls
	t.Skip("Requires mock OIDC provider")
}
