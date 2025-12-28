package siauth

import (
	"os"
	"testing"
)

func TestOIDCUserMappingStore(t *testing.T) {
	// Create temp directory for test database
	tmpDir, err := os.MkdirTemp("", "siauth_oidc_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Change to temp dir
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	namespace := "test_oidc_mappings"
	store, err := MakeOIDCUserMappingStore(namespace)
	if err != nil {
		t.Fatalf("Failed to create mapping store: %v", err)
	}

	if store == nil {
		t.Fatal("Expected store to be created")
	}

	// Test GetUsername when mapping doesn't exist
	username, err := store.GetUsername("google", "user123")
	if err != ErrOIDCMappingNotFound {
		t.Errorf("Expected ErrOIDCMappingNotFound, got %v", err)
	}
	if username != "" {
		t.Errorf("Expected empty username, got %s", username)
	}
}

func TestLinkIdentity(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "siauth_oidc_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	namespace := "test_link_identity"
	store, err := MakeOIDCUserMappingStore(namespace)
	if err != nil {
		t.Fatalf("Failed to create mapping store: %v", err)
	}

	// Link an identity
	err = store.LinkIdentity("google", "google_user_123", "john_doe")
	if err != nil {
		t.Fatalf("Failed to link identity: %v", err)
	}

	// Retrieve the username
	username, err := store.GetUsername("google", "google_user_123")
	if err != nil {
		t.Fatalf("Failed to get username: %v", err)
	}

	if username != "john_doe" {
		t.Errorf("Expected username 'john_doe', got '%s'", username)
	}
}

func TestLinkMultipleIdentities(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "siauth_oidc_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	namespace := "test_multiple_identities"
	store, err := MakeOIDCUserMappingStore(namespace)
	if err != nil {
		t.Fatalf("Failed to create mapping store: %v", err)
	}

	// Link Google identity
	err = store.LinkIdentity("google", "google_123", "alice")
	if err != nil {
		t.Fatalf("Failed to link Google identity: %v", err)
	}

	// Link GitHub identity to same user
	err = store.LinkIdentity("github", "github_456", "alice")
	if err != nil {
		t.Fatalf("Failed to link GitHub identity: %v", err)
	}

	// Verify both mappings exist
	username1, err := store.GetUsername("google", "google_123")
	if err != nil || username1 != "alice" {
		t.Errorf("Google identity not mapped correctly")
	}

	username2, err := store.GetUsername("github", "github_456")
	if err != nil || username2 != "alice" {
		t.Errorf("GitHub identity not mapped correctly")
	}

	// Get all identities for user
	identities, err := store.GetIdentities("alice")
	if err != nil {
		t.Fatalf("Failed to get identities: %v", err)
	}

	if len(identities) != 2 {
		t.Errorf("Expected 2 identities, got %d", len(identities))
	}

	// Verify both providers are present
	foundGoogle := false
	foundGitHub := false
	for _, identity := range identities {
		if identity.ProviderName == "google" && identity.ProviderSub == "google_123" {
			foundGoogle = true
		}
		if identity.ProviderName == "github" && identity.ProviderSub == "github_456" {
			foundGitHub = true
		}
	}

	if !foundGoogle {
		t.Error("Google identity not found in GetIdentities result")
	}
	if !foundGitHub {
		t.Error("GitHub identity not found in GetIdentities result")
	}
}

func TestUnlinkIdentity(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "siauth_oidc_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	namespace := "test_unlink_identity"
	store, err := MakeOIDCUserMappingStore(namespace)
	if err != nil {
		t.Fatalf("Failed to create mapping store: %v", err)
	}

	// Link an identity
	err = store.LinkIdentity("google", "user_789", "bob")
	if err != nil {
		t.Fatalf("Failed to link identity: %v", err)
	}

	// Verify it exists
	username, err := store.GetUsername("google", "user_789")
	if err != nil || username != "bob" {
		t.Error("Identity not linked correctly")
	}

	// Unlink the identity
	err = store.UnlinkIdentity("google", "user_789")
	if err != nil {
		t.Fatalf("Failed to unlink identity: %v", err)
	}

	// Verify it no longer exists
	username, err = store.GetUsername("google", "user_789")
	if err != ErrOIDCMappingNotFound {
		t.Errorf("Expected ErrOIDCMappingNotFound after unlinking, got %v", err)
	}
}

func TestMakeOIDCMappingKey(t *testing.T) {
	tests := []struct {
		provider string
		sub      string
		expected string
	}{
		{"google", "12345", "google:12345"},
		{"github", "user-abc", "github:user-abc"},
		{"okta", "admin@example.com", "okta:admin@example.com"},
	}

	for _, tt := range tests {
		result := makeOIDCMappingKey(tt.provider, tt.sub)
		if result != tt.expected {
			t.Errorf("makeOIDCMappingKey(%s, %s) = %s, want %s",
				tt.provider, tt.sub, result, tt.expected)
		}
	}
}

func TestUpdateExistingMapping(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "siauth_oidc_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	namespace := "test_update_mapping"
	store, err := MakeOIDCUserMappingStore(namespace)
	if err != nil {
		t.Fatalf("Failed to create mapping store: %v", err)
	}

	// Link identity to user1
	err = store.LinkIdentity("google", "user_999", "user1")
	if err != nil {
		t.Fatalf("Failed to link identity: %v", err)
	}

	// Update to link same identity to user2 (e.g., account migration)
	err = store.LinkIdentity("google", "user_999", "user2")
	if err != nil {
		t.Fatalf("Failed to update link: %v", err)
	}

	// Verify it now points to user2
	username, err := store.GetUsername("google", "user_999")
	if err != nil {
		t.Fatalf("Failed to get username: %v", err)
	}

	if username != "user2" {
		t.Errorf("Expected username 'user2' after update, got '%s'", username)
	}
}

func TestGetIdentitiesForNonexistentUser(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "siauth_oidc_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	namespace := "test_nonexistent_user"
	store, err := MakeOIDCUserMappingStore(namespace)
	if err != nil {
		t.Fatalf("Failed to create mapping store: %v", err)
	}

	identities, err := store.GetIdentities("nonexistent_user")
	if err != nil {
		t.Fatalf("GetIdentities should not error for nonexistent user: %v", err)
	}

	if len(identities) != 0 {
		t.Errorf("Expected empty identity list for nonexistent user, got %d", len(identities))
	}
}
