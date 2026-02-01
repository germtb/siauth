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

// TestGetIdentitiesIndexIsolation verifies that the username index correctly
// isolates identities between different users (critical for index correctness)
func TestGetIdentitiesIndexIsolation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "siauth_oidc_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	namespace := "test_index_isolation"
	store, err := MakeOIDCUserMappingStore(namespace)
	if err != nil {
		t.Fatalf("Failed to create mapping store: %v", err)
	}

	// Create identities for multiple users
	users := []struct {
		username   string
		identities []struct {
			provider string
			sub      string
		}
	}{
		{
			username: "alice",
			identities: []struct {
				provider string
				sub      string
			}{
				{"google", "alice_google_1"},
				{"github", "alice_github_1"},
				{"okta", "alice_okta_1"},
			},
		},
		{
			username: "bob",
			identities: []struct {
				provider string
				sub      string
			}{
				{"google", "bob_google_1"},
				{"microsoft", "bob_ms_1"},
			},
		},
		{
			username: "charlie",
			identities: []struct {
				provider string
				sub      string
			}{
				{"google", "charlie_google_1"},
			},
		},
	}

	// Link all identities
	for _, user := range users {
		for _, identity := range user.identities {
			err := store.LinkIdentity(identity.provider, identity.sub, user.username)
			if err != nil {
				t.Fatalf("Failed to link identity for %s: %v", user.username, err)
			}
		}
	}

	// Verify each user only sees their own identities
	for _, user := range users {
		identities, err := store.GetIdentities(user.username)
		if err != nil {
			t.Fatalf("Failed to get identities for %s: %v", user.username, err)
		}

		if len(identities) != len(user.identities) {
			t.Errorf("User %s: expected %d identities, got %d",
				user.username, len(user.identities), len(identities))
		}

		// Verify all returned identities belong to this user
		for _, identity := range identities {
			if identity.Username != user.username {
				t.Errorf("User %s: got identity belonging to %s (provider: %s, sub: %s)",
					user.username, identity.Username, identity.ProviderName, identity.ProviderSub)
			}
		}

		// Verify expected identities are present
		for _, expected := range user.identities {
			found := false
			for _, actual := range identities {
				if actual.ProviderName == expected.provider && actual.ProviderSub == expected.sub {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("User %s: missing identity %s:%s", user.username, expected.provider, expected.sub)
			}
		}
	}
}

// TestGetIdentitiesAfterUnlink verifies that the index is correctly updated
// when identities are unlinked
func TestGetIdentitiesAfterUnlink(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "siauth_oidc_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	namespace := "test_unlink_index"
	store, err := MakeOIDCUserMappingStore(namespace)
	if err != nil {
		t.Fatalf("Failed to create mapping store: %v", err)
	}

	// Link multiple identities
	store.LinkIdentity("google", "user_g1", "testuser")
	store.LinkIdentity("github", "user_gh1", "testuser")
	store.LinkIdentity("okta", "user_o1", "testuser")

	// Verify all 3 are present
	identities, _ := store.GetIdentities("testuser")
	if len(identities) != 3 {
		t.Fatalf("Expected 3 identities, got %d", len(identities))
	}

	// Unlink the middle one
	err = store.UnlinkIdentity("github", "user_gh1")
	if err != nil {
		t.Fatalf("Failed to unlink identity: %v", err)
	}

	// Verify only 2 remain
	identities, err = store.GetIdentities("testuser")
	if err != nil {
		t.Fatalf("Failed to get identities after unlink: %v", err)
	}

	if len(identities) != 2 {
		t.Errorf("Expected 2 identities after unlink, got %d", len(identities))
	}

	// Verify the correct ones remain
	for _, identity := range identities {
		if identity.ProviderName == "github" {
			t.Error("GitHub identity should have been unlinked")
		}
	}
}

// TestGetIdentitiesAfterRelink verifies that updating a mapping (relinking
// to a different user) correctly updates the index
func TestGetIdentitiesAfterRelink(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "siauth_oidc_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	namespace := "test_relink_index"
	store, err := MakeOIDCUserMappingStore(namespace)
	if err != nil {
		t.Fatalf("Failed to create mapping store: %v", err)
	}

	// Link identity to user1
	store.LinkIdentity("google", "shared_id", "user1")
	store.LinkIdentity("github", "user1_only", "user1")

	// Verify user1 has 2 identities
	identities1, _ := store.GetIdentities("user1")
	if len(identities1) != 2 {
		t.Fatalf("Expected 2 identities for user1, got %d", len(identities1))
	}

	// Relink the google identity to user2
	store.LinkIdentity("google", "shared_id", "user2")

	// Verify user1 now has only 1 identity
	identities1, _ = store.GetIdentities("user1")
	if len(identities1) != 1 {
		t.Errorf("Expected 1 identity for user1 after relink, got %d", len(identities1))
	}
	if len(identities1) > 0 && identities1[0].ProviderName != "github" {
		t.Error("user1 should only have github identity after relink")
	}

	// Verify user2 has the relinked identity
	identities2, _ := store.GetIdentities("user2")
	if len(identities2) != 1 {
		t.Errorf("Expected 1 identity for user2 after relink, got %d", len(identities2))
	}
	if len(identities2) > 0 && identities2[0].ProviderName != "google" {
		t.Error("user2 should have google identity after relink")
	}
}

// TestGetIdentitiesWithManyUsers stress tests the index with many users
func TestGetIdentitiesWithManyUsers(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "siauth_oidc_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	namespace := "test_many_users"
	store, err := MakeOIDCUserMappingStore(namespace)
	if err != nil {
		t.Fatalf("Failed to create mapping store: %v", err)
	}

	// Create 50 users with 3 identities each
	numUsers := 50
	identitiesPerUser := 3

	for i := 0; i < numUsers; i++ {
		username := "user_" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		for j := 0; j < identitiesPerUser; j++ {
			provider := []string{"google", "github", "okta"}[j]
			sub := username + "_" + provider + "_sub"
			err := store.LinkIdentity(provider, sub, username)
			if err != nil {
				t.Fatalf("Failed to link identity: %v", err)
			}
		}
	}

	// Verify a few users have correct identity count
	for i := 0; i < 10; i++ {
		username := "user_" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		identities, err := store.GetIdentities(username)
		if err != nil {
			t.Fatalf("Failed to get identities for %s: %v", username, err)
		}
		if len(identities) != identitiesPerUser {
			t.Errorf("User %s: expected %d identities, got %d",
				username, identitiesPerUser, len(identities))
		}

		// Verify all identities belong to this user
		for _, identity := range identities {
			if identity.Username != username {
				t.Errorf("User %s got identity belonging to %s", username, identity.Username)
			}
		}
	}
}

// TestGetIdentitiesSimilarUsernames tests that similar usernames don't get mixed up
func TestGetIdentitiesSimilarUsernames(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "siauth_oidc_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	namespace := "test_similar_usernames"
	store, err := MakeOIDCUserMappingStore(namespace)
	if err != nil {
		t.Fatalf("Failed to create mapping store: %v", err)
	}

	// Create users with similar names
	similarUsers := []string{
		"john",
		"john1",
		"john2",
		"john_doe",
		"johnny",
		"johnson",
	}

	for _, username := range similarUsers {
		store.LinkIdentity("google", "google_"+username, username)
	}

	// Verify each user only gets their own identity
	for _, username := range similarUsers {
		identities, err := store.GetIdentities(username)
		if err != nil {
			t.Fatalf("Failed to get identities for %s: %v", username, err)
		}

		if len(identities) != 1 {
			t.Errorf("User %s: expected 1 identity, got %d", username, len(identities))
		}

		if len(identities) > 0 && identities[0].Username != username {
			t.Errorf("User %s: got identity belonging to %s", username, identities[0].Username)
		}
	}
}
