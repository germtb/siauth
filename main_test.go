package siauth

import (
	"testing"
	"time"

	"github.com/germtb/sidb"
)

func Cleanup(siauth *Auth) {
	if siauth == nil {
		return
	}
	siauth.tokenStore.DropParentDb()
	for _, db := range siauth.userDbs {
		db.Drop()
	}
}

func TestInit(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if auth == nil {
		t.Fatal("Auth is nil")
	}

	if auth.pepper != pepper {
		t.Errorf("Expected pepper %v, got %v", pepper, auth.pepper)
	}
	if auth.tokenStore == nil {
		t.Fatal("Database is nil")
	}

}

func TestCreateUser(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	params := CreateUserParams{
		Username: "testuser",
		Password: "password123",
	}

	err = auth.CreateUser(params)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
}

func TestCreateDuplicateUser(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	params := CreateUserParams{
		Username: "testuser",
		Password: "password123",
	}

	err = auth.CreateUser(params)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	err = auth.CreateUser(params)
	if err != ErrUserExists {
		t.Fatalf("Expected ErrUserExists, got: %v", err)
	}
}

func TestGenerateToken(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	params := CreateUserParams{
		Username: "testuser",
		Password: "password123",
	}

	err = auth.CreateUser(params)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	token, err := auth.GenerateToken("testuser")

	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	if token == nil {
		t.Fatal("Expected authentication to succeed")
	}

	if token.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got: %v", token.Username)
	}

	if token.Code == "" {
		t.Error("Expected non-empty token string")
	}

	if !isBetween(time.UnixMilli(token.Expiry), time.Now(), time.Now().Add(24*time.Hour)) {
		t.Errorf("Token expiry time is not within expected range")
	}
}

func TestGenerateTokenNonExistentUser(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	token, err := auth.GenerateToken("nonexistentuser")
	if err == nil {
		t.Fatal("Expected error for non-existent user")
	}
	if token != nil {
		t.Fatal("Expected authentication to fail for non-existent user")
	}

}

func isBetween(t time.Time, start time.Time, end time.Time) bool {
	return !t.Before(start) && !t.After(end)
}

func TestAuthenticateToken(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = auth.CreateUser(CreateUserParams{
		Username: "testuser",
		Password: "password123",
	})

	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	token, err := auth.GenerateToken("testuser")

	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if token == nil {
		t.Fatal("Expected token to be generated")
	}

	validatedToken, err := auth.ValidateToken(token.Code)

	if err != nil {
		t.Fatalf("AuthenticateToken failed: %v", err)
	}

	if validatedToken == nil {
		t.Fatal("Expected token to be valid")
	}

	if validatedToken.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got: %v", validatedToken.Username)
	}

	if validatedToken.Code != token.Code {
		t.Errorf("Expected token code '%v', got: %v", token.Code, validatedToken.Code)
	}
}

func TestAuthenticateTokenInvalid(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = auth.CreateUser(CreateUserParams{
		Username: "testuser",
		Password: "password123",
	})

	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	token, err := auth.GenerateToken("testuser")

	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	if token == nil {
		t.Fatal("Expected token to be generated")
	}

	validatedToken, err := auth.ValidateToken("invalidtokenvalue")
	if err == nil {
		t.Fatal("Expected error for invalid token")
	}
	if validatedToken != nil {
		t.Fatal("Expected token to be invalid")
	}
}

func TestAuthenticateTokenExpired(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = auth.CreateUser(CreateUserParams{
		Username: "testuser",
		Password: "password123",
	})

	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	token, err := auth.GenerateToken("testuser")

	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if token == nil {
		t.Fatal("Expected token to be generated")
	}

	// Manually expire the token
	token.Expiry = time.Now().Add(-1 * time.Hour).UnixMilli()

	err = auth.tokenStore.Upsert(sidb.StoreEntryInput[*Token]{
		Key:   token.Code,
		Value: token,
	})
	if err != nil {
		t.Fatalf("Failed to update token expiry: %v", err)
	}

	validatedToken, err := auth.ValidateToken(token.Code)
	if err == nil {
		t.Fatal("Expected error for expired token")
	}
	if validatedToken != nil {
		t.Fatal("Expected token to be expired and invalid")
	}
}

func TestRefreshToken(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = auth.CreateUser(CreateUserParams{
		Username: "testuser",
		Password: "password123",
	})

	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	token, err := auth.GenerateToken("testuser")

	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if token == nil {
		t.Fatal("Expected token to be generated")
	}

	originalExpiry := token.Expiry

	time.Sleep(1 * time.Second) // Ensure time has passed for expiry comparison

	// Note: RefreshToken method doesn't exist - ValidateToken auto-refreshes
	// err = auth.RefreshToken(token.Code)
	_, err = auth.ValidateToken(token.Code)

	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	refreshedToken, err := auth.tokenStore.Get(token.Code)
	if err != nil {
		t.Fatalf("Failed to retrieve token after refresh: %v", err)
	}

	if refreshedToken.Expiry <= originalExpiry {
		t.Fatal("Expected token expiry to be extended")
	}
	if refreshedToken.Code != token.Code {
		t.Fatal("Expected token code to remain the same after refresh")
	}
}

func TestRefreshMissingToken(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = auth.CreateUser(CreateUserParams{
		Username: "testuser",
		Password: "password123",
	})

	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Note: RefreshToken method doesn't exist - using ValidateToken instead
	_, err = auth.ValidateToken("invalidtokenvalue")

	if err != ErrMissingToken {
		t.Fatalf("Expected ErrMissingToken, got: %v", err)
	}
}

func TestRegenerateToken(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = auth.CreateUser(CreateUserParams{
		Username: "testuser",
		Password: "password123",
	})

	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	originalToken, err := auth.GenerateToken("testuser")

	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if originalToken == nil {
		t.Fatal("Expected token to be generated")
	}

	newToken, err := auth.RegenerateToken(originalToken.Code)

	if err != nil {
		t.Fatalf("RegenerateToken failed: %v", err)
	}

	if newToken.Code == originalToken.Code {
		t.Fatal("Expected new token code to be different from original")
	}

	validatedToken, err := auth.ValidateToken(newToken.Code)

	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if validatedToken == nil {
		t.Fatal("Expected new token to be valid")
	}

	invalidToken, err := auth.ValidateToken(originalToken.Code)

	if err != ErrMissingToken {
		t.Fatalf("Expected ErrMissingToken, got: %v", err)
	}

	if invalidToken != nil {
		t.Fatal("Expected original token to be invalid after regeneration")
	}
}

func TestValidatePassword(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = auth.CreateUser(CreateUserParams{
		Username: "testuser",
		Password: "password123",
	})

	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	valid, err := auth.ValidatePassword("testuser", "password123")
	if err != nil {
		t.Fatalf("ValidatePassword failed: %v", err)
	}
	if !valid {
		t.Fatal("Expected password to be valid")
	}
}

func TestValidatePasswordInvalid(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = auth.CreateUser(CreateUserParams{
		Username: "testuser",
		Password: "password123",
	})

	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	valid, err := auth.ValidatePassword("testuser", "wrongpassword")
	if err != ErrInvalidCredentials {
		t.Fatalf("Expected ErrInvalidCredentials, got: %v", err)
	}
	if valid {
		t.Fatal("Expected password to be invalid")
	}
}

func TestValidatePasswordNonExistentUser(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	valid, err := auth.ValidatePassword("nonexistentuser", "password123")
	if err == nil {
		t.Fatal("Expected error for non-existent user")
	}
	if valid {
		t.Fatal("Expected password validation to fail for non-existent user")
	}
}

func TestChangePassword(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = auth.CreateUser(CreateUserParams{
		Username: "testuser",
		Password: "password123",
	})

	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	err = auth.ChangePassword("testuser", "password123", "newpassword456")
	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	valid, err := auth.ValidatePassword("testuser", "newpassword456")
	if err != nil {
		t.Fatalf("ValidatePassword failed: %v", err)
	}
	if !valid {
		t.Fatal("Expected new password to be valid")
	}

	// Ensure old password is no longer valid
	valid, err = auth.ValidatePassword("testuser", "password123")
	if err != ErrInvalidCredentials {
		t.Fatalf("Expected ErrInvalidCredentials for old password, got: %v", err)
	}
	if valid {
		t.Fatal("Expected old password to be invalid")
	}
}

func TestResetPasswordWithToken(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = auth.CreateUser(CreateUserParams{
		Username: "testuser",
		Password: "password123",
	})

	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Generate a reset token
	resetToken, err := auth.GeneratePasswordResetToken("testuser")
	if err != nil {
		t.Fatalf("GeneratePasswordResetToken failed: %v", err)
	}

	err = auth.ResetPasswordWithToken("testuser", resetToken.Code, "newpassword456")
	if err != nil {
		t.Fatalf("ResetPasswordWithToken failed: %v", err)
	}

	valid, err := auth.ValidatePassword("testuser", "newpassword456")
	if err != nil {
		t.Fatalf("ValidatePassword failed: %v", err)
	}
	if !valid {
		t.Fatal("Expected new password to be valid")
	}

	// Ensure old password is no longer valid
	valid, err = auth.ValidatePassword("testuser", "password123")
	if err != ErrInvalidCredentials {
		t.Fatalf("Expected ErrInvalidCredentials for old password, got: %v", err)
	}
	if valid {
		t.Fatal("Expected old password to be invalid")
	}
}

func TestRevokeToken(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = auth.CreateUser(CreateUserParams{
		Username: "testuser",
		Password: "password123",
	})

	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	token, err := auth.GenerateToken("testuser")

	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	if token == nil {
		t.Fatal("Expected token to be generated")
	}

	err = auth.RevokeToken(token.Code)
	if err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	validatedToken, err := auth.ValidateToken(token.Code)
	if err == nil {
		t.Fatal("Expected error for revoked token")
	}
	if validatedToken != nil {
		t.Fatal("Expected token to be invalid after revocation")
	}
}

func TestRevokeMissingToken(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = auth.RevokeToken("nonexistenttoken")

	if err != ErrMissingToken {
		t.Fatalf("Expected ErrMissingToken, got: %v", err)
	}
}

func TestGetTokensByUsername(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = auth.CreateUser(CreateUserParams{
		Username: "testuser",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Generate multiple tokens for the user
	for i := 0; i < 3; i++ {
		_, err := auth.GenerateToken("testuser")
		if err != nil {
			t.Fatalf("GenerateToken failed: %v", err)
		}
	}

	tokens, err := auth.GetTokensByUsername("testuser")
	if err != nil {
		t.Fatalf("GetTokensByUsername failed: %v", err)
	}

	if len(tokens) != 3 {
		t.Fatalf("Expected 3 tokens, got: %d", len(tokens))
	}
	for _, token := range tokens {
		if token.Username != "testuser" {
			t.Errorf("Expected token username 'testuser', got: %v", token.Username)
		}
	}
}

func TestGetTokensByUsernameNoTokens(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = auth.CreateUser(CreateUserParams{
		Username: "testuser",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	tokens, err := auth.GetTokensByUsername("testuser")
	if err != nil {
		t.Fatalf("GetTokensByUsername failed: %v", err)
	}

	if len(tokens) != 0 {
		t.Fatalf("Expected 0 tokens, got: %d", len(tokens))
	}
}

func TestGetTokensByUsernameNonExistentUser(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	tokens, err := auth.GetTokensByUsername("nonexistentuser")
	if err != nil {
		t.Fatalf("GetTokensByUsername failed: %v", err)
	}
	if len(tokens) != 0 {
		t.Fatalf("Expected 0 tokens for non-existent user, got: %d", len(tokens))
	}
}

func TestCreateUserWithInvalidName(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	params := CreateUserParams{
		Username: "invalid user!", // Invalid due to space and exclamation mark
		Password: "password123",
	}

	err = auth.CreateUser(params)
	if err != ErrInvalidUsername {
		t.Fatalf("Expected ErrInvalidUsername, got: %v", err)
	}

}

// OIDC Integration Tests

func TestGenerateUsernameFromEmail(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"john.doe@example.com", "john_doe"},
		{"alice+tag@gmail.com", "alice_tag"},
		{"bob-smith@company.co.uk", "bob_smith"},
		{"user123@test.org", "user123"},
		{"a@b.com", "a_user"},                    // Too short, padded
		{"verylongemailaddressusername@test.com", "verylongemailaddress"}, // Truncated to 20
		{"UPPERCASE@test.com", "uppercase"},
		{"with spaces@test.com", "with_spaces"},
		{"special!@#chars@test.com", "special_"},  // Special chars replaced with single _
	}

	for _, tt := range tests {
		result := generateUsernameFromEmail(tt.email)
		if result != tt.expected {
			t.Errorf("generateUsernameFromEmail(%s) = %s, want %s",
				tt.email, result, tt.expected)
		}

		// Verify result is valid username
		if !validateUsername(result) {
			t.Errorf("generateUsernameFromEmail(%s) produced invalid username: %s",
				tt.email, result)
		}
	}
}

func TestGenerateRandomPassword(t *testing.T) {
	password1 := generateRandomPassword()
	password2 := generateRandomPassword()

	// Should be non-empty
	if len(password1) == 0 || len(password2) == 0 {
		t.Error("Generated password should not be empty")
	}

	// Should be base64url encoded (no padding)
	if password1[len(password1)-1] == '=' || password2[len(password2)-1] == '=' {
		t.Error("Random password should not contain padding")
	}

	// Should be unique
	if password1 == password2 {
		t.Error("Random passwords should be unique")
	}

	// Should be reasonably long
	if len(password1) < 40 {
		t.Errorf("Random password too short: %d chars", len(password1))
	}
}

func TestOIDCUserMappingIntegration(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_oidc_integration"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Create a user
	err = auth.CreateUser(CreateUserParams{
		Username: "testuser",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Link OIDC identity to the user
	err = auth.oidcUserMappings.LinkIdentity("google", "google_sub_123", "testuser")
	if err != nil {
		t.Fatalf("Failed to link identity: %v", err)
	}

	// Verify mapping exists
	username, err := auth.oidcUserMappings.GetUsername("google", "google_sub_123")
	if err != nil {
		t.Fatalf("Failed to get username: %v", err)
	}

	if username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", username)
	}

	// Get all identities for user
	identities, err := auth.oidcUserMappings.GetIdentities("testuser")
	if err != nil {
		t.Fatalf("Failed to get identities: %v", err)
	}

	if len(identities) != 1 {
		t.Errorf("Expected 1 identity, got %d", len(identities))
	}

	if identities[0].ProviderName != "google" || identities[0].ProviderSub != "google_sub_123" {
		t.Error("Identity details don't match")
	}
}

func TestJITUserProvisioningSimulation(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_jit_provisioning"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Simulate JIT provisioning for new OIDC user
	email := "newuser@gmail.com"
	username := generateUsernameFromEmail(email)
	randomPassword := generateRandomPassword()

	// Create user with random password (OIDC-only account)
	err = auth.CreateUser(CreateUserParams{
		Username: username,
		Password: randomPassword,
		Email:    &email,
	})
	if err != nil {
		t.Fatalf("Failed to create JIT user: %v", err)
	}

	// Link OIDC identity
	err = auth.oidcUserMappings.LinkIdentity("google", "new_google_sub", username)
	if err != nil {
		t.Fatalf("Failed to link OIDC identity: %v", err)
	}

	// Verify user was created
	store, err := auth.GetUserStore(username)
	if err != nil {
		t.Fatalf("Failed to get user store: %v", err)
	}

	user, err := store.Get(username)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	if user == nil {
		t.Fatal("User not found after JIT provisioning")
	}

	if user.Email == nil || *user.Email != email {
		t.Errorf("User email not set correctly")
	}

	// Verify token can be generated for JIT user
	token, err := auth.GenerateToken(username)
	if err != nil {
		t.Fatalf("Failed to generate token for JIT user: %v", err)
	}

	if token == nil {
		t.Fatal("Token is nil")
	}

	if token.Username != username {
		t.Errorf("Expected token username '%s', got '%s'", username, token.Username)
	}
}

func TestUsernameCollisionHandling(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_collision"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Create a user with the base username
	baseUsername := "john_doe"
	err = auth.CreateUser(CreateUserParams{
		Username: baseUsername,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Failed to create base user: %v", err)
	}

	// Simulate collision - try to create user with same username
	email := "john.doe@newcompany.com"
	username := generateUsernameFromEmail(email)

	if username != baseUsername {
		t.Fatalf("Expected username collision scenario, got different usernames")
	}

	// First attempt should fail
	err = auth.CreateUser(CreateUserParams{
		Username: username,
		Password: "password456",
	})
	if err != ErrUserExists {
		t.Fatalf("Expected ErrUserExists, got %v", err)
	}

	// Try with suffix (simulating collision resolution)
	usernameWithSuffix := username + "1"
	err = auth.CreateUser(CreateUserParams{
		Username: usernameWithSuffix,
		Password: "password456",
	})
	if err != nil {
		t.Fatalf("Failed to create user with suffix: %v", err)
	}

	// Verify both users exist
	store1, _ := auth.GetUserStore(baseUsername)
	user1, _ := store1.Get(baseUsername)
	if user1 == nil {
		t.Error("Base user not found")
	}

	store2, _ := auth.GetUserStore(usernameWithSuffix)
	user2, _ := store2.Get(usernameWithSuffix)
	if user2 == nil {
		t.Error("User with suffix not found")
	}
}

func TestMultipleOIDCProvidersForSameUser(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_multiple_providers"

	auth, err := Init(pepper, namespace)
	defer Cleanup(auth)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Create user
	username := "multiuser"
	err = auth.CreateUser(CreateUserParams{
		Username: username,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Link multiple OIDC providers to same user
	providers := []struct {
		provider string
		sub      string
	}{
		{"google", "google_123"},
		{"github", "github_456"},
		{"okta", "okta_789"},
	}

	for _, p := range providers {
		err = auth.oidcUserMappings.LinkIdentity(p.provider, p.sub, username)
		if err != nil {
			t.Fatalf("Failed to link %s identity: %v", p.provider, err)
		}
	}

	// Verify all mappings
	for _, p := range providers {
		retrievedUsername, err := auth.oidcUserMappings.GetUsername(p.provider, p.sub)
		if err != nil {
			t.Fatalf("Failed to get username for %s: %v", p.provider, err)
		}
		if retrievedUsername != username {
			t.Errorf("Expected username '%s' for %s, got '%s'",
				username, p.provider, retrievedUsername)
		}
	}

	// Get all identities for user
	identities, err := auth.oidcUserMappings.GetIdentities(username)
	if err != nil {
		t.Fatalf("Failed to get identities: %v", err)
	}

	if len(identities) != 3 {
		t.Errorf("Expected 3 identities, got %d", len(identities))
	}
}

func TestSecureRandomGeneration(t *testing.T) {
	// Test secure random generation
	bytes1 := make([]byte, 32)
	bytes2 := make([]byte, 32)

	err := secureRandom(bytes1)
	if err != nil {
		t.Fatalf("secureRandom failed: %v", err)
	}

	err = secureRandom(bytes2)
	if err != nil {
		t.Fatalf("secureRandom failed: %v", err)
	}

	// Should not be all zeros
	allZeros := true
	for _, b := range bytes1 {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("secureRandom generated all zeros")
	}

	// Should be different
	same := true
	for i := range bytes1 {
		if bytes1[i] != bytes2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("secureRandom generated identical values")
	}
}
