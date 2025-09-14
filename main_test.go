package siauth

import (
	"testing"
	"time"

	"github.com/germtb/sidb"
	"google.golang.org/protobuf/proto"
)

func TestInit(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if auth == nil {
		t.Fatal("Auth is nil")
	}

	defer auth.db.Drop()

	if auth.pepper != pepper {
		t.Errorf("Expected pepper %v, got %v", pepper, auth.pepper)
	}
	if auth.db == nil {
		t.Fatal("Database is nil")
	}
}

func TestCreateUser(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer auth.db.Drop()

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
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer auth.db.Drop()

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
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer auth.db.Drop()

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
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer auth.db.Drop()

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
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer auth.db.Drop()

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
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	defer auth.db.Drop()

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
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer auth.db.Drop()

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
	serializedToken, err := proto.Marshal(token)

	if err != nil {
		t.Fatalf("Failed to serialize token: %v", err)
	}

	err = auth.db.Update(sidb.EntryInput{
		Key:   token.Code,
		Value: serializedToken,
		Type:  TOKEN_TYPE,
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
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer auth.db.Drop()

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

	err = auth.RefreshToken(token.Code)

	if err != nil {
		t.Fatalf("RefreshToken failed: %v", err)
	}

	entry, err := auth.db.GetByKey(token.Code, TOKEN_TYPE)
	if err != nil {
		t.Fatalf("Failed to retrieve token after refresh: %v", err)
	}

	var refreshedToken Token
	err = proto.Unmarshal(entry.Value, &refreshedToken)
	if err != nil {
		t.Fatalf("Failed to unmarshal refreshed token: %v", err)
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
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer auth.db.Drop()

	err = auth.CreateUser(CreateUserParams{
		Username: "testuser",
		Password: "password123",
	})

	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	err = auth.RefreshToken("invalidtokenvalue")

	if err != ErrMissingToken {
		t.Fatalf("Expected ErrMissingToken, got: %v", err)
	}
}

func TestRegenerateToken(t *testing.T) {
	pepper := [32]byte{}
	namespace := "test_namespace"

	auth, err := Init(pepper, namespace)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer auth.db.Drop()

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
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer auth.db.Drop()

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
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer auth.db.Drop()

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
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer auth.db.Drop()

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
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer auth.db.Drop()

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
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer auth.db.Drop()

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
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	defer auth.db.Drop()

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
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	defer auth.db.Drop()
	err = auth.RevokeToken("nonexistenttoken")

	if err != ErrMissingToken {
		t.Fatalf("Expected ErrMissingToken, got: %v", err)
	}
}
