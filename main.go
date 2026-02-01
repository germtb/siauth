package siauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	sync "sync"
	"time"

	"github.com/germtb/sidb"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/proto"
)

type User struct {
	Id       int64  // autoincrement
	Username string // unique
	Email    *string
	Name     *string
	Number   *string
}

type Auth struct {
	pepper     [32]byte
	namespace  string
	root       string
	userDbs    map[string]*sidb.Database
	mutex      sync.Mutex
	tokenStore *sidb.Store[*Token]
	codeStore  *sidb.Store[*AuthCode]

	// OIDC support
	oidcProviders    map[string]*OIDCProvider
	oidcUserMappings *OIDCUserMappingStore
}

func serialize[T proto.Message](msg T) ([]byte, error) {
	return proto.Marshal(msg)
}

func deserializeToken(data []byte) (*Token, error) {
	var token Token
	err := proto.Unmarshal(data, &token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func deserializeAuthCode(data []byte) (*AuthCode, error) {
	var code AuthCode
	err := proto.Unmarshal(data, &code)
	if err != nil {
		return nil, err
	}
	return &code, nil
}

func deserializeUser(data []byte) (*ProtoUser, error) {
	var user ProtoUser
	err := proto.Unmarshal(data, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func Init(
	pepper [32]byte,
	namespace string,
	oidcProviders ...*OIDCProvider,
) (*Auth, error) {
	return InitWithRoot(pepper, namespace, "", oidcProviders...)
}

func InitWithRoot(
	pepper [32]byte,
	namespace string,
	root string,
	oidcProviders ...*OIDCProvider,
) (*Auth, error) {
	tokenDb, err := sidb.InitWithRoot(root, []string{namespace}, "tokens")

	if err != nil {
		return nil, err
	}

	oidcMappingStore, err := MakeOIDCUserMappingStoreWithRoot(namespace, root)
	if err != nil {
		return nil, err
	}

	// Build provider map from list
	oidcProviderMap := make(map[string]*OIDCProvider)
	for _, provider := range oidcProviders {
		oidcProviderMap[provider.Name] = provider
	}

	return &Auth{
		pepper:           pepper,
		namespace:        namespace,
		root:             root,
		userDbs:          map[string]*sidb.Database{},
		tokenStore:       sidb.MakeStore(tokenDb, "token", serialize, deserializeToken, nil, nil),
		codeStore:        sidb.MakeStore(tokenDb, "auth_code", serialize, deserializeAuthCode, nil, nil),
		oidcProviders:    oidcProviderMap,
		oidcUserMappings: oidcMappingStore,
		mutex:            sync.Mutex{},
	}, nil
}

func (auth *Auth) applyPepper(password string) []byte {
	mac := hmac.New(sha256.New, auth.pepper[:])
	mac.Write([]byte(password))
	return mac.Sum(nil)
}

func (auth *Auth) HashPassword(password string) ([]byte, error) {
	peppered := auth.applyPepper(password)
	hash, err := bcrypt.GenerateFromPassword(peppered, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

type CreateUserParams struct {
	Username string
	Password string
	Email    *string
	Name     *string
	Number   *string
}

var ErrUserExists = errors.New("user already exists")

func (auth *Auth) GetUserDatabase(username string) (*sidb.Database, error) {
	auth.mutex.Lock()
	db, ok := auth.userDbs[username]
	auth.mutex.Unlock()

	if ok {
		return db, nil
	}

	db, err := sidb.InitWithRoot(auth.root, []string{auth.namespace, "users"}, username)

	if err != nil {
		return nil, err
	}

	auth.mutex.Lock()
	existingDb, ok := auth.userDbs[username]
	if !ok {
		auth.userDbs[username] = db
		existingDb = db
	}
	auth.mutex.Unlock()

	return existingDb, nil
}

func (auth *Auth) GetUserStore(username string) (*sidb.Store[*ProtoUser], error) {
	db, err := auth.GetUserDatabase(username)

	if err != nil {
		return nil, err
	}

	return sidb.MakeStore(db, "user", serialize, deserializeUser, nil, nil), nil
}

// UserExists checks if a user has actually been created (not just auto-created by GetUserStore)
func (auth *Auth) UserExists(username string) (bool, error) {
	// First check if the database file exists at all (without creating it)
	if !sidb.DatabaseExistsWithRoot(auth.root, []string{auth.namespace, "users"}, username) {
		return false, nil
	}

	// File exists, now check if there's an actual user record
	store, err := auth.GetUserStore(username)
	if err != nil {
		return false, err
	}

	user, err := store.Get(username)
	if err != nil {
		return false, err
	}

	return user != nil, nil
}

func validateUsername(username string) bool {
	// Add your username validation logic here.
	// For example, check length, allowed characters, etc.
	if len(username) < 3 || len(username) > 30 {
		return false
	}

	// only has alphanumeric characters and underscores
	for _, char := range username {
		if !(char >= 'a' && char <= 'z') &&
			!(char >= 'A' && char <= 'Z') &&
			!(char >= '0' && char <= '9') &&
			char != '_' {
			return false
		}
	}

	return true
}

var ErrInvalidUsername = errors.New("invalid username")

func (auth *Auth) CreateUser(params CreateUserParams) error {
	if !validateUsername(params.Username) {
		return ErrInvalidUsername
	}

	store, err := auth.GetUserStore(params.Username)

	if err != nil {
		return err
	}

	existing_user, err := store.Get(params.Username)
	if err != nil {
		return err
	}
	if existing_user != nil {
		return ErrUserExists
	}

	hash, err := auth.HashPassword(params.Password)
	if err != nil {
		return err
	}

	protoUser := ProtoUser{
		Username:     params.Username,
		PasswordHash: hash,
		Name:         params.Name,
		Email:        params.Email,
		Number:       params.Number,
	}

	return store.Upsert(sidb.StoreEntryInput[*ProtoUser]{
		Key:      params.Username,
		Value:    &protoUser,
		Grouping: params.Username,
	})
}

var ErrMissingToken = errors.New("missing token")
var ErrExpiredToken = errors.New("expired token")

func (auth *Auth) ValidateToken(
	authCode string,
) (*Token, error) {
	token, err := auth.tokenStore.Get(authCode)

	if err != nil {
		return nil, err
	}

	if token == nil {
		return nil, ErrMissingToken
	}

	now := time.Now().UnixMilli()
	if now > token.Expiry {
		go auth.tokenStore.Delete(authCode)
		return nil, ErrExpiredToken
	}

	// Always refresh the token on valid use
	token.Expiry = time.Now().Add(24 * time.Hour).UnixMilli()
	err = auth.tokenStore.Upsert(sidb.StoreEntryInput[*Token]{
		Key:      token.Code,
		Value:    token,
		Grouping: token.Username,
	})
	if err != nil {
		// Log error but still return the valid token
		log.Printf("Warning: failed to refresh token: %v", err)
	}

	return token, nil
}

var ErrInvalidToken = errors.New("invalid token")

func (auth *Auth) RevokeToken(
	authCode string,
) error {
	token, err := auth.ValidateToken(authCode)
	if err != nil {
		return err
	}

	if token == nil {
		return ErrInvalidToken
	}

	return auth.tokenStore.Delete(token.Code)
}

func (auth *Auth) RegenerateToken(
	authCode string,
) (*Token, error) {
	token, err := auth.ValidateToken(authCode)

	if err != nil {
		return nil, err
	}

	err = auth.tokenStore.Delete(authCode)

	if err != nil {
		return nil, err
	}

	newToken, err := auth.GenerateToken(token.Username)

	if err != nil {
		return nil, err
	}

	return newToken, nil
}

func (auth *Auth) GenerateAuthCode(username string, clientID string, redirectURI string, codeChallenge *string) (*AuthCode, error) {
	code, err := generateRandomToken()
	if err != nil {
		return nil, err
	}

	authCode := &AuthCode{
		Code:          code,
		ClientId:      clientID,
		Username:      username,
		RedirectUri:   redirectURI,
		CodeChallenge: codeChallenge,
		Expiry:        time.Now().Add(5 * time.Minute).UnixMilli(),
		Used:          false,
	}

	// Upsert into a store keyed like "code:"+code OR use a separate store
	err = auth.codeStore.Upsert(sidb.StoreEntryInput[*AuthCode]{Key: code, Value: authCode})
	if err != nil {
		return nil, err
	}
	return authCode, nil
}

var ErrUserNotFound = errors.New("user not found")
var ErrInvalidCredentials = errors.New("invalid credentials")

func (auth *Auth) ValidatePassword(
	username string,
	password string,
) (bool, error) {
	store, err := auth.GetUserStore(username)

	if err != nil {
		return false, err
	}
	user, err := store.Get(username)

	if err != nil {
		return false, err
	}

	if user == nil {
		return false, ErrUserNotFound
	}

	peppered := auth.applyPepper(password)
	err = bcrypt.CompareHashAndPassword(user.PasswordHash, peppered)

	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, ErrInvalidCredentials
		}
		return false, err
	}

	return true, nil
}

func (auth *Auth) GenerateToken(
	username string,
) (*Token, error) {
	store, err := auth.GetUserStore(username)

	if err != nil {
		return nil, err
	}

	user, err := store.Get(username)

	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	code, err := generateRandomToken()
	if err != nil {
		return nil, err
	}

	duration := 24 * time.Hour

	token := &Token{
		Code:     code,
		Username: username,
		Expiry:   time.Now().Add(duration).UnixMilli(),
	}

	err = auth.tokenStore.Upsert(sidb.StoreEntryInput[*Token]{
		Key:      token.Code,
		Value:    token,
		Grouping: username,
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}

func generateRandomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (auth *Auth) DeleteUser(username string) error {
	// Delete the file
	store, err := auth.GetUserStore(username)

	if err != nil {
		return err
	}

	err = store.DropParentDb()

	if err != nil {
		return err
	}

	auth.tokenStore.DeleteByGrouping(username)

	return err
}

func (auth *Auth) ChangePassword(username, oldPassword, newPassword string) error {
	valid, err := auth.ValidatePassword(username, oldPassword)
	if err != nil {
		return err
	}
	if !valid {
		return ErrInvalidCredentials
	}

	return auth.ResetPassword(username, newPassword)
}

func (auth *Auth) GeneratePasswordResetToken(username string) (*Token, error) {
	store, err := auth.GetUserStore(username)
	if err != nil {
		return nil, err
	}

	// First, check if the user exists.
	user, err := store.Get(username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	code, err := generateRandomToken()
	if err != nil {
		return nil, err
	}

	duration := 15 * time.Minute
	token := &Token{
		Code:     code,
		Username: username,
		Expiry:   time.Now().Add(duration).UnixMilli(),
	}

	resetKey := username + "-reset"
	err = auth.tokenStore.Upsert(sidb.StoreEntryInput[*Token]{
		Key:      resetKey,
		Value:    token,
		Grouping: username,
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (auth *Auth) ResetPasswordWithToken(username, tokenValue, newPassword string) error {
	resetKey := username + "-reset"
	storedToken, err := auth.tokenStore.Get(resetKey)
	if err != nil {
		return err
	}
	if storedToken == nil {
		return ErrMissingToken
	}

	if storedToken.Code != tokenValue {
		return ErrInvalidToken
	}

	if time.Now().UnixMilli() > storedToken.Expiry {
		return ErrExpiredToken
	}

	err = auth.ResetPassword(username, newPassword)
	if err != nil {
		return err
	}

	err = auth.tokenStore.Delete(resetKey)
	if err != nil {
		// Log this error, but don't return it to the user, as the password change was successful.
		log.Printf("Failed to delete password reset token for %s: %v", username, err)
	}
	return nil
}

func (auth *Auth) ResetPassword(username, newPassword string) error {
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}

	store, err := auth.GetUserStore(username)

	if err != nil {
		return err
	}

	// fetch user entry
	protoUser, err := store.Get(username)
	if err != nil {
		return err
	}
	if protoUser == nil {
		return ErrUserNotFound
	}

	protoUser.PasswordHash = hash

	// drop all existing tokens for this user
	go auth.tokenStore.DeleteByGrouping(username)

	return store.Upsert(sidb.StoreEntryInput[*ProtoUser]{
		Key:   username,
		Value: protoUser,
	})
}

func validatePKCE(codeVerifier *string, codeChallenge string) bool {
	// compute S256: base64url(sha256(code_verifier))
	hash := sha256.Sum256([]byte(*codeVerifier))
	computedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// compare in constant time with codeChallenge
	return hmac.Equal([]byte(computedChallenge), []byte(codeChallenge))
}

/////////////////////
// High level APIs //
/////////////////////

func (auth *Auth) Signup(params CreateUserParams) (*Token, error) {
	err := auth.CreateUser(params)

	if err != nil {
		return nil, err
	}

	token, err := auth.GenerateToken(params.Username)

	if err != nil {
		return nil, err
	}

	return token, nil
}

func (auth *Auth) Login(username string, password string) (*Token, error) {
	valid, err := auth.ValidatePassword(username, password)

	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, ErrInvalidCredentials
	}

	token, err := auth.GenerateToken(username)

	if err != nil {
		return nil, err
	}

	return token, nil
}

func (auth *Auth) Logout(username string) error {
	return auth.RevokeToken(username)
}

func (auth *Auth) ChangePasswordAndGenerateToken(
	username string, oldPassword string, newPassword string,
) (*Token, error) {
	valid, err := auth.ValidatePassword(username, oldPassword)

	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, ErrInvalidCredentials
	}

	err = auth.ResetPassword(username, newPassword)

	if err != nil {
		return nil, err
	}

	token, err := auth.GenerateToken(username)

	if err != nil {
		return nil, err
	}

	return token, nil
}

func (auth *Auth) ResetPasswordAndGenerateToken(username string, newPassword string) (*Token, error) {
	err := auth.ResetPassword(username, newPassword)
	if err != nil {
		return nil, err
	}

	token, err := auth.GenerateToken(username)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (auth *Auth) GetTokensByUsername(username string) ([]*Token, error) {
	return auth.tokenStore.Query().
		Grouping(username).
		Exec()
}

func (auth *Auth) ExchangeAuthCode(code string, clientID string, redirectURI string, codeVerifier *string) (*Token, error) {
	// 1. Fetch stored auth code
	authCode, err := auth.codeStore.Get(code)
	if err != nil {
		return nil, err
	}
	if authCode == nil {
		return nil, ErrMissingToken
	}
	if authCode.Used {
		return nil, errors.New("code already used")
	}
	if time.Now().UnixMilli() > authCode.Expiry {
		go auth.codeStore.Delete(code)
		return nil, ErrExpiredToken
	}
	if authCode.ClientId != clientID || authCode.RedirectUri != redirectURI {
		return nil, errors.New("invalid_client_or_redirect")
	}

	// 2. If PKCE used, validate code_verifier -> code_challenge
	if authCode.CodeChallenge != nil {
		if codeVerifier == nil {
			return nil, errors.New("missing PKCE verifier")
		}
		if !validatePKCE(codeVerifier, *authCode.CodeChallenge) {
			return nil, errors.New("invalid_pkce")
		}
	}

	// 3. Mark as used (or delete immediately)
	go auth.codeStore.Delete(code) // single-use

	// 4. Issue tokens
	access, err := auth.GenerateToken(authCode.Username) // adjust to shorter expiry
	if err != nil {
		return nil, err
	}
	return access, nil
}

// LoginWithOIDC performs OIDC login and returns a token
// Creates user on first login (JIT provisioning)
func (auth *Auth) LoginWithOIDC(ctx context.Context, provider *OIDCProvider, code string, codeVerifier *string) (*Token, *OIDCUserInfo, error) {
	// 1. Exchange code for user info
	userInfo, err := provider.ExchangeCode(ctx, code, codeVerifier)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exchange OIDC code: %w", err)
	}

	// Check email verification (security best practice)
	if !userInfo.EmailVerified && userInfo.Email != "" {
		logger.Warn("OIDC login with unverified email", "provider", provider.Name, "email", userInfo.Email)
	}

	// 2. Check if OIDC identity is already mapped
	username, err := auth.oidcUserMappings.GetUsername(provider.Name, userInfo.Sub)
	if err != nil && !errors.Is(err, ErrOIDCMappingNotFound) {
		return nil, nil, err
	}

	// 3. If not mapped, create new user (JIT provisioning)
	if username == "" {
		username = generateUsernameFromEmail(userInfo.Email)

		// Create user without password (OIDC-only account)
		randomPassword := generateRandomPassword()
		err := auth.CreateUser(CreateUserParams{
			Username: username,
			Password: randomPassword,
			Email:    &userInfo.Email,
			Name:     &userInfo.Name,
		})

		// If username collision, try with suffix
		if errors.Is(err, ErrUserExists) {
			for i := 1; i < 100; i++ {
				username = fmt.Sprintf("%s%d", generateUsernameFromEmail(userInfo.Email), i)
				err = auth.CreateUser(CreateUserParams{
					Username: username,
					Password: randomPassword,
					Email:    &userInfo.Email,
					Name:     &userInfo.Name,
				})
				if err == nil {
					break
				}
			}
		}

		if err != nil {
			return nil, nil, fmt.Errorf("failed to create user: %w", err)
		}

		logger.Info("Created user via OIDC JIT provisioning", "provider", provider.Name, "username", username, "email", userInfo.Email)

		// Link OIDC identity to new user
		err = auth.oidcUserMappings.LinkIdentity(provider.Name, userInfo.Sub, username)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to link OIDC identity: %w", err)
		}
	}

	// 4. Generate token
	token, err := auth.GenerateToken(username)
	if err != nil {
		return nil, nil, err
	}

	return token, userInfo, nil
}

// generateUsernameFromEmail extracts username from email and sanitizes it
func generateUsernameFromEmail(email string) string {
	// Extract username from email
	parts := strings.Split(email, "@")
	if len(parts) == 0 {
		return "user_" + generateRandomString(8)
	}

	username := strings.ToLower(parts[0])

	// Replace invalid chars with underscore
	username = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, username)

	// Ensure valid length
	if len(username) < 3 {
		username = username + "_user"
	}
	if len(username) > 20 {
		username = username[:20]
	}

	return username
}

// generateRandomPassword generates a secure random password for OIDC-only accounts
func generateRandomPassword() string {
	bytes := make([]byte, 32)
	secureRandom(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// generateRandomString generates a random alphanumeric string of given length
func generateRandomString(length int) string {
	bytes := make([]byte, length)
	secureRandom(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)[:length]
}

// secureRandom fills the byte slice with cryptographically secure random bytes
func secureRandom(bytes []byte) error {
	_, err := rand.Read(bytes)
	return err
}
