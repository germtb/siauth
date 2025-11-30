package siauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
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
	userDbs    map[string]*sidb.Store[*ProtoUser]
	mutex      sync.Mutex
	tokenStore *sidb.Store[*Token]
	codeStore  *sidb.Store[*AuthCode]
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
) (*Auth, error) {
	tokenDb, err := sidb.Init([]string{namespace}, "tokens")

	if err != nil {
		return nil, err
	}

	return &Auth{
		pepper:     pepper,
		namespace:  namespace,
		userDbs:    map[string]*sidb.Store[*ProtoUser]{},
		tokenStore: sidb.MakeStore(tokenDb, "token", serialize, deserializeToken, nil),
		codeStore:  sidb.MakeStore(tokenDb, "auth_code", serialize, deserializeAuthCode, nil),
		mutex:      sync.Mutex{},
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

func (auth *Auth) GetUserStore(username string) (*sidb.Store[*ProtoUser], error) {
	auth.mutex.Lock()
	store, ok := auth.userDbs[username]
	auth.mutex.Unlock()

	if ok {
		return store, nil
	}

	db, err := sidb.Init([]string{auth.namespace, "users"}, username)

	if err != nil {
		return nil, err
	}

	store = sidb.MakeStore(db, "user", serialize, deserializeUser, nil)

	auth.mutex.Lock()
	existingStore, ok := auth.userDbs[username]
	if !ok {
		auth.userDbs[username] = store
		existingStore = store
	}
	auth.mutex.Unlock()

	return existingStore, nil
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

	if time.Now().UnixMilli() > token.Expiry {
		go auth.tokenStore.Delete(authCode)
		return nil, ErrExpiredToken
	}

	return token, nil
}

var ErrInvalidToken = errors.New("invalid token")

func (auth *Auth) RefreshToken(
	authCode string,
) error {
	token, err := auth.ValidateToken(authCode)
	if err != nil {
		return err
	}

	if token == nil {
		return ErrInvalidToken
	}

	token.Expiry = time.Now().Add(24 * time.Hour).UnixMilli()

	err = auth.tokenStore.Upsert(sidb.StoreEntryInput[*Token]{
		Key:      token.Code,
		Value:    token,
		Grouping: token.Username,
	})

	return err
}

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

func (auth *Auth) GenerateAuthCode(clientID string, redirectURI string, codeChallenge *string) (*AuthCode, error) {
	code, err := generateRandomToken()
	if err != nil {
		return nil, err
	}

	authCode := &AuthCode{
		Code:          code,
		ClientId:      clientID,
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
	return auth.tokenStore.Query(sidb.StoreQueryParams{
		Grouping: &username,
	})
}

func (auth *Auth) RequestAuthCode(clientID string, redirectURI string, codeChallenge *string) (*AuthCode, error) {
	return auth.GenerateAuthCode(clientID, redirectURI, codeChallenge)
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
