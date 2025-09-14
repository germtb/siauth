package siauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"time"

	"github.com/germtb/sidb"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/proto"
)

var USER_TYPE = "user"
var TOKEN_TYPE = "token"

type User struct {
	Id       int64  // autoincrement
	Username string // unique
	Email    *string
	Name     *string
	Number   *string
}

type Auth struct {
	pepper [32]byte
	db     *sidb.Database
}

func Init(
	pepper [32]byte,
	namespace string,
) (*Auth, error) {
	db, err := sidb.Init([]string{namespace}, "users")

	if err != nil {
		return nil, err
	}

	return &Auth{
		pepper: pepper,
		db:     db,
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

func (auth *Auth) CreateUser(params CreateUserParams) error {
	existing_user, err := auth.db.GetByKey(params.Username, USER_TYPE)
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

	encodedProtoUser, err := proto.Marshal(&protoUser)

	if err != nil {
		return err
	}

	_, err = auth.db.Upsert(sidb.EntryInput{
		Key:      params.Username,
		Value:    encodedProtoUser,
		Type:     USER_TYPE,
		Grouping: params.Username,
	})

	return err
}

var ErrMissingToken = errors.New("missing token")
var ErrExpiredToken = errors.New("expired token")

func (auth *Auth) ValidateToken(
	authCode string,
) (*Token, error) {
	entry, err := auth.db.GetByKey(authCode, TOKEN_TYPE)

	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, ErrMissingToken
	}

	var token Token
	err = proto.Unmarshal(entry.Value, &token)

	if err != nil {
		return nil, err
	}

	if time.Now().UnixMilli() > token.Expiry {
		go auth.db.DeleteByKey(authCode, TOKEN_TYPE)
		return nil, ErrExpiredToken
	}

	return &token, nil
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

	serializedToken, err := proto.Marshal(token)

	if err != nil {
		return err
	}

	err = auth.db.Update(sidb.EntryInput{
		Key:      token.Code,
		Value:    serializedToken,
		Type:     TOKEN_TYPE,
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

	return auth.db.DeleteByKey(token.Code, TOKEN_TYPE)
}

func (auth *Auth) RegenerateToken(
	authCode string,
) (*Token, error) {
	token, err := auth.ValidateToken(authCode)

	if err != nil {
		return nil, err
	}

	err = auth.db.DeleteByKey(authCode, TOKEN_TYPE)

	if err != nil {
		return nil, err
	}

	newToken, err := auth.GenerateToken(token.Username)

	if err != nil {
		return nil, err
	}

	return newToken, nil
}

var ErrUserNotFound = errors.New("user not found")
var ErrInvalidCredentials = errors.New("invalid credentials")

func (auth *Auth) ValidatePassword(
	username string,
	password string,
) (bool, error) {
	user, err := auth.db.GetByKey(username, USER_TYPE)

	if err != nil {
		return false, err
	}

	if user == nil {
		return false, ErrUserNotFound
	}

	var protoUser ProtoUser
	err = proto.Unmarshal(user.Value, &protoUser)

	if err != nil {
		return false, err
	}

	peppered := auth.applyPepper(password)
	err = bcrypt.CompareHashAndPassword(protoUser.PasswordHash, peppered)

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
	user, err := auth.db.GetByKey(username, USER_TYPE)

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

	serializedToken, err := proto.Marshal(token)

	if err != nil {
		return nil, err
	}

	_, err = auth.db.Upsert(sidb.EntryInput{
		Key:      token.Code,
		Value:    serializedToken,
		Type:     TOKEN_TYPE,
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
	err := auth.db.DeleteByKey(username, USER_TYPE)
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
	// First, check if the user exists.
	user, err := auth.db.GetByKey(username, USER_TYPE)
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

	serializedToken, err := proto.Marshal(token)
	if err != nil {
		return nil, err
	}

	resetKey := username + "-reset"
	_, err = auth.db.Upsert(sidb.EntryInput{
		Key:      resetKey,
		Value:    serializedToken,
		Type:     TOKEN_TYPE,
		Grouping: username,
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (auth *Auth) ResetPasswordWithToken(username, tokenValue, newPassword string) error {
	resetKey := username + "-reset"
	entry, err := auth.db.GetByKey(resetKey, TOKEN_TYPE)
	if err != nil {
		return err
	}
	if entry == nil {
		return ErrMissingToken
	}

	var storedToken Token
	err = proto.Unmarshal(entry.Value, &storedToken)
	if err != nil {
		return err
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

	err = auth.db.DeleteByKey(resetKey, TOKEN_TYPE)
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

	// fetch user entry
	userEntry, err := auth.db.GetByKey(username, USER_TYPE)
	if err != nil {
		return err
	}
	if userEntry == nil {
		return ErrUserNotFound
	}

	var protoUser ProtoUser
	if err := proto.Unmarshal(userEntry.Value, &protoUser); err != nil {
		return err
	}
	protoUser.PasswordHash = hash

	updated, err := proto.Marshal(&protoUser)
	if err != nil {
		return err
	}

	return auth.db.Update(sidb.EntryInput{
		Key:      username,
		Value:    updated,
		Type:     USER_TYPE,
		Grouping: username,
	})
}

/////////////////////
// High level APIs //
/////////////////////

type Status struct {
	Valid    bool
	Username string
	Expiry   int64
}

func (auth *Auth) Status(authCode string) (*Status, error) {
	token, err := auth.ValidateToken(authCode)

	if err != nil {
		if errors.Is(err, ErrMissingToken) || errors.Is(err, ErrExpiredToken) {
			return &Status{
				Valid:    false,
				Username: "",
				Expiry:   0,
			}, nil
		}
		return nil, err
	}

	return &Status{
		Valid:    true,
		Username: token.Username,
		Expiry:   token.Expiry,
	}, nil

}

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
	entries, err := auth.db.GetByGrouping(username, TOKEN_TYPE)
	if err != nil {
		return nil, err
	}

	tokens := make([]*Token, 0, len(entries))
	for _, entry := range entries {
		var token Token
		err := proto.Unmarshal(entry.Value, &token)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, &token)
	}

	return tokens, nil
}
