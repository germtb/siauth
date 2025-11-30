package siauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/germtb/silogger"
	"google.golang.org/protobuf/proto"
)

var logger = silogger.InitLogger(nil)

var ErrSignUp = errors.New("sign up failed")
var ErrLogIn = errors.New("login failed")
var ErrMissingAuthCookie = errors.New("missing auth cookie")
var ErrChangePassword = errors.New("change password failed")
var ErrResetPassword = errors.New("reset password failed")

type AuthRpcServer struct {
	UnimplementedAuthServer
	Auth *Auth
}

type AuthCookie struct {
	AuthCode string
}

func GetAuthCookie(r *http.Request) (*AuthCookie, error) {
	cookie, err := r.Cookie("token")
	if err != nil {
		return nil, err
	}

	return &AuthCookie{
		AuthCode: cookie.Value,
	}, nil
}

// GetBearerToken extracts the token from Authorization header
// Supports "Bearer <token>" format
func GetBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("missing authorization header")
	}

	// Check for "Bearer " prefix
	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		return "", errors.New("invalid authorization header format")
	}

	return authHeader[len(bearerPrefix):], nil
}

// GetAuthToken extracts token from either Cookie or Authorization header
// Tries Cookie first (for web), then Authorization header (for CLI/API)
func GetAuthToken(r *http.Request) (string, error) {
	// Try cookie first
	cookie, err := GetAuthCookie(r)
	if err == nil && cookie != nil {
		return cookie.AuthCode, nil
	}

	// Fall back to Bearer token
	return GetBearerToken(r)
}

// ValidateAuthToken validates token from either Cookie or Authorization header
func ValidateAuthToken(r *http.Request, auth *Auth) (*Token, error) {
	tokenCode, err := GetAuthToken(r)
	if err != nil {
		return nil, err
	}

	return auth.ValidateToken(tokenCode)
}

func GetUsernameFromAuthToken(r *http.Request, auth *Auth) (string, error) {
	token, err := ValidateAuthToken(r, auth)
	if err != nil {
		return "", err
	} else if token == nil {
		return "", nil
	}

	return token.Username, nil
}

func (server *AuthRpcServer) Status(ctx context.Context, req *StatusParams, authCode string) (*StatusResult, error) {
	token, err := server.Auth.ValidateToken(authCode)

	if err != nil {
		return &StatusResult{IsAuthenticated: false}, err
	} else if token == nil {
		return &StatusResult{IsAuthenticated: false}, nil
	} else {
		logger.Info("Authenticated user: ", token.Username)
		return &StatusResult{IsAuthenticated: true, Username: token.Username}, nil
	}
}

func isValidUsername(username string) bool {
	if len(username) < 3 || len(username) > 20 {
		return false
	}

	for _, char := range username {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '_' {
			return false
		}
	}
	return true
}

func (server *AuthRpcServer) Signup(ctx context.Context, req *SignupParams) (*SignupResult, *Token, error) {
	if !isValidUsername(req.Username) {
		return &SignupResult{Success: false}, nil, ErrInvalidUsername
	}

	token, err := server.Auth.Signup(CreateUserParams{
		Username: req.Username,
		Password: req.Password,
		Email:    req.Email,
		Name:     req.Name,
		Number:   req.Number,
	})

	if err != nil {
		return &SignupResult{Success: false}, nil, err
	}

	return &SignupResult{Success: true, Username: req.Username}, token, nil
}

func (server *AuthRpcServer) Login(ctx context.Context, req *LoginParams) (*LoginResult, *Token, error) {
	token, err := server.Auth.Login(req.Username, req.Password)

	if err != nil {
		return &LoginResult{Success: false}, nil, err
	}

	return &LoginResult{Success: true}, token, nil
}

func (server *AuthRpcServer) Logout(ctx context.Context, req *LogoutParams, authCode string) (*LogoutResult, error) {
	token, err := server.Auth.ValidateToken(authCode)

	if err != nil || token == nil {
		return &LogoutResult{Success: false}, err
	}

	err = server.Auth.Logout(token.Code)

	if err != nil {
		return &LogoutResult{Success: false}, err
	}

	return &LogoutResult{Success: true}, nil
}

func (server *AuthRpcServer) ChangePassword(ctx context.Context, req *ChangePasswordParams) (*ChangePasswordResult, error) {
	err := server.Auth.ChangePassword(req.Username, req.OldPassword, req.NewPassword)

	if err != nil {
		return &ChangePasswordResult{Success: false}, err
	}

	// TODO: Find a way to store the token in HTTP only cookie

	return &ChangePasswordResult{Success: true}, nil
}

func (server *AuthRpcServer) ResetPassword(ctx context.Context, req *ResetPasswordParams) (*ResetPasswordResult, error) {
	err := server.Auth.ResetPassword(req.Username, req.NewPassword)

	if err != nil {
		return &ResetPasswordResult{Success: false}, err
	}

	return &ResetPasswordResult{Success: true}, nil
}

func (s *AuthRpcServer) HandleRpc(w http.ResponseWriter, r *http.Request) {
	onRpc(w, r, func(rpc_method string, body []byte) ([]byte, error) {
		logger.Info("Handling auth RPC method", "method", rpc_method)
		switch rpc_method {
		case "Status":
			var statusParams StatusParams
			if err := proto.Unmarshal(body, &statusParams); err != nil {
				return nil, err
			}
			cookie, err := GetAuthCookie(r)
			if err != nil {
				return nil, err
			} else if cookie == nil {
				return nil, ErrMissingAuthCookie
			}
			result, err := s.Status(r.Context(), &statusParams, cookie.AuthCode)
			if err != nil {
				return nil, err
			}
			return proto.Marshal(result)
		case "Signup":
			var signupParams SignupParams
			if err := proto.Unmarshal(body, &signupParams); err != nil {
				return nil, err
			}
			result, token, err := s.Signup(r.Context(), &signupParams)
			if err != nil {
				return nil, err
			} else if token == nil {
				return nil, ErrSignUp
			}

			http.SetCookie(w, &http.Cookie{
				Name:     "token",
				Value:    token.Code,
				HttpOnly: true,
				MaxAge:   3600 * 24 * 7, // 1 week
				Path:     "/",
				Secure:   true, // required for SameSite=None
				SameSite: http.SameSiteNoneMode,
			})

			return proto.Marshal(result)
		case "Login":
			var loginParams LoginParams
			if err := proto.Unmarshal(body, &loginParams); err != nil {
				return nil, err
			}
			result, token, err := s.Login(r.Context(), &loginParams)
			if err != nil {
				return nil, err
			} else if token == nil {
				return nil, ErrLogIn
			}

			http.SetCookie(w, &http.Cookie{
				Name:     "token",
				Value:    token.Code,
				HttpOnly: true,
				MaxAge:   3600 * 24 * 7, // 1 week
				Path:     "/",
				Secure:   true, // required for SameSite=None
				SameSite: http.SameSiteNoneMode,
			})

			return proto.Marshal(result)
		case "Logout":
			var logoutParams LogoutParams
			if err := proto.Unmarshal(body, &logoutParams); err != nil {
				return nil, err
			}
			cookie, err := GetAuthCookie(r)
			if err != nil {
				return nil, err
			}

			result, err := s.Logout(r.Context(), &logoutParams, cookie.AuthCode)

			if err != nil {
				return nil, err
			}

			if result.Success {
				http.SetCookie(w, &http.Cookie{
					Name:     "token",
					Value:    "",
					HttpOnly: true,
					MaxAge:   -1, // Expire the cookie
					Path:     "/",
					Secure:   true, // required for SameSite=None
					SameSite: http.SameSiteNoneMode,
				})
			}

			return proto.Marshal(result)
		case "ChangePassword":
			var changePasswordParams ChangePasswordParams
			if err := proto.Unmarshal(body, &changePasswordParams); err != nil {
				return nil, err
			}
			result, err := s.ChangePassword(r.Context(), &changePasswordParams)
			if err != nil {
				return nil, err
			} else if result == nil {
				return nil, ErrChangePassword
			}
			return proto.Marshal(result)
		case "ResetPassword":
			var resetPasswordParams ResetPasswordParams
			if err := proto.Unmarshal(body, &resetPasswordParams); err != nil {
				return nil, err
			}
			result, err := s.ResetPassword(r.Context(), &resetPasswordParams)
			if err != nil {
				return nil, err
			} else if result == nil {
				return nil, ErrResetPassword
			}
			return proto.Marshal(result)
		case "RequestAuthCode":
			token, err := ValidateAuthToken(r, s.Auth)

			if err != nil {
				return nil, err
			} else if token == nil {
				return nil, fmt.Errorf("unauthenticated")
			}

			username, err := GetUsernameFromAuthToken(r, s.Auth)

			var requestAuthCodeParams RequestAuthCodeParams
			if err := proto.Unmarshal(body, &requestAuthCodeParams); err != nil {
				return nil, err
			}
			authCode, err := s.Auth.GenerateAuthCode(username, requestAuthCodeParams.ClientId, requestAuthCodeParams.RedirectUri, requestAuthCodeParams.CodeChallenge)
			if err != nil {
				return nil, err
			}
			result := &RequestAuthCodeResult{
				Success:  authCode != nil,
				AuthCode: &authCode.Code,
			}
			return proto.Marshal(result)
		case "ExchangeAuthCode":
			var exchangeAuthCodeParams ExchangeAuthCodeParams
			if err := proto.Unmarshal(body, &exchangeAuthCodeParams); err != nil {
				return nil, err
			}
			token, err := s.Auth.ExchangeAuthCode(exchangeAuthCodeParams.AuthCode, exchangeAuthCodeParams.ClientId, exchangeAuthCodeParams.RedirectUri, exchangeAuthCodeParams.CodeVerifier)
			if err != nil {
				return nil, err
			} else if token == nil {
				return nil, fmt.Errorf("invalid auth code")
			}

			result := &ExchangeAuthCodeResult{
				Success: token != nil,
				Token:   token,
			}
			return proto.Marshal(result)
		default:
			return nil, errors.New("unknown RPC method: " + rpc_method)
		}

	})
}

type RpcHandler func(rpc_method string, body []byte) ([]byte, error)

func onRpc(w http.ResponseWriter, r *http.Request, handler RpcHandler) {
	origin := r.Header.Get("Origin")
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With, X-Rpc-Method")
	w.Header().Set("Content-Type", "application/x-protobuf")

	rpc_method := r.Header.Get("X-Rpc-Method")
	logger.Info("X-Rpc-Method header", "method", rpc_method)

	if r.Method == http.MethodOptions {
		// Respond to preflight request
		w.WriteHeader(http.StatusOK)
		return
	}

	body, bodyErr := io.ReadAll(r.Body)
	if bodyErr != nil {
		logger.Error("Failed to read request body", "error", bodyErr)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	logger.Info("Handling RPC", "method", rpc_method)

	responseBytes, err := handler(rpc_method, body)

	if err != nil {
		logger.Error("Failed to handle response", "error", err)
		http.Error(w, "Failed to handle response", http.StatusInternalServerError)
		return
	}

	if responseBytes == nil {
		logger.Error("Invalid request: responseBytes is nil")
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	logger.Info("Handled RPC", "method", rpc_method)

	w.WriteHeader(http.StatusOK)
	w.Write(responseBytes)
}
