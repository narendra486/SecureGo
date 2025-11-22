package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"Securego/internal/auth"
	securecrypto "Securego/internal/crypto"
	"Securego/internal/graphqlapi"
	"Securego/internal/grpcapi"
	"Securego/internal/inputvalidation"
	"Securego/internal/middleware"
	"Securego/internal/server"
	"Securego/internal/telemetry"
	jwt "github.com/golang-jwt/jwt/v5"
)

func main() {
	logger := telemetry.NewLogger()
	cfg := server.DefaultConfig()
	cfg.Addr = getEnv("HTTP_ADDR", cfg.Addr)
	cfg.TLSCertFile = os.Getenv("TLS_CERT_FILE")
	cfg.TLSKeyFile = os.Getenv("TLS_KEY_FILE")

	tokenKey := mustTokenKey(logger)
	tokenTTL := 15 * time.Minute
	tokenizer := auth.SignedToken{Key: tokenKey, TTL: tokenTTL}
	sessionCodec := mustSessionCodec(logger)
	jwtValidator := mustJWTValidator(logger)
	csrf := middleware.NewCSRF(middleware.DefaultCSRFConfig())
	rateLimiter := middleware.NewIPRateLimit(100*time.Millisecond, 10)
	waf := mustWAF(logger)
	validator := inputvalidation.NewValidator()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/api/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token, err := tokenizer.Mint()
		if err != nil {
			logger.Error("mint token failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"token":              token,
			"expires_in_seconds": int(tokenTTL.Seconds()),
		})
	})
	mux.HandleFunc("/api/session/set", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := sessionCodec.Set(w, []byte("user:demo")); err != nil {
			logger.Error("set session failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/session/check", func(w http.ResponseWriter, r *http.Request) {
		val, err := sessionCodec.Parse(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"session": string(val)})
	})
	mux.HandleFunc("/api/jwt/check", func(w http.ResponseWriter, r *http.Request) {
		tokenStr, err := auth.BearerExtractor(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if _, err := jwtValidator.Validate(r.Context(), tokenStr); err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "jwt valid"})
	})
	// Example validated input with authZ hook.
	type profileRequest struct {
		Email string `json:"email" validate:"required,email"`
		Name  string `json:"name" validate:"required,min=2,max=100"`
		Role  string `json:"role" validate:"required,oneof=user admin auditor"`
	}
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req profileRequest
		if err := inputvalidation.DecodeAndValidate(r.Body, &req, validator); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Role != "user" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"email":  req.Email,
			"name":   req.Name,
		})
	})
	// CSRF token issuance for clients (double-submit: cookie + header).
	mux.HandleFunc("/api/csrf", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token, err := csrf.IssueToken(w)
		if err != nil {
			logger.Error("issue csrf failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"csrf_token":"%s"}`, token)
	})

	if gqlHandler, err := graphqlapi.NewHandler(graphqlapi.DefaultConfig()); err == nil {
		mux.Handle("/graphql", gqlHandler)
	} else {
		logger.Error("graphql init failed", "err", err)
	}

	var wrapped http.Handler = mux
	wrapped = csrf.EnsureCSRF(csrf.Middleware(wrapped))
	if waf != nil {
		wrapped = waf.Middleware(wrapped)
	}
	wrapped = rateLimiter.Middleware(wrapped)
	wrapped = middleware.BodyLimit(1 << 20)(wrapped)
	wrapped = middleware.Recovery(wrapped)
	wrapped = middleware.RequestID(wrapped)
	wrapped = middleware.SecurityHeaders(wrapped)
	handler := wrapped

	srv := server.New(handler, cfg)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("http server starting", "addr", cfg.Addr)
		var err error
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			err = srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Error("http server error", "err", err)
		}
	}()

	startGRPC(logger)

	<-ctx.Done()
	stop()
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
	}
}

func getEnv(key, def string) string {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	return val
}

func mustTokenKey(logger telemetry.Logger) []byte {
	key := os.Getenv("TOKEN_KEY")
	if key != "" {
		return []byte(key)
	}
	random, err := securecrypto.RandomBytes(32)
	if err != nil {
		logger.Error("generate random key failed", "err", err)
		os.Exit(1)
	}
	logger.Info("TOKEN_KEY not provided; using ephemeral random key")
	return random
}

func mustSessionCodec(logger telemetry.Logger) *auth.SessionCodec {
	key := os.Getenv("SESSION_KEY")
	if key == "" || len(key) < 32 {
		randKey, err := securecrypto.RandomBytes(32)
		if err != nil {
			logger.Error("generate session key failed", "err", err)
			os.Exit(1)
		}
		key = string(randKey)
		logger.Info("SESSION_KEY not provided; using ephemeral random key")
	}
	codec, err := auth.NewSessionCodec("sid", []byte(key)[:32])
	if err != nil {
		logger.Error("init session codec failed", "err", err)
		os.Exit(1)
	}
	return codec
}

func mustJWTValidator(logger telemetry.Logger) auth.JWTValidator {
	// Prefer Ed25519 if provided; fall back to RSA.
	edPath := os.Getenv("JWT_ED_PUBLIC_KEY")
	rsPath := os.Getenv("JWT_RS_PUBLIC_KEY")
	var keyFunc jwt.Keyfunc
	var alg string
	if edPath != "" {
		pubBytes, err := os.ReadFile(edPath)
		if err != nil {
			logger.Error("read jwt ed25519 pubkey failed", "err", err)
			os.Exit(1)
		}
		edPub, err := auth.ParseEd25519PublicKeyFromPEM(pubBytes)
		if err != nil {
			logger.Error("parse jwt ed25519 pubkey failed", "err", err)
			os.Exit(1)
		}
		keyFunc = auth.StaticKeyFunc(edPub)
		alg = "EdDSA"
	} else {
		if rsPath == "" {
			logger.Error("JWT_RS_PUBLIC_KEY not provided; JWT validation disabled")
			os.Exit(1)
		}
		pubBytes, err := os.ReadFile(rsPath)
		if err != nil {
			logger.Error("read jwt rsa pubkey failed", "err", err)
			os.Exit(1)
		}
		pubKey, err := auth.ParseRSAPublicKeyFromPEM(pubBytes)
		if err != nil {
			logger.Error("parse jwt rsa pubkey failed", "err", err)
			os.Exit(1)
		}
		algEnv := os.Getenv("JWT_RS_ALG")
		if algEnv == "" {
			algEnv = "RS256"
		}
		if algEnv != "RS256" && algEnv != "RS512" {
			logger.Error("unsupported JWT_RS_ALG (only RS256 or RS512)")
			os.Exit(1)
		}
		keyFunc = auth.StaticKeyFunc(pubKey)
		alg = algEnv
	}
	return auth.JWTValidator{
		Issuer:     "securego",
		Audiences:  []string{"securego-api"},
		Algorithms: []string{alg},
		KeyFunc:    keyFunc,
		ClockSkew:  30 * time.Second,
	}
}

func mustWAF(logger telemetry.Logger) *middleware.WAF {
	directives := os.Getenv("CORAZA_DIRECTIVES")
	if directives == "" {
		return nil
	}
	w, err := middleware.NewWAF(directives)
	if err != nil {
		logger.Error("init WAF failed", "err", err)
		os.Exit(1)
	}
	return w
}

func startGRPC(logger telemetry.Logger) {
	addr := getEnv("GRPC_ADDR", ":50051")
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("grpc listener failed", "err", err)
		return
	}
	cfg := grpcapi.DefaultConfig()
	cfg.AllowJSON = true
	s := grpcapi.NewServer(logger, cfg)
	go func() {
		logger.Info("grpc server starting", "addr", addr)
		if err := s.Serve(lis); err != nil {
			logger.Error("grpc server error", "err", err)
		}
	}()
}
