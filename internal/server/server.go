package server

import (
	"crypto/tls"
	"net/http"
	"time"
)

// Config captures the HTTP server knobs with secure defaults.
type Config struct {
	Addr              string
	TLSCertFile       string
	TLSKeyFile        string
	ShutdownGrace     time.Duration
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	EnableH2C         bool // optional; default off
}

// DefaultConfig returns a hardened baseline suitable for public APIs.
func DefaultConfig() Config {
	return Config{
		Addr:              ":8443",
		TLSCertFile:       "",
		TLSKeyFile:        "",
		ShutdownGrace:     10 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// New builds an http.Server with secure timeouts and TLS config when certs are provided.
func New(handler http.Handler, cfg Config) *http.Server {
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		TLSConfig:         tlsConfig(),
	}

	// Strict TLS only when certs are set; otherwise the caller can decide to run plain HTTP inside private networks.
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		srv.TLSConfig = nil
	}

	return srv
}

func tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
	}
}
