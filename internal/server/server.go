package server

import (
	"crypto/tls"
	"net/http"
	"time"

	"golang.org/x/net/http2"
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
	EnableH2          bool
	H2MaxConcurrent   uint32
	H2ReadIdle        time.Duration
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
		EnableH2:          true,
		H2MaxConcurrent:   128,
		H2ReadIdle:        30 * time.Second,
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
		// Optionally allow H2C with explicit flag (off by default).
		if cfg.EnableH2C {
			http2.ConfigureServer(srv, &http2.Server{
				MaxConcurrentStreams: cfg.H2MaxConcurrent,
				ReadIdleTimeout:      cfg.H2ReadIdle,
			})
		}
	}

	// Configure HTTP/2 with limits to reduce DoS risk.
	if cfg.EnableH2 && srv.TLSConfig != nil {
		http2.ConfigureServer(srv, &http2.Server{
			MaxConcurrentStreams: cfg.H2MaxConcurrent,
			ReadIdleTimeout:      cfg.H2ReadIdle,
		})
	}

	return srv
}

func tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:               tls.VersionTLS13,
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
	}
}
