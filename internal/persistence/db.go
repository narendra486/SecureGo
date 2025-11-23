package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// SafeDB wraps sql.DB with context timeouts and prepared statement guidance.
type SafeDB struct {
	DB             DB
	DefaultTimeout time.Duration
}

// DB defines the methods SafeDB needs (satisfied by sql.DB and role wrappers).
type DB interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
}

// Configure sets sensible connection pool defaults.
func Configure(db *sql.DB) {
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetMaxIdleConns(5)
	db.SetMaxOpenConns(20)
}

// Exec issues an ExecContext with deadline guarding.
func (s SafeDB) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return s.DB.ExecContext(withTimeout(ctx, s.DefaultTimeout), query, args...)
}

// Query issues a QueryContext with deadline guarding.
func (s SafeDB) Query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.DB.QueryContext(withTimeout(ctx, s.DefaultTimeout), query, args...)
}

// QueryRow wraps QueryRowContext for parity.
func (s SafeDB) QueryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return s.DB.QueryRowContext(withTimeout(ctx, s.DefaultTimeout), query, args...)
}

// MustPrepared is a helper enforcing prepared statements usage.
func (s SafeDB) MustPrepared(ctx context.Context, query string) (*sql.Stmt, error) {
	stmt, err := s.DB.PrepareContext(withTimeout(ctx, s.DefaultTimeout), query)
	if err != nil {
		return nil, fmt.Errorf("prepare statement: %w", err)
	}
	return stmt, nil
}

func withTimeout(ctx context.Context, d time.Duration) context.Context {
	if d <= 0 {
		return ctx
	}
	c, _ := context.WithTimeout(ctx, d)
	return c
}
