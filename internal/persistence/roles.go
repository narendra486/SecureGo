package persistence

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// Role defines whether a DB handle can perform writes.
type Role int

const (
	ReadOnly Role = iota
	ReadWrite
)

// WithRole returns a SafeDB view that enforces read-only access when requested.
func (s SafeDB) WithRole(role Role) SafeDB {
	base, ok := toSQLDB(s.DB)
	if !ok {
		return s
	}
	return SafeDB{
		DB:             &roleDB{db: base, role: role},
		DefaultTimeout: s.DefaultTimeout,
	}
}

type roleDB struct {
	db   *sql.DB
	role Role
}

func (r *roleDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if r.role == ReadOnly {
		return nil, errors.New("read-only: exec not allowed")
	}
	return r.db.ExecContext(ctx, query, args...)
}

func (r *roleDB) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	if r.role == ReadOnly && isMutating(query) {
		return nil, errors.New("read-only: mutate not allowed")
	}
	return r.db.PrepareContext(ctx, query)
}

func (r *roleDB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if r.role == ReadOnly && isMutating(query) {
		return nil, errors.New("read-only: mutate not allowed")
	}
	return r.db.QueryContext(ctx, query, args...)
}

func (r *roleDB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	if r.role == ReadOnly && isMutating(query) {
		return r.db.QueryRowContext(ctx, "SELECT 1 WHERE 1=0")
	}
	return r.db.QueryRowContext(ctx, query, args...)
}

func isMutating(q string) bool {
	// lightweight check; callers should still use read-only DB accounts in production
	q = strings.TrimSpace(strings.ToUpper(q))
	return strings.HasPrefix(q, "INSERT") || strings.HasPrefix(q, "UPDATE") || strings.HasPrefix(q, "DELETE") || strings.HasPrefix(q, "DROP") || strings.HasPrefix(q, "ALTER")
}

func toSQLDB(db DB) (*sql.DB, bool) {
	switch v := db.(type) {
	case *sql.DB:
		return v, true
	case *roleDB:
		return v.db, true
	default:
		return nil, false
	}
}
