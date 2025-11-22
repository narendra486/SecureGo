package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// OAuth2Client wraps oauth2.Config with sane defaults and token validation.
type OAuth2Client struct {
	Config     *oauth2.Config
	HTTPClient *http.Client
	Timeout    time.Duration
}

// ExchangeCode exchanges authorization code for token with deadline.
func (c OAuth2Client) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	if c.Config == nil {
		return nil, errors.New("oauth2 config missing")
	}
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	tkn, err := c.Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}
	if !tkn.Valid() {
		return nil, errors.New("received invalid token")
	}
	return tkn, nil
}

// TokenSource returns a context-aware token source with timeout.
func (c OAuth2Client) TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource {
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	return oauth2.ReuseTokenSourceWithExpiry(t, oauth2.StaticTokenSource(t), time.Minute)
}
