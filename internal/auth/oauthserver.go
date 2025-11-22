package auth

import (
	"context"
	"net/http"
	"time"

	oauth2 "github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
)

// OAuthServer provides a minimal OAuth2 server skeleton with in-memory stores.
type OAuthServer struct {
	Server  *server.Server
	Manage  *manage.Manager
	clients *store.ClientStore
}

// NewInMemoryOAuthServer returns an OAuth2 server with in-memory client/token stores (for dev/staging).
func NewInMemoryOAuthServer() *OAuthServer {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	manager.MustTokenStorage(store.NewMemoryTokenStore())
	cs := store.NewClientStore()
	manager.MapClientStorage(cs)
	srv := server.NewServer(server.NewConfig(), manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		return &errors.Response{Error: err}
	})
	return &OAuthServer{Server: srv, Manage: manager, clients: cs}
}

// AddClient registers an OAuth2 client.
func (o *OAuthServer) AddClient(id, secret, domain string) error {
	return o.clients.Set(id, &models.Client{
		ID:     id,
		Secret: secret,
		Domain: domain,
	})
}

// TokenHandler handles token endpoint.
func (o *OAuthServer) TokenHandler(w http.ResponseWriter, r *http.Request) {
	o.Server.HandleTokenRequest(w, r)
}

// AuthorizeHandler handles authorization endpoint.
func (o *OAuthServer) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	o.Server.HandleAuthorizeRequest(w, r)
}

// IssuePasswordToken issues a password grant token programmatically (for service accounts/testing).
func (o *OAuthServer) IssuePasswordToken(ctx context.Context, clientID, username string) (oauth2.TokenInfo, error) {
	req := &oauth2.TokenGenerateRequest{
		ClientID: clientID,
		UserID:   username,
		Scope:    "all",
		Request:  &http.Request{Method: http.MethodPost},
	}
	return o.Manage.GenerateAccessToken(ctx, oauth2.PasswordCredentials, req)
}

// SetTokenTTL sets access/refresh token durations.
func (o *OAuthServer) SetTokenTTL(access, refresh time.Duration) {
	cfg := manage.Config{
		AccessTokenExp:    access,
		RefreshTokenExp:   refresh,
		IsGenerateRefresh: true,
	}
	o.Manage.SetAuthorizeCodeTokenCfg(&cfg)
}
