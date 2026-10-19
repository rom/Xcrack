package webui

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// This file is the optional multi-user tier. With Config.Auth.Enabled=false the
// authenticator is inert: currentUser returns the implicit local owner, nothing
// is gated, and the console behaves exactly as the single-user build. With it
// enabled, users sign in through an OIDC provider (Authorization Code + PKCE),
// get a server-side cookie session, and each job is owned by its creator.

const (
	sessionCookie = "xcrack_session"
	sessionTTL    = 12 * time.Hour
	stateTTL      = 10 * time.Minute
)

// user is an authenticated principal (or the implicit local owner when auth is
// off). Subject is the stable owner key stored on jobs.
type user struct {
	Subject string `json:"subject"`
	Email   string `json:"email,omitempty"`
	Name    string `json:"name,omitempty"`
	Admin   bool   `json:"admin"`
}

// localUser is the implicit principal when auth is disabled: an admin with an
// empty subject, so jobs created in single-user mode carry no owner and access
// checks are always satisfied.
var localUser = user{Name: "local", Admin: true}

type session struct {
	u       user
	expires time.Time
}

type pkceState struct {
	verifier string
	created  time.Time
}

// authenticator holds the session + OAuth state stores and, when configured, the
// OIDC provider bindings. It is safe for concurrent use.
type authenticator struct {
	enabled      bool
	cookieSecure bool
	admins       map[string]bool

	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier

	mu       sync.Mutex
	sessions map[string]*session
	states   map[string]pkceState
}

// newAuthenticator builds the authenticator. When auth is disabled or no issuer
// is set it returns an inert instance with no provider (login endpoints then
// report "not configured"); otherwise it performs OIDC discovery against the
// issuer, which requires network access at startup.
func newAuthenticator(ctx context.Context, cfg AuthConfig) (*authenticator, error) {
	a := &authenticator{
		enabled: cfg.Enabled, cookieSecure: cfg.CookieSecure,
		admins: map[string]bool{}, sessions: map[string]*session{}, states: map[string]pkceState{},
	}
	for _, s := range cfg.Admins {
		if s = strings.TrimSpace(s); s != "" {
			a.admins[s] = true
		}
	}
	if !cfg.Enabled || cfg.Issuer == "" {
		return a, nil
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc provider %q: %w", cfg.Issuer, err)
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	a.oauth = &oauth2.Config{
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL,
		Endpoint: provider.Endpoint(), Scopes: scopes,
	}
	a.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	return a, nil
}

func (a *authenticator) isAdmin(u user) bool {
	return a.admins[u.Subject] || (u.Email != "" && a.admins[u.Email])
}

func (a *authenticator) newSession(u user) (string, error) {
	id, err := randID()
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	a.sessions[id] = &session{u: u, expires: time.Now().Add(sessionTTL)}
	a.mu.Unlock()
	return id, nil
}

func (a *authenticator) lookup(id string) (user, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[id]
	if s == nil {
		return user{}, false
	}
	if time.Now().After(s.expires) {
		delete(a.sessions, id)
		return user{}, false
	}
	return s.u, true
}

func (a *authenticator) deleteSession(id string) {
	a.mu.Lock()
	delete(a.sessions, id)
	a.mu.Unlock()
}

// putState records a fresh PKCE verifier under a new random state value and
// opportunistically evicts expired states.
func (a *authenticator) putState(verifier string) (string, error) {
	id, err := randID()
	if err != nil {
		return "", err
	}
	now := time.Now()
	a.mu.Lock()
	for k, st := range a.states {
		if now.Sub(st.created) > stateTTL {
			delete(a.states, k)
		}
	}
	a.states[id] = pkceState{verifier: verifier, created: now}
	a.mu.Unlock()
	return id, nil
}

// takeState consumes the verifier for a state value (single use), rejecting
// unknown or expired states.
func (a *authenticator) takeState(id string) (string, bool) {
	if id == "" {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	st, ok := a.states[id]
	if !ok {
		return "", false
	}
	delete(a.states, id)
	if time.Since(st.created) > stateTTL {
		return "", false
	}
	return st.verifier, true
}

func (a *authenticator) setCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/", HttpOnly: true,
		Secure: a.cookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL / time.Second),
	})
}

func (a *authenticator) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: a.cookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// currentUser resolves the principal for a request. With auth off it is always
// the local owner; with auth on it is the session user, or (false) when there is
// no valid session.
func (s *Server) currentUser(r *http.Request) (user, bool) {
	if !s.auth.enabled {
		return localUser, true
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return user{}, false
	}
	u, ok := s.auth.lookup(c.Value)
	if !ok {
		return user{}, false
	}
	u.Admin = u.Admin || s.auth.isAdmin(u)
	return u, true
}

// canAccess reports whether u may see/act on a job with the given owner. Auth
// off, or an admin, sees everything; otherwise only the owner's own jobs.
func (s *Server) canAccess(u user, owner string) bool {
	if !s.auth.enabled || u.Admin {
		return true
	}
	return owner == u.Subject
}

// protected wraps a handler so that, when auth is enabled, it is reachable only
// with a valid session (401 otherwise). It is a no-op when auth is off.
func (s *Server) protected(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.auth.enabled {
			if _, ok := s.currentUser(r); !ok {
				writeErr(w, http.StatusUnauthorized, "authentication required")
				return
			}
		}
		h(w, r)
	}
}

// handleLogin starts the OIDC Authorization Code + PKCE flow.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.auth.oauth == nil {
		writeErr(w, http.StatusServiceUnavailable, "authentication is not configured")
		return
	}
	verifier := oauth2.GenerateVerifier()
	state, err := s.auth.putState(verifier)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start login")
		return
	}
	url := s.auth.oauth.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, url, http.StatusFound)
}

// handleCallback completes the flow: verify state, exchange the code, verify the
// ID token, and establish a cookie session.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if s.auth.oauth == nil {
		writeErr(w, http.StatusServiceUnavailable, "authentication is not configured")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		writeErr(w, http.StatusBadRequest, "login failed: "+e)
		return
	}
	verifier, ok := s.auth.takeState(q.Get("state"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid or expired login state")
		return
	}
	ctx := r.Context()
	tok, err := s.auth.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "token exchange failed")
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		writeErr(w, http.StatusBadRequest, "no id_token in provider response")
		return
	}
	idt, err := s.auth.verifier.Verify(ctx, rawID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "id token verification failed")
		return
	}
	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	_ = idt.Claims(&claims)
	u := user{Subject: claims.Sub, Email: claims.Email, Name: claims.Name}
	if u.Subject == "" {
		u.Subject = idt.Subject
	}
	u.Admin = s.auth.isAdmin(u)
	id, err := s.auth.newSession(u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create session")
		return
	}
	s.auth.setCookie(w, id)
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLogout clears the session and its cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.auth.deleteSession(c.Value)
	}
	s.auth.clearCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

// handleMe reports whether auth is enabled and, if so, whether this request is
// signed in (and as whom). It is always reachable so the SPA can decide between
// the login gate and the app.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{"auth_enabled": s.auth.enabled}
	if !s.auth.enabled {
		resp["authenticated"] = true
		writeJSON(w, http.StatusOK, resp)
		return
	}
	if u, ok := s.currentUser(r); ok {
		resp["authenticated"] = true
		resp["user"] = u
	} else {
		resp["authenticated"] = false
	}
	writeJSON(w, http.StatusOK, resp)
}
