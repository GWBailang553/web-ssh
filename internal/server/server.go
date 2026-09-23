package server

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/GWBailang553/web-ssh/internal/auth"
	"github.com/GWBailang553/web-ssh/internal/config"
	"github.com/GWBailang553/web-ssh/internal/store"
	"github.com/GWBailang553/web-ssh/internal/terminal"
)

//go:embed assets/*
var assets embed.FS

const (
	sessionCookieName = "web_ssh_session"
	maxBodyBytes      = 64 * 1024
	maxLoginAttempts  = 5
	lockDuration      = 15 * time.Minute
)

type Server struct {
	config    config.Config
	store     *store.Store
	terminals *terminal.Manager
	logger    *slog.Logger
	upgrader  websocket.Upgrader
	limiter   *loginLimiter
	adminMu   sync.Mutex
}

type contextKey string

const (
	sessionContextKey contextKey = "session"
	userContextKey    contextKey = "user"
)

type apiError struct {
	Error string `json:"error"`
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func New(config config.Config, database *store.Store, logger *slog.Logger) *Server {
	return &Server{
		config:    config,
		store:     database,
		terminals: terminal.NewManager(terminal.Limits{MaxPerUser: config.MaxTerminals, Shell: config.Shell}),
		logger:    logger,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin:     func(*http.Request) bool { return true },
		},
		limiter: newLoginLimiter(20, 5*time.Minute),
	}
}

func (s *Server) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("POST /api/bootstrap", s.handleBootstrap)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.requireAuth(s.handleLogout))
	mux.HandleFunc("POST /api/register", s.handleRegister)
	mux.HandleFunc("POST /api/password-reset", s.handlePasswordReset)
	mux.HandleFunc("GET /api/me", s.requireAuth(s.handleMe))
	mux.HandleFunc("GET /ws/terminal", s.handleTerminal)
	mux.HandleFunc("GET /api/admin/invites", s.requireAdmin(s.handleListInvites))
	mux.HandleFunc("POST /api/admin/invites", s.requireAdmin(s.handleCreateInvite))
	mux.HandleFunc("DELETE /api/admin/invites/{id}", s.requireAdmin(s.handleDeleteInvite))
	mux.HandleFunc("PATCH /api/admin/users/{id}", s.requireAdmin(s.handleUpdateUser))
	mux.HandleFunc("POST /api/admin/users/{id}/reset", s.requireAdmin(s.handleResetUser))
	mux.HandleFunc("POST /api/admin/users/{id}/revoke", s.requireAdmin(s.handleRevokeUser))
	mux.HandleFunc("GET /api/admin/users", s.requireAdmin(s.handleListUsers))
	mux.HandleFunc("GET /api/admin/audit", s.requireAdmin(s.handleAudit))
	mux.HandleFunc("GET /assets/", s.handleAssets)
	mux.HandleFunc("GET /", s.handleIndex)
	return s.securityHeaders(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	hasUsers, err := s.store.HasUsers()
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"bootstrap": !hasUsers})
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if !s.checkOrigin(w, r) {
		return
	}
	clientIP := requestIP(r)
	if !s.limiter.Allow(clientIP, 10) {
		writeJSON(w, http.StatusTooManyRequests, apiError{"too many attempts; try again later"})
		return
	}
	var input credentials
	if !decodeJSON(w, r, &input) {
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	if err := validateUsername(input.Username); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{err.Error()})
		return
	}
	if err := auth.ValidatePassword(input.Password, input.Username); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{err.Error()})
		return
	}
	passwordHash, err := auth.HashPassword(input.Password)
	if err != nil {
		s.internalError(w, err)
		return
	}
	user, err := s.store.CreateFirstUser(input.Username, passwordHash, time.Now())
	if errors.Is(err, store.ErrBootstrapDone) {
		writeJSON(w, http.StatusConflict, apiError{"setup has already been completed"})
		return
	}
	if errors.Is(err, store.ErrAlreadyExists) {
		writeJSON(w, http.StatusConflict, apiError{"username is already in use"})
		return
	}
	if err != nil {
		s.internalError(w, err)
		return
	}
	s.audit(r, "bootstrap_admin", user.ID, user.Username, "initial admin created")
	s.createSession(w, r, user)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.checkOrigin(w, r) {
		return
	}
	if !s.limiter.Allow(requestIP(r), 10) {
		writeJSON(w, http.StatusTooManyRequests, apiError{"too many attempts; try again later"})
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Invite   string `json:"invite"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	input.Invite = strings.TrimSpace(input.Invite)
	if err := validateUsername(input.Username); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{err.Error()})
		return
	}
	if input.Invite == "" {
		writeJSON(w, http.StatusBadRequest, apiError{"invitation code is required"})
		return
	}
	if err := auth.ValidatePassword(input.Password, input.Username); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{err.Error()})
		return
	}
	passwordHash, err := auth.HashPassword(input.Password)
	if err != nil {
		s.internalError(w, err)
		return
	}
	user, err := s.store.CreateInvitedUser(input.Invite, input.Username, passwordHash, time.Now())
	if errors.Is(err, store.ErrInviteInvalid) {
		writeJSON(w, http.StatusBadRequest, apiError{"invitation is invalid or expired"})
		return
	}
	if errors.Is(err, store.ErrAlreadyExists) {
		writeJSON(w, http.StatusConflict, apiError{"username is already in use"})
		return
	}
	if err != nil {
		s.internalError(w, err)
		return
	}
	s.audit(r, "user_registered", user.ID, user.Username, "invitation accepted")
	s.createSession(w, r, user)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.checkOrigin(w, r) {
		return
	}
	clientIP := requestIP(r)
	if !s.limiter.Allow(clientIP, 10) {
		writeJSON(w, http.StatusTooManyRequests, apiError{"too many login attempts; try again later"})
		return
	}
	var input credentials
	if !decodeJSON(w, r, &input) {
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	user, err := s.store.GetUserByUsername(input.Username)
	if err != nil || !user.Enabled || !auth.VerifyPassword(user.PasswordHash, input.Password) {
		s.handleFailedLogin(w, r, user, err, input.Username)
		return
	}
	now := time.Now().UTC()
	if !user.LockedUntil.IsZero() && now.Before(user.LockedUntil) {
		writeJSON(w, http.StatusLocked, apiError{"account is temporarily locked"})
		return
	}
	if err := s.store.ClearLoginFailures(user.ID, now); err != nil {
		s.internalError(w, err)
		return
	}
	s.audit(r, "login_success", user.ID, user.Username, "")
	s.createSession(w, r, user)
}

func (s *Server) handleFailedLogin(w http.ResponseWriter, r *http.Request, user store.User, lookupErr error, attemptedUsername string) {
	if lookupErr == nil && user.ID != "" {
		updated, err := s.store.RecordLoginFailure(user.ID, time.Now(), maxLoginAttempts, lockDuration)
		if err == nil && updated.FailedAttempts >= maxLoginAttempts {
			s.audit(r, "account_locked", user.ID, user.Username, fmt.Sprintf("failed attempts: %d", updated.FailedAttempts))
		}
	}
	s.audit(r, "login_failure", user.ID, attemptedUsername, "")
	writeJSON(w, http.StatusUnauthorized, apiError{"invalid username or password"})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	session := sessionFromContext(r.Context())
	if err := s.store.RevokeSession(session.TokenHash); err != nil {
		s.internalError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	if !s.checkOrigin(w, r) {
		return
	}
	if !s.limiter.Allow(requestIP(r), 10) {
		writeJSON(w, http.StatusTooManyRequests, apiError{"too many attempts; try again later"})
		return
	}
	var input struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if err := auth.ValidatePassword(input.Password, ""); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{err.Error()})
		return
	}
	passwordHash, err := auth.HashPassword(input.Password)
	if err != nil {
		s.internalError(w, err)
		return
	}
	user, err := s.store.ConsumePasswordReset(input.Code, passwordHash, time.Now())
	if errors.Is(err, store.ErrResetInvalid) {
		writeJSON(w, http.StatusBadRequest, apiError{"reset code is invalid or expired"})
		return
	}
	if err != nil {
		s.internalError(w, err)
		return
	}
	if err := s.store.RevokeUserSessions(user.ID); err != nil {
		s.internalError(w, err)
		return
	}
	s.terminals.CloseUser(user.ID)
	s.audit(r, "password_reset", user.ID, user.Username, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	writeJSON(w, http.StatusOK, publicUser(user))
}

func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	var input struct {
		ExpiresInMinutes int `json:"expires_in_minutes"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.ExpiresInMinutes == 0 {
		input.ExpiresInMinutes = 1440
	}
	if input.ExpiresInMinutes < 5 || input.ExpiresInMinutes > 10080 {
		writeJSON(w, http.StatusBadRequest, apiError{"expiry must be between 5 minutes and 7 days"})
		return
	}
	code, err := store.NewToken()
	if err != nil {
		s.internalError(w, err)
		return
	}
	id, err := store.NewID()
	if err != nil {
		s.internalError(w, err)
		return
	}
	actor := userFromContext(r.Context())
	now := time.Now().UTC()
	invite := store.Invite{
		ID:        id,
		CodeHash:  store.HashToken(code),
		CreatedBy: actor.ID,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(input.ExpiresInMinutes) * time.Minute),
	}
	if err := s.store.CreateInvite(invite); err != nil {
		s.internalError(w, err)
		return
	}
	s.audit(r, "invite_created", actor.ID, actor.Username, "invite "+invite.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"id": invite.ID, "code": code, "expires_at": invite.ExpiresAt})
}

func (s *Server) handleListInvites(w http.ResponseWriter, r *http.Request) {
	invites, err := s.store.ListInvites(time.Now().UTC())
	if err != nil {
		s.internalError(w, err)
		return
	}
	type publicInvite struct {
		ID        string    `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
		UsedAt    time.Time `json:"used_at,omitempty"`
		UsedBy    string    `json:"used_by,omitempty"`
	}
	result := make([]publicInvite, 0, len(invites))
	for _, invite := range invites {
		result = append(result, publicInvite{
			ID:        invite.ID,
			CreatedAt: invite.CreatedAt,
			ExpiresAt: invite.ExpiresAt,
			UsedAt:    invite.UsedAt,
			UsedBy:    invite.UsedBy,
		})
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDeleteInvite(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.store.DeleteInvite(id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, apiError{"invitation not found"})
			return
		}
		s.internalError(w, err)
		return
	}
	actor := userFromContext(r.Context())
	s.audit(r, "invite_deleted", actor.ID, actor.Username, "invite "+id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers()
	if err != nil {
		s.internalError(w, err)
		return
	}
	result := make([]map[string]any, 0, len(users))
	for _, user := range users {
		result = append(result, publicUser(user))
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	var input struct {
		Enabled *bool   `json:"enabled"`
		Role    *string `json:"role"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	actor := userFromContext(r.Context())
	target, err := s.store.GetUserByID(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, apiError{"user not found"})
		return
	}
	if input.Role != nil {
		if *input.Role != "admin" && *input.Role != "user" {
			writeJSON(w, http.StatusBadRequest, apiError{"role must be admin or user"})
			return
		}
		if target.ID == actor.ID && *input.Role != "admin" {
			writeJSON(w, http.StatusBadRequest, apiError{"you cannot demote your own account"})
			return
		}
		if target.Role == "admin" && *input.Role == "user" && s.lastEnabledAdmin(target.ID) {
			writeJSON(w, http.StatusConflict, apiError{"cannot demote the last enabled admin"})
			return
		}
		target.Role = *input.Role
	}
	if input.Enabled != nil {
		if target.ID == actor.ID && !*input.Enabled {
			writeJSON(w, http.StatusBadRequest, apiError{"you cannot disable your own account"})
			return
		}
		if target.Role == "admin" && !*input.Enabled && s.lastEnabledAdmin(target.ID) {
			writeJSON(w, http.StatusConflict, apiError{"cannot disable the last enabled admin"})
			return
		}
		target.Enabled = *input.Enabled
	}
	if err := s.store.UpdateUser(target); err != nil {
		s.internalError(w, err)
		return
	}
	if !target.Enabled {
		if err := s.store.RevokeUserSessions(target.ID); err != nil {
			s.internalError(w, err)
			return
		}
		s.terminals.CloseUser(target.ID)
	}
	s.audit(r, "user_updated", actor.ID, actor.Username, "user "+target.ID)
	writeJSON(w, http.StatusOK, publicUser(target))
}

func (s *Server) lastEnabledAdmin(excludeID string) bool {
	users, err := s.store.ListUsers()
	if err != nil {
		return true
	}
	for _, user := range users {
		if user.ID != excludeID && user.Role == "admin" && user.Enabled {
			return false
		}
	}
	return true
}

func (s *Server) handleResetUser(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	actor := userFromContext(r.Context())
	user, err := s.store.GetUserByID(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, apiError{"user not found"})
		return
	}
	code, err := store.NewToken()
	if err != nil {
		s.internalError(w, err)
		return
	}
	now := time.Now().UTC()
	reset := store.PasswordReset{
		CodeHash:  store.HashToken(code),
		UserID:    user.ID,
		CreatedAt: now,
		ExpiresAt: now.Add(10 * time.Minute),
	}
	if err := s.store.CreatePasswordReset(reset); err != nil {
		s.internalError(w, err)
		return
	}
	s.audit(r, "password_reset_created", actor.ID, actor.Username, "user "+user.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"code": code, "expires_at": reset.ExpiresAt})
}

func (s *Server) handleRevokeUser(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	actor := userFromContext(r.Context())
	if err := s.store.RevokeUserSessions(r.PathValue("id")); err != nil {
		s.internalError(w, err)
		return
	}
	s.terminals.CloseUser(r.PathValue("id"))
	s.audit(r, "sessions_revoked", actor.ID, actor.Username, "user "+r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 1000 {
			writeJSON(w, http.StatusBadRequest, apiError{"limit must be between 1 and 1000"})
			return
		}
		limit = parsed
	}
	events, err := s.store.ListAudit(limit)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleTerminal(w http.ResponseWriter, r *http.Request) {
	if !s.checkOrigin(w, r) {
		writeJSON(w, http.StatusForbidden, apiError{"origin is not allowed"})
		return
	}
	if !isWebSocketUpgrade(r) {
		writeJSON(w, http.StatusUpgradeRequired, apiError{"websocket upgrade required"})
		return
	}
	request, session, user, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	r = request
	cols := parseDimension(r.URL.Query().Get("cols"), 120)
	rows := parseDimension(r.URL.Query().Get("rows"), 32)

	connection, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer connection.Close()
	connection.SetReadLimit(64 * 1024)
	_ = connection.SetReadDeadline(time.Now().Add(60 * time.Second))
	connection.SetPongHandler(func(string) error {
		return connection.SetReadDeadline(time.Now().Add(60 * time.Second))
	})

	ptySession, err := s.terminals.Open(user.ID, cols, rows)
	if err != nil {
		_ = connection.WriteJSON(apiError{err.Error()})
		return
	}
	s.audit(r, "terminal_open", user.ID, user.Username, ptySession.ID())
	defer func() {
		_ = ptySession.Close()
		s.audit(r, "terminal_close", user.ID, user.Username, ptySession.ID())
	}()

	_ = connection.WriteJSON(map[string]string{"type": "ready", "session": ptySession.ID()})
	done := make(chan struct{})
	var closeOnce sync.Once
	closeDone := func() { closeOnce.Do(func() { close(done) }) }

	go s.forwardPTY(connection, ptySession, closeDone)
	go s.forwardInput(connection, ptySession, session, user, closeDone)
	<-done
}

func (s *Server) forwardPTY(connection *websocket.Conn, ptySession *terminal.Session, done func()) {
	defer done()
	buffer := make([]byte, 32*1024)
	for {
		count, err := ptySession.Read(buffer)
		if count > 0 {
			_ = connection.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if writeErr := connection.WriteMessage(websocket.BinaryMessage, buffer[:count]); writeErr != nil {
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.logger.Debug("terminal read ended", "error", err)
			}
			return
		}
	}
}

func (s *Server) forwardInput(connection *websocket.Conn, ptySession *terminal.Session, session store.Session, user store.User, done func()) {
	defer done()
	keepaliveDone := make(chan struct{})
	defer close(keepaliveDone)
	go keepAlive(connection, keepaliveDone)
	for {
		messageType, data, err := connection.ReadMessage()
		if err != nil {
			return
		}
		current, err := s.store.GetUserByID(user.ID)
		if err != nil || !current.Enabled {
			return
		}
		if _, err := s.store.GetSession(session.TokenHash, time.Now(), s.config.SessionIdle); err != nil {
			return
		}

		switch messageType {
		case websocket.BinaryMessage:
			if _, err := ptySession.Write(data); err != nil {
				return
			}
		case websocket.TextMessage:
			var message struct {
				Type string `json:"type"`
				Cols uint16 `json:"cols"`
				Rows uint16 `json:"rows"`
			}
			if json.Unmarshal(data, &message) != nil {
				continue
			}
			if message.Type == "resize" {
				if err := ptySession.Resize(message.Cols, message.Rows); err != nil {
					return
				}
			}
		}
	}
}

func keepAlive(connection *websocket.Conn, done <-chan struct{}) {
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ping.C:
			if err := connection.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
				return
			}
		case <-done:
			return
		}
	}
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request, user store.User) {
	token, err := store.NewToken()
	if err != nil {
		s.internalError(w, err)
		return
	}
	csrfToken, err := store.NewToken()
	if err != nil {
		s.internalError(w, err)
		return
	}
	now := time.Now().UTC()
	session := store.Session{
		TokenHash: store.HashToken(token),
		CSRFToken: csrfToken,
		UserID:    user.ID,
		CreatedAt: now,
		LastSeen:  now,
		ExpiresAt: now.Add(s.config.SessionMax),
		IP:        requestIP(r),
		UserAgent: truncate(r.UserAgent(), 512),
	}
	if err := s.store.CreateSession(session); err != nil {
		s.internalError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int((s.config.SessionIdle + time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"user": publicUser(user), "csrf_token": csrfToken})
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, _, _, ok := s.authenticate(w, r)
		if !ok {
			return
		}
		next(w, request)
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		user := userFromContext(r.Context())
		if user.Role != "admin" {
			writeJSON(w, http.StatusForbidden, apiError{"administrator access required"})
			return
		}
		next(w, r)
	})
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*http.Request, store.Session, store.User, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		writeJSON(w, http.StatusUnauthorized, apiError{"authentication required"})
		return r, store.Session{}, store.User{}, false
	}
	session, err := s.store.GetSession(store.HashToken(cookie.Value), time.Now(), s.config.SessionIdle)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, apiError{"session is invalid or expired"})
		return r, store.Session{}, store.User{}, false
	}
	user, err := s.store.GetUserByID(session.UserID)
	if err != nil || !user.Enabled {
		_ = s.store.RevokeSession(session.TokenHash)
		writeJSON(w, http.StatusUnauthorized, apiError{"account is disabled"})
		return r, store.Session{}, store.User{}, false
	}
	ctx := context.WithValue(r.Context(), sessionContextKey, session)
	ctx = context.WithValue(ctx, userContextKey, user)
	return r.WithContext(ctx), session, user, true
}

func (s *Server) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	session := sessionFromContext(r.Context())
	provided := r.Header.Get("X-CSRF-Token")
	if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(session.CSRFToken)) != 1 {
		writeJSON(w, http.StatusForbidden, apiError{"invalid CSRF token"})
		return false
	}
	return s.checkOrigin(w, r)
}

func (s *Server) checkOrigin(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		writeJSON(w, http.StatusForbidden, apiError{"origin is not allowed"})
		return false
	}
	host := r.Host
	if !sameHost(parsed.Host, host) {
		writeJSON(w, http.StatusForbidden, apiError{"origin is not allowed"})
		return false
	}
	return true
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self' wss: ws:; font-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.serveAsset(w, "assets/index.html", "text/html; charset=utf-8")
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	switch name {
	case "assets/app.js":
		s.serveAsset(w, name, "text/javascript; charset=utf-8")
	case "assets/app.css":
		s.serveAsset(w, name, "text/css; charset=utf-8")
	case "assets/vendor/xterm.js":
		s.serveAsset(w, name, "text/javascript; charset=utf-8")
	case "assets/vendor/xterm.css":
		s.serveAsset(w, name, "text/css; charset=utf-8")
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveAsset(w http.ResponseWriter, name, contentType string) {
	data, err := assets.ReadFile(name)
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(data)
}

func (s *Server) audit(r *http.Request, event, actorID, username, details string) {
	entry := store.AuditEvent{
		Event:     event,
		ActorID:   actorID,
		Username:  username,
		IP:        requestIP(r),
		UserAgent: truncate(r.UserAgent(), 512),
		Details:   truncate(details, 512),
	}
	if err := s.store.AppendAudit(entry); err != nil {
		s.logger.Error("write audit event", "error", err)
	}
}

func (s *Server) internalError(w http.ResponseWriter, err error) {
	s.logger.Error("request failed", "error", err)
	writeJSON(w, http.StatusInternalServerError, apiError{"internal server error"})
}

func publicUser(user store.User) map[string]any {
	return map[string]any{
		"id":         user.ID,
		"username":   user.Username,
		"role":       user.Role,
		"enabled":    user.Enabled,
		"created_at": user.CreatedAt,
	}
}

func validateUsername(username string) error {
	length := len(username)
	if length < 3 || length > 32 {
		return errors.New("username must contain 3 to 32 characters")
	}
	for _, character := range username {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '_' ||
			character == '-' {
			continue
		}
		return errors.New("username may only contain letters, numbers, underscore, and hyphen")
	}
	return nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	if contentType := r.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		writeJSON(w, http.StatusUnsupportedMediaType, apiError{"content type must be application/json"})
		return false
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{"invalid JSON request"})
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, apiError{"request must contain one JSON object"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func requestIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func sameHost(first, second string) bool {
	firstHost, firstPort, err := net.SplitHostPort(first)
	if err != nil {
		firstHost = strings.Trim(first, "[]")
	}
	secondHost, secondPort, err := net.SplitHostPort(second)
	if err != nil {
		secondHost = strings.Trim(second, "[]")
	}
	return strings.EqualFold(firstHost, secondHost) && (firstPort == "" || secondPort == "" || firstPort == secondPort)
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func parseDimension(value string, fallback uint16) uint16 {
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil || parsed < 2 || parsed > 500 {
		return fallback
	}
	return uint16(parsed)
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func sessionFromContext(ctx context.Context) store.Session {
	value, _ := ctx.Value(sessionContextKey).(store.Session)
	return value
}

func userFromContext(ctx context.Context) store.User {
	value, _ := ctx.Value(userContextKey).(store.User)
	return value
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	window   time.Duration
}

func newLoginLimiter(_ int, window time.Duration) *loginLimiter {
	return &loginLimiter{attempts: make(map[string][]time.Time), window: window}
}

func (l *loginLimiter) Allow(key string, maximum int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-l.window)
	existing := l.attempts[key]
	kept := existing[:0]
	for _, timestamp := range existing {
		if timestamp.After(cutoff) {
			kept = append(kept, timestamp)
		}
	}
	if len(kept) >= maximum {
		l.attempts[key] = kept
		return false
	}
	l.attempts[key] = append(kept, now)
	return true
}

func (s *Server) Prune() {
	_ = s.store.PruneAudit(time.Now().Add(-s.config.AuditRetention), s.config.AuditMaxEvents)
}
