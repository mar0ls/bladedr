package api

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"bladedr/internal/auth"
	"bladedr/internal/store"
)

// clientIP extracts the caller's IP (honouring X-Forwarded-For's first hop).
func clientIP(r *http.Request) string {
	if h := r.Header.Get("X-Forwarded-For"); h != "" {
		return strings.TrimSpace(strings.Split(h, ",")[0])
	}
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}

// audit records a security event attributed to the request's authenticated user.
func (a *API) audit(r *http.Request, action, target, result, detail string) {
	actor := ""
	if u := currentUser(r); u != nil {
		actor = u.Username
	}
	a.auditAs(r, actor, action, target, result, detail)
}

// auditAs records a security event with an explicit actor (e.g. a failed login,
// where there is no authenticated user yet).
func (a *API) auditAs(r *http.Request, actor, action, target, result, detail string) {
	_ = a.Store.AppendAudit(r.Context(), &store.AuditEvent{
		Actor: actor, ActorIP: clientIP(r), Action: action, Target: target, Result: result, Detail: detail,
	})
}

const sessionCookie = "bladedr_session"
const sessionTTL = 12 * time.Hour

// sessionCookieValue builds the session cookie. Secure is set when SecureCookies is
// enabled (behind TLS) — required there so the cookie is never sent over plain HTTP;
// it is off by default so login still works on a plain-HTTP trusted-LAN deployment.
// SameSite=Lax already blocks the cookie on cross-site POSTs (CSRF protection).
func (a *API) sessionCookieValue(tok string, exp time.Time) *http.Cookie {
	// Secure is configurable (a.SecureCookies / BLADEDR_SECURE_COOKIES) — enabled
	// behind TLS, off for a plain-HTTP trusted-LAN deploy. SameSite=Lax + HttpOnly are
	// always set (CSRF + XSS-read protection).
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	c := &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: a.SecureCookies}
	if tok == "" {
		c.MaxAge = -1
	} else {
		c.Expires = exp
	}
	return c
}

type ctxKey int

const userCtxKey ctxKey = 0

// publicPath routes that need no authentication.
func publicPath(p string) bool {
	switch p {
	case "/healthz", "/api/v1/login", "/ui/login", "/ui/logo.png":
		return true
	}
	return false
}

// userFromRequest resolves the session token (UI cookie or API bearer) to a user.
func (a *API) userFromRequest(r *http.Request) *store.User {
	tok := ""
	if c, err := r.Cookie(sessionCookie); err == nil {
		tok = c.Value
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		tok = strings.TrimPrefix(h, "Bearer ")
	}
	if tok == "" {
		return nil
	}
	u, err := a.Store.SessionUser(r.Context(), tok)
	if err != nil {
		return nil
	}
	return u
}

// authMiddleware enforces authentication + RBAC on every non-public route. UI
// routes redirect to the login page when unauthenticated; API routes return 401.
func (a *API) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if publicPath(p) {
			next.ServeHTTP(w, r)
			return
		}
		// Machine-to-machine sensor ingest: a valid ingest bearer token authorizes
		// POST /hosts/{id}/events without a user session.
		if a.IngestToken != "" && r.Method == http.MethodPost &&
			strings.HasPrefix(p, "/api/v1/hosts/") && strings.HasSuffix(p, "/events") &&
			r.Header.Get("Authorization") == "Bearer "+a.IngestToken {
			next.ServeHTTP(w, r)
			return
		}
		isUI := strings.HasPrefix(p, "/ui")
		u := a.userFromRequest(r)
		if u == nil || u.Disabled {
			if isUI {
				http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
			} else {
				writeError(w, http.StatusUnauthorized, "authentication required")
			}
			return
		}
		if !auth.Allowed(u.Role, r.Method, p) {
			a.auditAs(r, u.Username, "access.denied", r.Method+" "+p, "denied", "role="+u.Role)
			writeError(w, http.StatusForbidden, "insufficient role ("+u.Role+")")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userCtxKey, u)))
	})
}

// currentUser returns the authenticated user from the request context (nil if none).
func currentUser(r *http.Request) *store.User {
	if u, ok := r.Context().Value(userCtxKey).(*store.User); ok {
		return u
	}
	return nil
}

// login authenticates a username/password and issues a session (cookie + token).
func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var body struct{ Username, Password string }
	if !decode(w, r, &body) {
		return
	}
	u, err := a.Store.GetUserByName(r.Context(), body.Username)
	if err != nil || u.Disabled || !auth.CheckPassword(u.PasswordHash, body.Password) {
		a.auditAs(r, body.Username, "login", "", "denied", "invalid credentials")
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	tok := auth.NewToken()
	if err := a.Store.CreateSession(r.Context(), &store.Session{Token: tok, UserID: u.ID, ExpiresAt: time.Now().Add(sessionTTL)}); err != nil {
		writeErr(w, err)
		return
	}
	http.SetCookie(w, a.sessionCookieValue(tok, time.Now().Add(sessionTTL)))
	a.auditAs(r, u.Username, "login", "", "ok", "")
	writeJSON(w, http.StatusOK, map[string]string{"token": tok, "username": u.Username, "role": u.Role})
}

// logout revokes the current session.
func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = a.Store.DeleteSession(r.Context(), c.Value)
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		_ = a.Store.DeleteSession(r.Context(), strings.TrimPrefix(h, "Bearer "))
	}
	a.audit(r, "logout", "", "ok", "")
	http.SetCookie(w, a.sessionCookieValue("", time.Time{}))
	w.WriteHeader(http.StatusNoContent)
}

// me returns the authenticated user.
func (a *API) me(w http.ResponseWriter, r *http.Request) {
	if u := currentUser(r); u != nil {
		writeJSON(w, http.StatusOK, u)
		return
	}
	writeError(w, http.StatusUnauthorized, "not authenticated")
}

// --- user management (admin-only, enforced by the middleware) ---

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	us, err := a.Store.ListUsers(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, us)
}

func validRole(role string) bool {
	return role == store.RoleAdmin || role == store.RoleOperator || role == store.RoleViewer
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var body struct{ Username, Password, Role string }
	if !decode(w, r, &body) {
		return
	}
	if body.Username == "" || len(body.Password) < 8 {
		writeError(w, http.StatusBadRequest, "username required and password must be at least 8 chars")
		return
	}
	if !validRole(body.Role) {
		writeError(w, http.StatusBadRequest, "role must be admin, operator or viewer")
		return
	}
	hash, err := auth.HashPassword(body.Password)
	if err != nil {
		writeErr(w, err)
		return
	}
	u := &store.User{Username: body.Username, PasswordHash: hash, Role: body.Role}
	if err := a.Store.CreateUser(r.Context(), u); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	a.audit(r, "user.create", u.Username, "ok", "role="+u.Role)
	writeJSON(w, http.StatusCreated, u)
}

func (a *API) patchUser(w http.ResponseWriter, r *http.Request) {
	u, err := a.Store.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
		Password *string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Role != nil {
		if !validRole(*body.Role) {
			writeError(w, http.StatusBadRequest, "invalid role")
			return
		}
		u.Role = *body.Role
	}
	if body.Disabled != nil {
		u.Disabled = *body.Disabled
	}
	if body.Password != nil {
		if len(*body.Password) < 8 {
			writeError(w, http.StatusBadRequest, "password must be at least 8 chars")
			return
		}
		if h, err := auth.HashPassword(*body.Password); err == nil {
			u.PasswordHash = h
		}
	}
	if err := a.Store.UpdateUser(r.Context(), u); err != nil {
		writeErr(w, err)
		return
	}
	detail := ""
	if body.Role != nil {
		detail = "role=" + *body.Role
	}
	if body.Disabled != nil {
		detail = strings.TrimSpace(detail + " disabled=" + map[bool]string{true: "true", false: "false"}[*body.Disabled])
	}
	if body.Password != nil {
		detail = strings.TrimSpace(detail + " password-reset")
	}
	a.audit(r, "user.update", u.Username, "ok", detail)
	writeJSON(w, http.StatusOK, u)
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if cu := currentUser(r); cu != nil && cu.ID == id {
		writeError(w, http.StatusBadRequest, "cannot delete your own account")
		return
	}
	target := id
	if u, err := a.Store.GetUser(r.Context(), id); err == nil {
		target = u.Username
	}
	if err := a.Store.DeleteUser(r.Context(), id); err != nil {
		writeErr(w, err)
		return
	}
	a.audit(r, "user.delete", target, "ok", "")
	w.WriteHeader(http.StatusNoContent)
}
