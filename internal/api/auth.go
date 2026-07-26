package api

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"bladedr/internal/auth"
	"bladedr/internal/store"
)

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
}

func remoteIP(r *http.Request) net.IP {
	host := r.RemoteAddr
	if ip, _, err := net.SplitHostPort(host); err == nil {
		host = ip
	}
	return net.ParseIP(strings.TrimSpace(host))
}

// clientIP only honours forwarding headers when the direct peer belongs to an
// explicitly trusted proxy network. With the default empty list, spoofed
// X-Forwarded-For values never affect throttling or audit attribution.
func (a *API) clientIP(r *http.Request) string {
	peer := remoteIP(r)
	trusted := false
	for _, network := range a.TrustedProxies {
		if peer != nil && network.Contains(peer) {
			trusted = true
			break
		}
	}
	if trusted {
		if first := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); net.ParseIP(first) != nil {
			return first
		}
	}
	if peer != nil {
		return peer.String()
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
		Actor: actor, ActorIP: a.clientIP(r), Action: action, Target: target, Result: result, Detail: detail,
	})
}

const sessionCookie = "bladedr_session"
const sessionTTL = 12 * time.Hour

// sessionCookieValue creates or expires the authentication cookie.
func (a *API) sessionCookieValue(tok string, exp time.Time) *http.Cookie {
	// Secure is configured from TLS state or BLADEDR_SECURE_COOKIES. SameSite and
	// HttpOnly apply to every deployment.
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
	case "/healthz", "/readyz", "/metrics", "/openapi.yaml", "/api/v1/login", "/ui/login", "/ui/logo.png":
		return true
	}
	return false
}

// passwordChangePath is the allowlist for an account under a forced password change.
// Deliberately tiny: the change itself, the form that submits it, /me so a client can
// see why it is being refused, and logout so the account can always walk away instead of
// being trapped in a loop.
func passwordChangePath(p string) bool {
	switch p {
	case "/api/v1/me/password", "/ui/password", "/api/v1/me", "/api/v1/logout":
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
	if bearer := bearerToken(r); bearer != "" {
		tok = bearer
	}
	if tok == "" {
		return nil
	}
	u, err := a.Store.SessionUser(r.Context(), auth.TokenDigest(tok))
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
		// Machine-to-machine sensor ingest: the credential is bound to the host id in
		// the URL. A sensor credential can never impersonate another host.
		if r.Method == http.MethodPost && strings.HasPrefix(p, "/api/v1/hosts/") &&
			strings.HasSuffix(p, "/events") {
			hostID := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v1/hosts/"), "/events")
			bearer := bearerToken(r)
			if bearer != "" {
				ok, err := a.Store.SensorTokenValid(r.Context(), hostID, auth.TokenDigest(bearer))
				if err != nil {
					writeError(w, http.StatusServiceUnavailable, "sensor authentication unavailable")
					return
				}
				if ok {
					next.ServeHTTP(w, r)
					return
				}
			}
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
		// A password someone else has seen buys exactly one thing: the chance to replace
		// it. Enforced here rather than per-handler so a route added later is covered by
		// default — the failure mode of forgetting is then a locked-out account, not an
		// open one.
		if u.MustChangePassword && !passwordChangePath(p) {
			if isUI {
				http.Redirect(w, r, "/ui/password", http.StatusSeeOther)
			} else {
				writeError(w, http.StatusForbidden,
					"password change required: POST /api/v1/me/password before using the API")
			}
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
	ip := a.clientIP(r)
	if a.loginLimiter != nil {
		if wait := a.loginLimiter.retryAfter(ip, time.Now()); wait > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			a.auditAs(r, "", "login", "", "throttled", "too many failed attempts from "+ip)
			writeError(w, http.StatusTooManyRequests, "too many attempts, try again later")
			return
		}
	}
	var body struct{ Username, Password, OTP string }
	if !decode(w, r, &body) {
		return
	}
	// An unknown or disabled account must cost the same as a wrong password, so the
	// no-user branch still performs a bcrypt comparison. Short-circuiting here would
	// let an unauthenticated caller enumerate valid usernames by response latency.
	u, err := a.Store.GetUserByName(r.Context(), body.Username)
	ok := err == nil && !u.Disabled && auth.CheckPassword(u.PasswordHash, body.Password)
	if err != nil || u.Disabled {
		ok = auth.DummyCheckPassword(body.Password)
	}
	if !ok {
		if a.loginLimiter != nil {
			a.loginLimiter.fail(ip, time.Now())
		}
		a.auditAs(r, body.Username, "login", "", "denied", "invalid credentials")
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if u.MFAEnabled {
		if a.Crypto == nil || !a.Crypto.CanOpen() {
			writeError(w, http.StatusServiceUnavailable, "MFA key unavailable")
			return
		}
		secret, openErr := a.Crypto.Open(u.MFASecretEnc)
		if openErr != nil || !auth.VerifyTOTP(string(secret), body.OTP, time.Now()) {
			if a.loginLimiter != nil {
				a.loginLimiter.fail(ip, time.Now())
			}
			a.auditAs(r, body.Username, "login", "", "denied", "invalid MFA code")
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "valid MFA code required", "mfa_required": true})
			return
		}
	}
	if a.loginLimiter != nil {
		a.loginLimiter.reset(ip)
	}
	tok := auth.NewToken()
	if err := a.Store.CreateSession(r.Context(), &store.Session{TokenHash: auth.TokenDigest(tok), UserID: u.ID, ExpiresAt: time.Now().Add(sessionTTL)}); err != nil {
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
		_ = a.Store.DeleteSession(r.Context(), auth.TokenDigest(c.Value))
	}
	if tok := bearerToken(r); tok != "" {
		_ = a.Store.DeleteSession(r.Context(), auth.TokenDigest(tok))
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

func (a *API) setupMFA(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if a.Crypto == nil {
		writeError(w, http.StatusServiceUnavailable, "secret encryption unavailable")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if !auth.CheckPassword(u.PasswordHash, body.Password) {
		writeError(w, http.StatusUnauthorized, "password confirmation failed")
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		writeErr(w, err)
		return
	}
	sealed, err := a.Crypto.Seal([]byte(secret))
	if err != nil {
		writeErr(w, err)
		return
	}
	u.MFASecretEnc, u.MFAEnabled = sealed, false
	if err := a.Store.UpdateUser(r.Context(), u); err != nil {
		writeErr(w, err)
		return
	}
	label := url.QueryEscape("bladedr:" + u.Username)
	uri := "otpauth://totp/" + label + "?secret=" + url.QueryEscape(secret) + "&issuer=bladedr&algorithm=SHA1&digits=6&period=30"
	a.audit(r, "mfa.setup", u.Username, "ok", "pending confirmation")
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_uri": uri})
}

func (a *API) confirmMFA(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u == nil || len(u.MFASecretEnc) == 0 {
		writeError(w, http.StatusBadRequest, "MFA setup has not been started")
		return
	}
	if a.Crypto == nil || !a.Crypto.CanOpen() {
		writeError(w, http.StatusServiceUnavailable, "MFA key unavailable")
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &body) {
		return
	}
	secret, err := a.Crypto.Open(u.MFASecretEnc)
	if err != nil || !auth.VerifyTOTP(string(secret), body.Code, time.Now()) {
		writeError(w, http.StatusBadRequest, "invalid MFA code")
		return
	}
	u.MFAEnabled = true
	if err := a.Store.UpdateUser(r.Context(), u); err != nil {
		writeErr(w, err)
		return
	}
	a.audit(r, "mfa.enable", u.Username, "ok", "")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) disableMFA(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u == nil || !u.MFAEnabled {
		writeError(w, http.StatusBadRequest, "MFA is not enabled")
		return
	}
	if a.Crypto == nil || !a.Crypto.CanOpen() {
		writeError(w, http.StatusServiceUnavailable, "MFA key unavailable")
		return
	}
	var body struct{ Password, Code string }
	if !decode(w, r, &body) {
		return
	}
	secret, err := a.Crypto.Open(u.MFASecretEnc)
	if !auth.CheckPassword(u.PasswordHash, body.Password) || err != nil || !auth.VerifyTOTP(string(secret), body.Code, time.Now()) {
		writeError(w, http.StatusUnauthorized, "password and valid MFA code required")
		return
	}
	u.MFASecretEnc, u.MFAEnabled = nil, false
	if err := a.Store.UpdateUser(r.Context(), u); err != nil {
		writeErr(w, err)
		return
	}
	a.audit(r, "mfa.disable", u.Username, "ok", "")
	w.WriteHeader(http.StatusNoContent)
}

// minPasswordLen matches what createUser and patchUser already enforce. Keeping the
// self-service path on the same floor avoids a route that quietly accepts weaker
// passwords than the admin one.
const minPasswordLen = 8

// changeOwnPassword is the only route a must-change account can reach. It takes the
// current password as well as the new one: the session may have been resumed from a
// machine the account holder walked away from, and a forced change exists precisely
// because the current password is known to more people than it should be.
func (a *API) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if !auth.CheckPassword(u.PasswordHash, body.CurrentPassword) {
		a.audit(r, "password.change", u.Username, "denied", "current password incorrect")
		writeError(w, http.StatusUnauthorized, "current password incorrect")
		return
	}
	if len(body.NewPassword) < minPasswordLen {
		writeError(w, http.StatusBadRequest,
			"new password must be at least "+strconv.Itoa(minPasswordLen)+" chars")
		return
	}
	if body.NewPassword == body.CurrentPassword {
		writeError(w, http.StatusBadRequest, "new password must differ from the current one")
		return
	}
	hash, err := auth.HashPassword(body.NewPassword)
	if err != nil {
		writeErr(w, err)
		return
	}
	u.PasswordHash, u.MustChangePassword = hash, false
	if err := a.Store.UpdateUser(r.Context(), u); err != nil {
		writeErr(w, err)
		return
	}
	a.audit(r, "password.change", u.Username, "ok", "")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listSensorTokens(w http.ResponseWriter, r *http.Request) {
	if _, err := a.Store.GetHost(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	tokens, err := a.Store.ListSensorTokens(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (a *API) createSensorToken(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	if _, err := a.Store.GetHost(r.Context(), hostID); err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		TTL string `json:"ttl"`
	}
	if r.ContentLength != 0 && !decode(w, r, &body) {
		return
	}
	expires := time.Now().UTC().Add(90 * 24 * time.Hour)
	if body.TTL != "" {
		d, err := time.ParseDuration(body.TTL)
		if err != nil || d < time.Hour || d > 366*24*time.Hour {
			writeError(w, http.StatusBadRequest, "ttl must be between 1h and 8760h")
			return
		}
		expires = time.Now().UTC().Add(d)
	}
	raw := auth.NewToken()
	t := &store.SensorToken{HostID: hostID, TokenHash: auth.TokenDigest(raw), ExpiresAt: &expires}
	if err := a.Store.CreateSensorToken(r.Context(), t); err != nil {
		writeErr(w, err)
		return
	}
	a.audit(r, "sensor.token.create", hostID, "ok", "token_id="+t.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"id": t.ID, "host_id": hostID, "token": raw, "expires_at": expires})
}

func (a *API) revokeSensorToken(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.RevokeSensorToken(r.Context(), r.PathValue("id"), r.PathValue("token")); err != nil {
		writeErr(w, err)
		return
	}
	a.audit(r, "sensor.token.revoke", r.PathValue("id"), "ok", "token_id="+r.PathValue("token"))
	w.WriteHeader(http.StatusNoContent)
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
	// The admin creating the account picked this password, so they know it. It gets the
	// new user in and nothing more.
	u := &store.User{Username: body.Username, PasswordHash: hash, Role: body.Role, MustChangePassword: true}
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
		h, err := auth.HashPassword(*body.Password)
		if err != nil {
			writeErr(w, err)
			return
		}
		// An admin reset means two people know this password. It is a way back in for a
		// locked-out user, not a password they get to keep.
		u.PasswordHash, u.MustChangePassword = h, true
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
