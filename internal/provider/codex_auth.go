package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"
)

// These are AuthAPI's diagnostic reasons, as Codex sends them
// (codex-rs/login/src/oauth/client.rs, RefreshReason). They don't assert
// that a token is valid: the reply from the authority decides that.
type codexRefreshReason string

const (
	codexProactive    codexRefreshReason = "proactive_expiry"
	codexScheduled    codexRefreshReason = "scheduled"
	codexUnauthorized codexRefreshReason = "unauthorized_recovery"
	codexForced       codexRefreshReason = "forced"
)

// Workspace ids can be shared by several people. Recovery is anchored to
// the signed-in person too, preferring Codex's user id, then the JWT subject
// or the email carried by older sign-ins.
type codexIdentity struct {
	user, subject, email string
}

func codexIdentityOf(a codexAuth) codexIdentity {
	id := jwtClaims(a.Tokens.IDToken)
	user := claimString(id, "https://api.openai.com/auth", "chatgpt_user_id")
	if user == "" {
		user = claimString(id, "https://api.openai.com/auth", "user_id")
	}
	return codexIdentity{user: user, subject: claimString(id, "sub"), email: claimString(id, "email")}
}

func (i codexIdentity) matches(a codexAuth, sent string) bool {
	other := codexIdentityOf(a)
	switch {
	case i.user != "":
		return i.user == other.user
	case i.subject != "":
		return i.subject == other.subject
	case i.email != "":
		return strings.EqualFold(i.email, other.email)
	default:
		return a.Tokens.AccessToken == sent // no identity proves a different token is still theirs
	}
}

func savedCodexIdentity(user string) codexIdentity {
	for _, l := range readLogins() {
		if l.Agent == "codex" && strings.EqualFold(l.User, user) {
			var a codexAuth
			if json.Unmarshal(l.Auth, &a) == nil {
				return codexIdentityOf(a)
			}
		}
	}
	return codexIdentity{}
}

func sameCodexCredential(a, b []byte) bool {
	var x, y codexAuth
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && x.AuthMode == y.AuthMode && x.Tokens == y.Tokens
}

// Keep fields another writer changed while the refresh was in flight.
// JSON key order and unrelated metadata aren't a credential change. A
// different credential, however, must never be overwritten by this one.
func codexRotated(latest, before []byte, fresh map[string]any) ([]byte, error) {
	if !sameCodexCredential(latest, before) {
		return nil, errCodexAccountChanged
	}
	var raw map[string]any
	if err := json.Unmarshal(latest, &raw); err != nil {
		return nil, err
	}
	tokens, ok := raw["tokens"].(map[string]any)
	if !ok {
		return nil, errors.New("the Codex sign-in has no tokens")
	}
	rotated, _ := fresh["tokens"].(map[string]any)
	for _, k := range []string{"access_token", "refresh_token", "id_token"} {
		if v, ok := rotated[k]; ok {
			tokens[k] = v
		}
	}
	raw["last_refresh"] = fresh["last_refresh"]
	return json.MarshalIndent(raw, "", "  ")
}

func codexExpired(a codexAuth) bool {
	exp, known := codexExpiry(a.Tokens.AccessToken)
	return known && !exp.After(time.Now())
}

// codexExpiry is the token's JWT expiry, when it has a valid one. An
// opaque token or a malformed claim says nothing about its lifetime.
func codexExpiry(token string) (time.Time, bool) {
	exp, ok := jwtClaims(token)["exp"].(float64)
	if !ok || exp < math.MinInt64 || exp >= math.MaxInt64 || math.Trunc(exp) != exp {
		return time.Time{}, false
	}
	return time.Unix(int64(exp), 0), true
}

// codexRefreshDue follows Codex's proactive_refresh_reason: expiry takes
// precedence over last_refresh; without an expiry, a known refresh more
// than eight days ago is due. Unknown dates aren't an expired sign-in.
func codexRefreshDue(a codexAuth, now time.Time) codexRefreshReason {
	if exp, ok := codexExpiry(a.Tokens.AccessToken); ok {
		if !exp.After(now.Add(5 * time.Minute)) {
			return codexProactive
		}
		return ""
	}
	var last time.Time
	if json.Unmarshal(a.LastRefresh, &last) == nil && !last.IsZero() && last.Before(now.Add(-8*24*time.Hour)) {
		return codexScheduled
	}
	return ""
}

// A proactive renewal that never reached the authority, or was answered
// with a temporary failure, doesn't spend an access token's remaining
// lifetime. A forced renewal, a revoked sign-in, an expired/unknown token
// or a caller already gone must still report the failure.
func codexStillUsable(ctx context.Context, a codexAuth, reason codexRefreshReason, err error) bool {
	var refused refreshRefused
	exp, known := codexExpiry(a.Tokens.AccessToken)
	return reason == codexProactive && ctx.Err() == nil && !errors.As(err, &refused) && known && exp.After(time.Now())
}

// Codex distinguishes a dead refresh token from another 400. Keep this
// separate from other vendors' refreshFailed rules, and never put the
// server's body (which can contain credentials) in the returned error.
func codexRefreshFailed(status int, body []byte) error {
	var detail struct {
		Error json.RawMessage `json:"error"`
		Code  string          `json:"code"`
	}
	var code string
	if json.Unmarshal(body, &detail) == nil && json.Unmarshal(detail.Error, &code) != nil {
		var nested struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(detail.Error, &nested) == nil {
			code = nested.Code
		}
	}
	if code == "" {
		code = detail.Code
	}
	code = strings.ToLower(code)
	if status == http.StatusUnauthorized || status == http.StatusBadRequest && code == "invalid_grant" ||
		code == "refresh_token_expired" || code == "refresh_token_reused" || code == "refresh_token_invalidated" {
		return refreshRefused("Codex is signed out (token refresh failed); run codex login")
	}
	return fmt.Errorf("Codex token refresh failed (HTTP %d)", status)
}
