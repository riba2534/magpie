package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"strings"
)

// codexSentAuth binds recovery to the credential this request used. A
// different account on disk is never silently substituted during recovery.
type codexSentAuth struct {
	token, accountID string
	identity         codexIdentity
}

func (s codexSentAuth) matches(a codexAuth) bool {
	return s.token != "" && s.accountID != "" && a.AuthMode != "apikey" && codexAccountID(a) == s.accountID && s.identity.matches(a, s.token)
}

var errCodexAccountChanged = errors.New("Codex's sign-in changed accounts while the request was in flight")

func recoverCodexToken(ctx context.Context, dir string, sent codexSentAuth) (string, string, error) {
	savedTokenMu.Lock() // also excludes a switch into or out of this store
	defer savedTokenMu.Unlock()
	codexMu.Lock()
	defer codexMu.Unlock()
	return codexTokenLocked(ctx, dir, codexUnauthorized, &sent)
}

func recoverSavedCodex(ctx context.Context, user string, sent codexSentAuth) (string, string, error) {
	ctx = ViaLogin(ctx, "codex", user)
	savedTokenMu.Lock()
	defer savedTokenMu.Unlock()
	// The user may have switched this saved account into Codex while the
	// request was out. Its saved copy is then only a bookmark; refresh the
	// store Codex now owns, never that stale copy.
	if b, _, err := readCodexLogin(codexHome(), true); err == nil {
		var active codexAuth
		if json.Unmarshal(b, &active) != nil {
			return "", "", errors.New("Codex's current sign-in is unreadable")
		}
		if sent.matches(active) {
			codexMu.Lock()
			defer codexMu.Unlock()
			return codexTokenLocked(ctx, codexHome(), codexUnauthorized, &sent)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", "", err // unknown whether the saved copy became Codex's own
	}
	return renewSavedLoginLocked(ctx, "codex", user, codexUnauthorized, &sent)
}

// retryCodexAuth asks the same account once more after a 401, before the
// gateway considers another account. The request is already signed and
// encoded: only its credential changes. Its body, headers, context (proxy
// and request provenance included) and the caller's request stay intact.
func (p Provider) retryCodexAuth(client *http.Client, req *http.Request, res *http.Response) (*http.Response, error) {
	a := p.Account
	if a == nil || a.Agent != "codex" || a.recover == nil || res.StatusCode != http.StatusUnauthorized ||
		req.GetBody == nil || req.Context().Err() != nil {
		return res, nil
	}
	token, bearer := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	sent := codexSentAuth{token: token, accountID: req.Header.Get("chatgpt-account-id"), identity: a.codexIdentity}
	if !bearer || sent.token == "" || sent.accountID == "" {
		return res, nil
	}
	body, err := req.GetBody()
	if err != nil || body == nil {
		return res, nil
	}
	handedOff := false
	defer func() {
		if !handedOff {
			body.Close()
		}
	}()
	if !keepCodexRefusalBody(res) {
		return res, nil
	}
	token, accountID, err := a.recover(req.Context(), sent)
	if err != nil || token == "" || accountID != sent.accountID || req.Context().Err() != nil {
		return res, nil
	}
	retry := req.Clone(req.Context())
	retry.Body = body
	retry.Header.Set("Authorization", "Bearer "+token)
	retry.Header.Set("chatgpt-account-id", accountID)
	handedOff = true // http.Client owns the retry body's lifetime from here
	got, err := client.Do(retry)
	if err != nil {
		// Keep the original refusal for the gateway's existing fallback.
		// Its body was retained before releasing the connection.
		return res, nil
	}
	res.Body.Close()
	if got.Request == nil {
		got.Request = retry
	}
	return got, nil
}

type codexRefusalBody struct {
	io.Reader
	io.Closer
}

// A 401 must release its HTTP/1 connection before the retry can acquire
// one, including clients with a single connection per host. Keep a small
// refusal readable for fallback. An oversized or unreadable body isn't
// discarded and doesn't trigger a replay.
func keepCodexRefusalBody(res *http.Response) bool {
	const most = 64 << 10
	if res.Body == nil {
		res.Body = http.NoBody
		return true
	}
	original := res.Body
	b, err := io.ReadAll(io.LimitReader(original, most+1))
	if err != nil || len(b) > most {
		res.Body = codexRefusalBody{Reader: io.MultiReader(bytes.NewReader(b), original), Closer: original}
		return false
	}
	original.Close()
	res.Body = io.NopCloser(bytes.NewReader(b))
	return true
}

// keepCodexRefusal persists a refusal only for the credential still held.
// savedTokenMu is held by the observer. An active account's saved copy is
// a bookmark: bring it up to date before marking the refreshed credential,
// or rememberLogins would mistake that rotation for a new sign-in and
// clear the mark immediately.
func keepCodexRefusal(a *Account, req *http.Request, mark, why string) bool {
	token, bearer := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	sent := codexSentAuth{token: token, accountID: req.Header.Get("chatgpt-account-id"), identity: a.codexIdentity}
	if !bearer || token == "" || sent.accountID == "" {
		return false
	}
	dir := a.codexHome
	if dir == "" {
		dir = codexHome()
	}
	b, _, err := readCodexLogin(dir, true)
	var active codexAuth
	own := false
	if err == nil {
		if json.Unmarshal(b, &active) != nil {
			return false
		}
		own = sent.matches(active)
		if own && active.Tokens.AccessToken != sent.token {
			return false
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if a.codexHome != "" && !own {
		return false
	}
	err = editSideLogin(a.Agent, a.User, func(ls []savedLogin, i int) ([]savedLogin, error) {
		var current codexAuth
		if json.Unmarshal(ls[i].Auth, &current) != nil || !sent.matches(current) {
			return nil, errUnchanged
		}
		if own {
			ls[i].Auth = b
		} else if current.Tokens.AccessToken != sent.token {
			return nil, errUnchanged
		}
		ls[i].Lapsed, ls[i].Refused = why, revokedPrefix+mark
		return ls, nil
	})
	return err == nil
}
