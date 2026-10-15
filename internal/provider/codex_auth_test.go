package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Each store is entirely in signIn's temporary home (the keychain is a fake).
// The saved account is distinct from the agent's own, so a refresh cannot pass
// by accidentally changing the active sign-in instead.
type codexCredentialFixture struct {
	p     Provider
	get   func(context.Context) (string, string, error)
	read  func() []byte
	write func([]byte)
}

func codexCredential(t *testing.T, store, token string, last any) codexCredentialFixture {
	t.Helper()
	home := signIn(t)
	dir := filepath.Join(home, ".codex")
	email, id := "me@example.com", "acct-1"
	if store == "saved" {
		email, id = "saved@example.com", "acct-saved"
	}
	auth := map[string]any{"auth_mode": "chatgpt", "kept": "unknown field", "tokens": map[string]any{
		"id_token":     fakeJWT(map[string]any{"email": email, "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": id}}),
		"access_token": token, "refresh_token": "refresh-old", "account_id": id,
	}}
	if last != nil {
		auth["last_refresh"] = last
	}
	b, _ := json.Marshal(auth)
	f := codexCredentialFixture{}
	if store == "saved" {
		f.write = func(b []byte) {
			t.Helper()
			loginsMu.Lock()
			defer loginsMu.Unlock()
			ls := readLogins()
			found := false
			for i := range ls {
				if ls[i].Agent == "codex" && ls[i].User == email {
					ls[i].Auth, found = b, true
				}
			}
			if !found {
				ls = append(ls, savedLogin{Agent: "codex", User: email, On: true, Auth: b, Seen: time.Now().Add(-48 * time.Hour)})
			}
			if err := writeLogins(ls); err != nil {
				t.Fatal(err)
			}
		}
		f.read = func() []byte {
			for _, l := range readLogins() {
				if l.Agent == "codex" && l.User == email {
					return l.Auth
				}
			}
			t.Fatal("saved account disappeared")
			return nil
		}
		f.get = func(ctx context.Context) (string, string, error) { return savedLoginToken(ctx, "codex", email) }
	} else {
		if store == "keychain" {
			codexInKeychain(t, home, "keyring")
		}
		st := codexStore{home: dir, keychain: store == "keychain"}
		f.write = func(b []byte) {
			t.Helper()
			if err := st.write(b); err != nil {
				t.Fatal(err)
			}
		}
		f.read = func() []byte {
			t.Helper()
			b, _, err := readCodexLogin(dir, true)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		f.get = func(ctx context.Context) (string, string, error) { return codexToken(ctx, dir) }
	}
	f.write(b)
	rememberLogins(true)
	p, ok := codexAccount(home)
	if !ok {
		t.Fatal("Codex fixture not found")
	}
	if store == "saved" {
		also := p.AlsoOn()
		if len(also) != 1 {
			t.Fatalf("saved accounts: %d", len(also))
		}
		p = also[0]
	}
	f.p = p
	return f
}

func TestCodexRefreshUsesExpiryThenLastRefresh(t *testing.T) {
	for _, store := range []string{"file", "keychain", "saved"} {
		for _, tc := range []struct {
			name, token, reason string
			last                any
		}{
			{"near expiry", fakeJWT(map[string]any{"exp": time.Now().Add(2 * time.Minute).Unix()}), "proactive_expiry", time.Now()},
			{"expired", fakeJWT(map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}), "proactive_expiry", time.Now()},
			{"epoch expiry", fakeJWT(map[string]any{"exp": 0}), "proactive_expiry", time.Now()},
			{"expiry wins", fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}), "", time.Now().Add(-9 * 24 * time.Hour)},
			{"opaque old", "opaque-token", "scheduled", time.Now().Add(-9 * 24 * time.Hour)},
			{"invalid expiry old", fakeJWT(map[string]any{"exp": "not a number"}), "scheduled", time.Now().Add(-9 * 24 * time.Hour)},
			{"opaque recent", "opaque-token", "", time.Now().Add(-time.Hour)},
			{"unknown refresh time", "opaque-token", "", "not a date"},
			{"no refresh time", "opaque-token", "", nil},
		} {
			t.Run(store+"/"+tc.name, func(t *testing.T) {
				f := codexCredential(t, store, tc.token, tc.last)
				var calls atomic.Int32
				fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					var grant map[string]string
					if err := json.NewDecoder(r.Body).Decode(&grant); err != nil {
						t.Error(err)
					}
					want := map[string]string{"grant_type": "refresh_token", "client_id": codexClientID, "refresh_token": "refresh-old", "refresh_reason": tc.reason}
					if !reflect.DeepEqual(grant, want) {
						t.Errorf("refresh grant = %v, want %v", grant, want)
					}
					io.WriteString(w, `{"access_token":"fresh-token","refresh_token":"refresh-next"}`)
				}))
				defer fake.Close()
				defer CodexTokenURLForTest(fake.URL)()
				tok, _, err := f.get(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if tc.reason == "" {
					if tok != tc.token || calls.Load() != 0 {
						t.Fatalf("token without refresh: %q, requests %d", tok, calls.Load())
					}
				} else if tok != "fresh-token" || calls.Load() != 1 || !bytes.Contains(f.read(), []byte("refresh-next")) || !bytes.Contains(f.read(), []byte("unknown field")) {
					t.Fatalf("refresh not persisted: token %q, requests %d", tok, calls.Load())
				}
			})
		}
	}
}

func TestCodexProactiveRefreshHiccupKeepsUnexpiredToken(t *testing.T) {
	for _, store := range []string{"file", "keychain", "saved"} {
		for _, tc := range []struct {
			name, body string
			status     int
			expired    bool
			keeps      bool
		}{
			{"busy", `{"error":"temporarily_unavailable"}`, 503, false, true},
			{"other bad request", `{"error":"invalid_request"}`, 400, false, true},
			{"revoked", `{"error":"invalid_grant"}`, 400, false, false},
			{"expired refresh", `{"error":{"code":"refresh_token_expired"}}`, 403, false, false},
			{"top-level revoked", `{"code":"refresh_token_invalidated"}`, 403, false, false},
			{"unauthorized", `{}`, 401, false, false},
			{"expired access", `{"error":"temporarily_unavailable"}`, 503, true, false},
		} {
			t.Run(store+"/"+tc.name, func(t *testing.T) {
				exp := time.Now().Add(2 * time.Minute)
				if tc.expired {
					exp = time.Now().Add(-time.Hour)
				}
				token := fakeJWT(map[string]any{"exp": exp.Unix()})
				f := codexCredential(t, store, token, time.Now())
				before := append([]byte(nil), f.read()...)
				fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tc.status)
					io.WriteString(w, tc.body)
				}))
				defer fake.Close()
				defer CodexTokenURLForTest(fake.URL)()
				got, _, err := f.get(context.Background())
				if tc.keeps && (err != nil || got != token) {
					t.Fatalf("unexpired token lost on temporary refresh failure: %q, %v", got, err)
				}
				if !tc.keeps && err == nil {
					t.Fatal("unusable sign-in was accepted")
				}
				if !bytes.Equal(before, f.read()) {
					t.Fatal("failed refresh changed credentials")
				}
			})
		}
	}
}

func TestCodexUnauthorizedRefreshesSameAccount(t *testing.T) {
	for _, store := range []string{"file", "keychain", "saved"} {
		t.Run(store, func(t *testing.T) {
			old := fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()})
			f := codexCredential(t, store, old, time.Now())
			var refreshes atomic.Int32
			oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				refreshes.Add(1)
				var grant map[string]string
				json.NewDecoder(r.Body).Decode(&grant)
				if grant["refresh_reason"] != "unauthorized_recovery" {
					t.Errorf("refresh reason: %q", grant["refresh_reason"])
				}
				io.WriteString(w, `{"access_token":"fresh-token","refresh_token":"refresh-next"}`)
			}))
			defer oauth.Close()
			defer CodexTokenURLForTest(oauth.URL)()
			var mu sync.Mutex
			var headers []http.Header
			var bodies []string
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				mu.Lock()
				headers, bodies = append(headers, r.Header.Clone()), append(bodies, string(b))
				mu.Unlock()
				if r.Header.Get("Authorization") != "Bearer fresh-token" {
					w.WriteHeader(http.StatusUnauthorized)
					io.WriteString(w, `{"error":{"code":"token_expired"}}`)
					return
				}
				io.WriteString(w, "served")
			}))
			defer up.Close()
			// The body already has its final encoding. Recovering auth must
			// not feed compressed bytes to a body transformer or signer.
			req, _ := http.NewRequest(http.MethodPost, up.URL+"/responses?q=kept", strings.NewReader("encoded-wire-body"))
			if err := f.p.Sign(req.Context(), req, Responses, nil); err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Encoding", "zstd")
			req.Header.Set("X-Request-Metadata", "kept")
			res, err := f.p.Do(http.DefaultClient, req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != 200 {
				t.Fatalf("same account wasn't retried: HTTP %d, refreshes %d", res.StatusCode, refreshes.Load())
			}
			mu.Lock()
			defer mu.Unlock()
			if len(headers) != 2 || refreshes.Load() != 1 || bodies[0] != bodies[1] {
				t.Fatalf("requests %d, refreshes %d, bodies %v", len(headers), refreshes.Load(), bodies)
			}
			headers[0].Del("Authorization")
			headers[1].Del("Authorization")
			if !reflect.DeepEqual(headers[0], headers[1]) {
				t.Fatal("recovery changed non-authentication headers")
			}
			if !bytes.Contains(f.read(), []byte("refresh-next")) {
				t.Fatal("rotated refresh token wasn't kept")
			}
		})
	}
}
