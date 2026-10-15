package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A late success on token A must not forgive token B's later refusal.
// These events are ordered explicitly; no goroutine timing is needed.
func TestCodexSuccessOnlyClearsCurrentCredential(t *testing.T) {
	for _, store := range []string{"file", "keychain", "saved"} {
		t.Run(store, func(t *testing.T) {
			f := codexCredential(t, store, fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}), time.Now())
			resetRevoked()
			t.Cleanup(resetRevoked)
			old := codexRecoveryRequest(t, f, context.Background(), "http://127.0.0.1/responses")
			codexNewCredential(t, f, "new-token", "")
			current := codexRecoveryRequest(t, f, context.Background(), "http://127.0.0.1/responses")
			NoteRevokedSignIn(context.Background(), f.p.Account, current)
			if _, marked := RevokedSignIn(f.p.Account, current); !marked {
				t.Fatal("the current credential wasn't marked")
			}
			ServedSignInForRequest(f.p.Account, old)
			if _, marked := RevokedSignIn(f.p.Account, current); !marked {
				t.Error("an old credential's late success cleared the current credential's refusal")
			}
			ServedSignInForRequest(f.p.Account, current)
			if _, marked := RevokedSignIn(f.p.Account, current); marked {
				t.Fatal("the current credential's own success didn't clear its refusal")
			}
			NoteRevokedSignIn(context.Background(), f.p.Account, current)
			codexNewCredential(t, f, "served-replacement", "")
			newer := codexRecoveryRequest(t, f, context.Background(), "http://127.0.0.1/responses")
			ServedSignInForRequest(f.p.Account, newer)
			if _, marked := RevokedSignIn(f.p.Account, current); marked {
				t.Fatal("a successful replacement credential didn't clear the older refusal")
			}
		})
	}
}

func TestCodexPermanentRecoveryRefusalIsRemembered(t *testing.T) {
	for _, store := range []string{"file", "keychain", "saved"} {
		for _, permanent := range []bool{false, true} {
			name := store + "/temporary"
			if permanent {
				name = store + "/permanent"
			}
			t.Run(name, func(t *testing.T) {
				f := codexCredential(t, store, fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}), time.Now())
				resetRevoked()
				t.Cleanup(resetRevoked)
				var refreshes atomic.Int32
				oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					refreshes.Add(1)
					if permanent {
						w.WriteHeader(400)
						io.WriteString(w, `{"error":"invalid_grant"}`)
					} else {
						w.WriteHeader(503)
						io.WriteString(w, `{"error":"temporarily_unavailable"}`)
					}
				}))
				defer oauth.Close()
				defer CodexTokenURLForTest(oauth.URL)()
				const refusal = `{"error":{"code":"token_expired"}}`
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(401)
					io.WriteString(w, refusal)
				}))
				defer up.Close()
				for i := range 3 {
					if i == 2 {
						resetRevoked() // persistent state must guard the next request too
					}
					req := codexRecoveryRequest(t, f, context.Background(), up.URL)
					res, err := f.p.Do(http.DefaultClient, req)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(res.Body)
					res.Body.Close()
					if err != nil || res.StatusCode != 401 || string(body) != refusal {
						t.Fatalf("original refusal lost: HTTP %d, %q, %v", res.StatusCode, body, err)
					}
					if _, marked := RevokedSignIn(f.p.Account, req); marked != permanent {
						t.Errorf("credential marked = %v, permanent = %v", marked, permanent)
					}
				}
				want := int32(3)
				if permanent {
					want = 1
				}
				if got := refreshes.Load(); got != want {
					t.Errorf("refresh requests = %d, want %d", got, want)
				}
				for _, l := range readLogins() {
					if l.User == f.p.Account.User && (l.Lapsed != "") != permanent {
						t.Errorf("sign-in status = %q, permanent = %v", l.Lapsed, permanent)
					}
				}
			})
		}
	}
}

func TestCodexPermanentRecoveryDoesNotMarkChangedCredential(t *testing.T) {
	for _, store := range []string{"file", "keychain", "saved"} {
		t.Run(store, func(t *testing.T) {
			f := codexCredential(t, store, fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}), time.Now())
			resetRevoked()
			t.Cleanup(resetRevoked)
			oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				codexNewCredential(t, f, "replacement-token", "replacement-account")
				w.WriteHeader(400)
				io.WriteString(w, `{"error":"invalid_grant"}`)
			}))
			defer oauth.Close()
			defer CodexTokenURLForTest(oauth.URL)()
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(401)
				io.WriteString(w, `{"error":{"code":"token_expired"}}`)
			}))
			defer up.Close()
			req := codexRecoveryRequest(t, f, context.Background(), up.URL)
			res, err := f.p.Do(http.DefaultClient, req)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if res.StatusCode != 401 {
				t.Fatalf("HTTP %d", res.StatusCode)
			}
			if _, marked := RevokedSignIn(f.p.Account, req); marked {
				t.Fatal("old refusal marked a credential the account no longer holds")
			}
			for _, l := range readLogins() {
				if l.User == f.p.Account.User && l.Lapsed != "" {
					t.Fatal("replacement account was marked as needing sign-in")
				}
			}
		})
	}
}

func TestCodexRevocationSurvivesMetadataEdit(t *testing.T) {
	for _, store := range []string{"file", "keychain"} {
		t.Run(store, func(t *testing.T) {
			f := codexCredential(t, store, fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}), time.Now())
			resetRevoked()
			t.Cleanup(resetRevoked)
			req := codexRecoveryRequest(t, f, context.Background(), "http://127.0.0.1/responses")
			NoteRevokedSignIn(context.Background(), f.p.Account, req)
			if _, marked := RevokedSignIn(f.p.Account, req); !marked {
				t.Fatal("credential wasn't marked before editing metadata")
			}
			var raw map[string]json.RawMessage
			json.Unmarshal(f.read(), &raw)
			f.write([]byte(fmt.Sprintf(`{"external_edit":"kept","tokens":%s,"auth_mode":%s,"last_refresh":%s}`, raw["tokens"], raw["auth_mode"], raw["last_refresh"])))
			rememberLogins(true)
			resetRevoked()
			if _, marked := RevokedSignIn(f.p.Account, req); !marked {
				t.Error("metadata-only edits made the revoked credential usable after restart")
			}
			codexNewCredential(t, f, "replacement-token", "")
			rememberLogins(true)
			resetRevoked()
			if _, marked := RevokedSignIn(f.p.Account, req); marked {
				t.Fatal("a real credential change retained the old refusal")
			}
		})
	}
}
