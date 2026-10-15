package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type codexAuthTransport func(*http.Request) (*http.Response, error)

func (f codexAuthTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func codexNewCredential(t *testing.T, f codexCredentialFixture, token, id string) {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal(f.read(), &raw); err != nil {
		t.Fatal(err)
	}
	tokens := raw["tokens"].(map[string]any)
	tokens["access_token"], tokens["refresh_token"] = token, "refresh-from-another-process"
	if id != "" {
		tokens["account_id"] = id
	}
	b, _ := json.Marshal(raw)
	f.write(b)
}

func codexRecoveryRequest(t *testing.T, f codexCredentialFixture, ctx context.Context, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(`{"model":"gpt-5.5","input":"hello","stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.p.Sign(ctx, req, Responses, nil); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestCodexUnauthorizedUsesConcurrentRotation(t *testing.T) {
	for _, store := range []string{"file", "keychain", "saved"} {
		t.Run(store, func(t *testing.T) {
			f := codexCredential(t, store, fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}), time.Now())
			var refreshes atomic.Int32
			oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				refreshes.Add(1)
				w.WriteHeader(500)
			}))
			defer oauth.Close()
			defer CodexTokenURLForTest(oauth.URL)()
			var calls atomic.Int32
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					codexNewCredential(t, f, "rotated-elsewhere", "")
					w.WriteHeader(401)
					return
				}
				if r.Header.Get("Authorization") != "Bearer rotated-elsewhere" {
					t.Error("the rotation wasn't used")
				}
				io.WriteString(w, "served")
			}))
			defer up.Close()
			req := codexRecoveryRequest(t, f, context.Background(), up.URL)
			old := req.Header.Get("Authorization")
			res, err := f.p.Do(http.DefaultClient, req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != 200 || calls.Load() != 2 || refreshes.Load() != 0 {
				t.Fatalf("HTTP %d, attempts %d, refreshes %d", res.StatusCode, calls.Load(), refreshes.Load())
			}
			if req.Header.Get("Authorization") != old || res.Request == nil || res.Request.Header.Get("Authorization") != "Bearer rotated-elsewhere" {
				t.Fatal("the original request changed, or the response doesn't name the retried credential")
			}
		})
	}
}

func TestCodexConcurrentUnauthorizedRefreshesOnce(t *testing.T) {
	for _, store := range []string{"file", "keychain", "saved"} {
		t.Run(store, func(t *testing.T) {
			f := codexCredential(t, store, fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}), time.Now())
			var refreshes atomic.Int32
			oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				refreshes.Add(1)
				io.WriteString(w, `{"access_token":"fresh-token","refresh_token":"refresh-next"}`)
			}))
			defer oauth.Close()
			defer CodexTokenURLForTest(oauth.URL)()
			const requests = 4
			var first atomic.Int32
			allArrived := make(chan struct{})
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "Bearer fresh-token" {
					io.WriteString(w, "served")
					return
				}
				if first.Add(1) == requests {
					close(allArrived)
				}
				// Every request is sent on the old token before any 401 is
				// released. There are no scheduling sleeps in this test.
				select {
				case <-allArrived:
					w.WriteHeader(401)
				case <-r.Context().Done():
				}
			}))
			defer up.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var reqs []*http.Request
			for range requests {
				reqs = append(reqs, codexRecoveryRequest(t, f, ctx, up.URL))
			}
			var wg sync.WaitGroup
			for _, req := range reqs {
				wg.Go(func() {
					res, err := f.p.Do(http.DefaultClient, req)
					if err != nil {
						t.Error(err)
						return
					}
					defer res.Body.Close()
					if res.StatusCode != 200 {
						t.Errorf("recovery returned HTTP %d", res.StatusCode)
					}
				})
			}
			wg.Wait()
			if refreshes.Load() != 1 || first.Load() != requests {
				t.Fatalf("refreshes %d, original requests %d", refreshes.Load(), first.Load())
			}
		})
	}
}

func TestCodexUnauthorizedDoesNotCrossAccounts(t *testing.T) {
	for _, store := range []string{"file", "keychain", "saved"} {
		for _, during := range []bool{false, true} {
			t.Run(store+map[bool]string{false: "/before refresh", true: "/during refresh"}[during], func(t *testing.T) {
				f := codexCredential(t, store, fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}), time.Now())
				var refreshes atomic.Int32
				oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					refreshes.Add(1)
					codexNewCredential(t, f, "other-account-token", "other-account")
					io.WriteString(w, `{"access_token":"fresh-old-account","refresh_token":"refresh-next"}`)
				}))
				defer oauth.Close()
				defer CodexTokenURLForTest(oauth.URL)()
				var calls atomic.Int32
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if !during {
						codexNewCredential(t, f, "other-account-token", "other-account")
					}
					w.Header().Set("X-Original-Refusal", "kept")
					w.WriteHeader(401)
					io.WriteString(w, "original refusal")
				}))
				defer up.Close()
				req := codexRecoveryRequest(t, f, context.Background(), up.URL)
				res, err := f.p.Do(http.DefaultClient, req)
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				body, _ := io.ReadAll(res.Body)
				wantRefreshes := int32(0)
				if during {
					wantRefreshes = 1
				}
				if res.StatusCode != 401 || string(body) != "original refusal" || res.Header.Get("X-Original-Refusal") != "kept" || calls.Load() != 1 || refreshes.Load() != wantRefreshes {
					t.Fatalf("lost refusal or crossed accounts: HTTP %d, attempts %d, refreshes %d", res.StatusCode, calls.Load(), refreshes.Load())
				}
				if !bytes.Contains(f.read(), []byte("other-account-token")) || bytes.Contains(f.read(), []byte("fresh-old-account")) {
					t.Fatal("overwrote the new account's credential")
				}
			})
		}
	}
}

func TestCodexUnauthorizedRecoveryStopsAfterOneRetry(t *testing.T) {
	for _, store := range []string{"file", "keychain", "saved"} {
		t.Run(store, func(t *testing.T) { codexRepeatedUnauthorized(t, store) })
	}
}

func codexRepeatedUnauthorized(t *testing.T, store string) {
	f := codexCredential(t, store, fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}), time.Now())
	resetRevoked()
	t.Cleanup(resetRevoked)
	var refreshes atomic.Int32
	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshes.Add(1)
		io.WriteString(w, `{"access_token":"fresh-token","refresh_token":"refresh-next"}`)
	}))
	defer oauth.Close()
	defer CodexTokenURLForTest(oauth.URL)()
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"code":"token_revoked"}}`)
	}))
	defer up.Close()
	req := codexRecoveryRequest(t, f, context.Background(), up.URL)
	res, err := f.p.Do(http.DefaultClient, req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 401 || calls.Load() != 2 || refreshes.Load() != 1 || res.Request.Header.Get("Authorization") != "Bearer fresh-token" {
		t.Fatalf("HTTP %d, attempts %d, refreshes %d", res.StatusCode, calls.Load(), refreshes.Load())
	}
	NoteRevokedSignIn(req.Context(), f.p.Account, res.Request)
	if refreshes.Load() != 1 {
		t.Fatal("observing the final refusal refreshed again")
	}
	if _, marked := RevokedSignIn(f.p.Account, res.Request); !marked {
		t.Fatal("the final credential wasn't marked revoked")
	}
	if _, marked := RevokedSignIn(f.p.Account, req); marked {
		t.Fatal("the original credential was marked for the retry's refusal")
	}
	rememberLogins(true)
	resetRevoked()
	if _, marked := RevokedSignIn(f.p.Account, res.Request); !marked {
		t.Fatal("remembering the active credential or restarting lost its refusal")
	}
}

func TestCodexUnauthorizedUnreplayableRequestsStayRefused(t *testing.T) {
	for _, mode := range []string{"no GetBody", "broken GetBody", "cancelled", "account missing", "not bearer", "refresh failed", "replay failed", "ordinary provider"} {
		t.Run(mode, func(t *testing.T) {
			f := codexCredential(t, "saved", fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}), time.Now())
			var refreshes atomic.Int32
			oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				refreshes.Add(1)
				if mode == "refresh failed" {
					w.WriteHeader(503)
					return
				}
				io.WriteString(w, `{"access_token":"fresh-token","refresh_token":"refresh-next"}`)
			}))
			defer oauth.Close()
			defer CodexTokenURLForTest(oauth.URL)()
			type contextKey struct{}
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), contextKey{}, "provenance"))
			defer cancel()
			req := codexRecoveryRequest(t, f, ctx, "http://127.0.0.1/responses")
			switch mode {
			case "no GetBody":
				req.GetBody = nil
			case "broken GetBody":
				req.GetBody = func() (io.ReadCloser, error) { return nil, errors.New("body lost") }
			case "account missing":
				req.Header.Del("chatgpt-account-id")
			case "not bearer":
				req.Header.Set("Authorization", "Basic caller")
			case "ordinary provider":
				f.p.Account = nil
			}
			var attempts int
			client := &http.Client{Transport: codexAuthTransport(func(r *http.Request) (*http.Response, error) {
				attempts++
				if r.Context().Value(contextKey{}) != "provenance" {
					t.Error("request context was lost")
				}
				if mode == "cancelled" {
					cancel()
				}
				if attempts > 1 {
					return nil, errors.New("retry transport failed")
				}
				return &http.Response{StatusCode: 401, Header: http.Header{"X-Original": []string{"kept"}}, Body: io.NopCloser(strings.NewReader("original refusal")), Request: r}, nil
			})}
			res, err := f.p.Do(client, req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)
			wantAttempts, wantRefreshes := 1, int32(0)
			if mode == "replay failed" {
				wantAttempts, wantRefreshes = 2, 1
			} else if mode == "refresh failed" {
				wantRefreshes = 1
			}
			if res.StatusCode != 401 || string(body) != "original refusal" || res.Header.Get("X-Original") != "kept" || attempts != wantAttempts || refreshes.Load() != wantRefreshes {
				t.Fatalf("HTTP %d, body %q, attempts %d, refreshes %d", res.StatusCode, body, attempts, refreshes.Load())
			}
		})
	}
}

func TestCodexRenewalReasons(t *testing.T) {
	for _, every := range []time.Duration{0, 24 * time.Hour} {
		t.Run(every.String(), func(t *testing.T) {
			f := codexCredential(t, "saved", "opaque-token", time.Now().Add(-48*time.Hour))
			var reason atomic.Value
			oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var grant map[string]string
				json.NewDecoder(r.Body).Decode(&grant)
				reason.Store(grant["refresh_reason"])
				io.WriteString(w, `{"access_token":"fresh-token","refresh_token":"refresh-next"}`)
			}))
			defer oauth.Close()
			defer CodexTokenURLForTest(oauth.URL)()
			out := RenewLogins(context.Background(), every)
			want := "scheduled"
			if every == 0 {
				want = "forced"
			}
			if reason.Load() != want || len(out) != 1 || !out[0].Renewed || !bytes.Contains(f.read(), []byte("refresh-next")) {
				t.Fatalf("reason %v, renewals %+v", reason.Load(), out)
			}
		})
	}
}

func TestCodexRecoveryReleasesSingleConnection(t *testing.T) {
	f := codexCredential(t, "saved", fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}), time.Now())
	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"access_token":"fresh-token","refresh_token":"refresh-next"}`)
	}))
	defer oauth.Close()
	defer CodexTokenURLForTest(oauth.URL)()
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer fresh-token" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":{"code":"token_expired"}}`)
			return
		}
		io.WriteString(w, "served")
	}))
	defer up.Close()
	tr := &http.Transport{MaxConnsPerHost: 1}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := f.p.Do(client, codexRecoveryRequest(t, f, ctx, up.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || calls.Load() != 2 {
		t.Fatalf("the 401 occupied the only connection: HTTP %d, attempts %d", res.StatusCode, calls.Load())
	}
}

func TestCodexRecoveryPreservesLargeRefusal(t *testing.T) {
	f := codexCredential(t, "saved", fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}), time.Now())
	var refreshes atomic.Int32
	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshes.Add(1)
		w.WriteHeader(500)
	}))
	defer oauth.Close()
	defer CodexTokenURLForTest(oauth.URL)()
	want := strings.Repeat("refusal ", 12<<10)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		io.WriteString(w, want)
	}))
	defer up.Close()
	res, err := f.p.Do(http.DefaultClient, codexRecoveryRequest(t, f, context.Background(), up.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	got, err := io.ReadAll(res.Body)
	if err != nil || string(got) != want || refreshes.Load() != 0 {
		t.Fatalf("oversized refusal lost bytes or refreshed: bytes %d, error %v, refreshes %d", len(got), err, refreshes.Load())
	}
}

func TestCodexRecoveryDoesNotCrossPeopleInAWorkspace(t *testing.T) {
	for _, store := range []string{"file", "keychain", "saved"} {
		for _, during := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/during=%v", store, during), func(t *testing.T) {
				f := codexCredential(t, store, fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}), time.Now())
				changePerson := func() {
					var raw map[string]any
					json.Unmarshal(f.read(), &raw)
					tokens := raw["tokens"].(map[string]any)
					tokens["id_token"] = fakeJWT(map[string]any{"email": "another-person@example.com"})
					tokens["access_token"] = "another-person-token"
					b, _ := json.Marshal(raw)
					f.write(b)
				}
				var refreshes atomic.Int32
				oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					refreshes.Add(1)
					changePerson()
					io.WriteString(w, `{"access_token":"fresh-original-person","refresh_token":"refresh-next"}`)
				}))
				defer oauth.Close()
				defer CodexTokenURLForTest(oauth.URL)()
				var calls atomic.Int32
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if !during {
						changePerson()
					}
					w.WriteHeader(401)
					io.WriteString(w, `{"error":{"code":"token_revoked"}}`)
				}))
				defer up.Close()
				res, err := f.p.Do(http.DefaultClient, codexRecoveryRequest(t, f, context.Background(), up.URL))
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				if res.StatusCode != 401 || calls.Load() != 1 || refreshes.Load() != map[bool]int32{false: 0, true: 1}[during] {
					t.Fatalf("crossed people: HTTP %d, attempts %d, refreshes %d", res.StatusCode, calls.Load(), refreshes.Load())
				}
				NoteRevokedSignIn(context.Background(), f.p.Account, res.Request)
				for _, l := range readLogins() {
					if l.User == f.p.Account.User && l.Lapsed != "" {
						t.Fatal("marked the other person's sign-in revoked")
					}
				}
				if !bytes.Contains(f.read(), []byte("another-person-token")) {
					t.Fatal("overwrote the other person's token")
				}
			})
		}
	}
}

func TestCodexRotationKeepsConcurrentMetadata(t *testing.T) {
	for _, store := range []string{"file", "keychain", "saved"} {
		t.Run(store, func(t *testing.T) {
			f := codexCredential(t, store, fakeJWT(map[string]any{"exp": time.Now().Add(2 * time.Minute).Unix()}), time.Now())
			oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var raw map[string]json.RawMessage
				json.Unmarshal(f.read(), &raw)
				// Reordered top-level keys and an unrelated edit aren't an
				// account switch. Keep both the edit and the rotated token.
				b := []byte(fmt.Sprintf(`{"external_edit":"kept","tokens":%s,"auth_mode":%s,"last_refresh":%s,"kept":%s}`, raw["tokens"], raw["auth_mode"], raw["last_refresh"], raw["kept"]))
				f.write(b)
				io.WriteString(w, `{"access_token":"fresh-token","refresh_token":"refresh-next"}`)
			}))
			defer oauth.Close()
			defer CodexTokenURLForTest(oauth.URL)()
			token, _, err := f.get(context.Background())
			if err != nil || token != "fresh-token" {
				t.Fatalf("metadata edit discarded the rotation: %q, %v", token, err)
			}
			var raw map[string]any
			json.Unmarshal(f.read(), &raw)
			if raw["external_edit"] != "kept" || raw["tokens"].(map[string]any)["refresh_token"] != "refresh-next" {
				t.Fatal("concurrent metadata or rotated refresh token was lost")
			}
		})
	}
}

func TestCodexRecoveryRefreshesAnExpiredConcurrentRotation(t *testing.T) {
	f := codexCredential(t, "saved", fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}), time.Now())
	var refreshes atomic.Int32
	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshes.Add(1)
		var grant map[string]string
		json.NewDecoder(r.Body).Decode(&grant)
		if grant["refresh_token"] != "refresh-from-another-process" {
			t.Error("refreshed the credential from before the reload")
		}
		io.WriteString(w, `{"access_token":"fresh-token","refresh_token":"refresh-next"}`)
	}))
	defer oauth.Close()
	defer CodexTokenURLForTest(oauth.URL)()
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			codexNewCredential(t, f, fakeJWT(map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}), "")
			w.WriteHeader(401)
			return
		}
		if r.Header.Get("Authorization") != "Bearer fresh-token" {
			t.Error("retried with the expired rotation")
		}
		io.WriteString(w, "served")
	}))
	defer up.Close()
	res, err := f.p.Do(http.DefaultClient, codexRecoveryRequest(t, f, context.Background(), up.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || refreshes.Load() != 1 || calls.Load() != 2 {
		t.Fatalf("HTTP %d, refreshes %d, attempts %d", res.StatusCode, refreshes.Load(), calls.Load())
	}
}
