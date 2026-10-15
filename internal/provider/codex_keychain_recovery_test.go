package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// security prints mdat to the second. Unlike fakeKeychain's content hash,
// this date does not distinguish two writes in the same second.
type sameSecondCodexKeychain struct{ *fakeKeychain }

func (k sameSecondCodexKeychain) Stat(service, account string) (string, error) {
	if _, err := k.fakeKeychain.Stat(service, account); err != nil {
		return "", err
	}
	return "20260101000000Z", nil
}

// The returned fixture reads and writes as an external Codex process:
// directly to the item, without updating magpie's credential cache.
func codexExternalKeychain(t *testing.T, f codexCredentialFixture) codexCredentialFixture {
	t.Helper()
	k := codexKeychain.(*fakeKeychain)
	account := codexKeychainAccount(codexHome())
	codexKeychain = sameSecondCodexKeychain{k}
	resetCodexKeychain()
	if _, err := findCodexKeychain(codexHome(), false); err != nil {
		t.Fatal(err)
	}
	f.read = func() []byte { return k.item(account) }
	f.write = func(b []byte) { k.set(account, b) }
	return f
}

func TestCodexKeychainSameSecondChanges(t *testing.T) {
	for _, tc := range []struct {
		change string
		during bool
	}{
		{"rotation", false},
		{"account", false},
		{"account", true},
		{"metadata", true},
	} {
		phase := "before refusal"
		if tc.during {
			phase = "during refresh"
		}
		t.Run(tc.change+"/"+phase, func(t *testing.T) {
			f := codexCredential(t, "keychain", fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}), time.Now())
			external := codexExternalKeychain(t, f)
			var changed map[string]any
			if err := json.Unmarshal(external.read(), &changed); err != nil {
				t.Fatal(err)
			}
			tokens := changed["tokens"].(map[string]any)
			if tc.change == "metadata" {
				changed["agent_identity"] = "written by Codex during refresh"
			} else {
				tokens["access_token"] = "written-by-codex"
				tokens["refresh_token"] = "rotated-by-codex"
				if tc.change == "account" {
					tokens["account_id"] = "another-workspace"
				}
			}
			updated, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			var refreshes atomic.Int32
			oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				refreshes.Add(1)
				if tc.during {
					external.write(updated)
				}
				io.WriteString(w, `{"access_token":"refreshed-by-magpie","refresh_token":"refresh-next"}`)
			}))
			defer oauth.Close()
			defer CodexTokenURLForTest(oauth.URL)()
			wantStatus, wantCalls, wantRefreshes := 200, 2, int32(1)
			wantToken := "refreshed-by-magpie"
			if tc.change == "account" {
				wantStatus, wantCalls = 401, 1
			}
			if !tc.during {
				wantRefreshes = 0
			}
			if tc.change != "metadata" {
				wantToken = "written-by-codex"
			}
			var calls int
			client := &http.Client{Transport: codexAuthTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				status, body := 200, "served"
				if calls == 1 {
					if !tc.during {
						external.write(updated)
					}
					status, body = 401, "original refusal"
				} else if r.Header.Get("Authorization") != "Bearer "+wantToken || r.Header.Get("chatgpt-account-id") != "acct-1" {
					t.Error("the replay did not use the same account's current credential")
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}
			req := codexRecoveryRequest(t, f, context.Background(), "http://127.0.0.1/responses")
			res, err := f.p.Do(client, req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != wantStatus || calls != wantCalls || refreshes.Load() != wantRefreshes {
				t.Errorf("HTTP %d, attempts %d, refreshes %d; want %d, %d, %d", res.StatusCode, calls, refreshes.Load(), wantStatus, wantCalls, wantRefreshes)
			}
			if wantStatus == 401 && string(body) != "original refusal" {
				t.Errorf("lost the original refusal: %s", body)
			}
			var stored map[string]any
			if err := json.Unmarshal(external.read(), &stored); err != nil {
				t.Fatal(err)
			}
			held := stored["tokens"].(map[string]any)
			if held["access_token"] != wantToken || held["account_id"] != tokens["account_id"] {
				t.Error("overwrote Codex's concurrent credential change")
			}
			if tc.change == "metadata" && stored["agent_identity"] != changed["agent_identity"] {
				t.Error("lost Codex's metadata written during refresh")
			}
		})
	}
}
