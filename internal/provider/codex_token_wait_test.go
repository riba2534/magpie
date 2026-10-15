package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A saved account's daily renewal may be waiting for OpenAI. An active
// account with a usable credential needs no part of that rotation lock.
// The channels hold the renewal until signing has actually finished; the
// timeout only bounds a regression, it doesn't decide the ordering.
func TestCodexActiveTokenDoesNotWaitForSavedRenewal(t *testing.T) {
	for _, store := range []string{"file", "keychain"} {
		for _, mode := range []string{"usable", "cancelled", "signed out", "success without a mark"} {
			t.Run(store+"/"+mode, func(t *testing.T) {
				f := codexCredential(t, "saved", "saved-token", time.Now())
				resetRevoked()
				t.Cleanup(resetRevoked)
				home, err := os.UserHomeDir()
				if err != nil {
					t.Fatal(err)
				}
				if store == "keychain" {
					codexInKeychain(t, home, "keyring")
				}
				active, ok := codexAccount(home)
				if !ok {
					t.Fatal("active Codex account is missing")
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if mode == "cancelled" {
					cancel()
				}
				req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://127.0.0.1/responses", nil)
				if mode == "success without a mark" {
					if err := active.Sign(ctx, req, Responses, nil); err != nil {
						t.Fatal(err)
					}
				} else if mode == "signed out" {
					if err := (codexStore{home: codexHome(), keychain: store == "keychain"}).write([]byte(`{}`)); err != nil {
						t.Fatal(err)
					}
				}
				arrived, release := make(chan struct{}), make(chan struct{})
				fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(arrived)
					<-release
					io.WriteString(w, `{"access_token":"saved-fresh","refresh_token":"saved-next"}`)
				}))
				defer fake.Close()
				defer CodexTokenURLForTest(fake.URL)()
				var wg sync.WaitGroup
				defer func() {
					close(release)
					wg.Wait()
				}()
				renewed := make(chan error, 1)
				wg.Go(func() {
					_, _, err := renewSavedLogin(context.Background(), "codex", f.p.Account.User, true)
					renewed <- err
				})
				select {
				case <-arrived:
				case <-time.After(5 * time.Second):
					t.Fatal("saved renewal did not reach its fake authority")
				}
				signed := make(chan error, 1)
				wg.Go(func() {
					if mode == "success without a mark" {
						ServedSignInForRequest(active.Account, req)
						signed <- nil
						return
					}
					signed <- active.Sign(ctx, req, Responses, nil)
				})
				select {
				case err := <-signed:
					if mode == "cancelled" {
						if !errors.Is(err, context.Canceled) {
							t.Fatalf("cancelled signing: %v", err)
						}
					} else if mode == "signed out" {
						if err == nil || req.Header.Get("Authorization") != "" {
							t.Fatal("a signed-out account authenticated the request")
						}
					} else if err != nil || req.Header.Get("chatgpt-account-id") != "acct-1" || req.Header.Get("Authorization") == "" {
						t.Fatalf("active signing: %v, account %q", err, req.Header.Get("chatgpt-account-id"))
					}
				case <-time.After(5 * time.Second):
					t.Error("active signing waited for an unrelated saved account's renewal")
				}
				select {
				case err := <-renewed:
					t.Fatalf("saved renewal ended before release: %v", err)
				default:
				}
			})
		}
	}
}

type codexReadNotice struct {
	keychain
	read chan struct{}
	once sync.Once
}

func (k *codexReadNotice) Find(service, account string) ([]byte, error) {
	b, err := k.keychain.Find(service, account)
	k.once.Do(func() { close(k.read) })
	return b, err
}

// The pre-lock snapshot is only a fast-path test. If it needs renewal,
// another writer may replace it while it waits for the renewal lock.
func TestCodexActiveRefreshRereadsAfterWaiting(t *testing.T) {
	f := codexCredential(t, "keychain", fakeJWT(map[string]any{"exp": time.Now().Add(time.Minute).Unix()}), time.Now())
	var refreshes atomic.Int32
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshes.Add(1)
		w.WriteHeader(500)
	}))
	defer fake.Close()
	defer CodexTokenURLForTest(fake.URL)()
	read := make(chan struct{})
	codexKeychain = &codexReadNotice{keychain: codexKeychain, read: read}
	resetCodexKeychain()
	savedTokenMu.Lock()
	var unlock sync.Once
	release := func() { unlock.Do(savedTokenMu.Unlock) }
	var wg sync.WaitGroup
	defer func() { release(); wg.Wait() }()
	result := make(chan string, 1)
	wg.Go(func() {
		token, _, err := f.get(context.Background())
		if err != nil {
			t.Errorf("reading the updated credential: %v", err)
		}
		result <- token
	})
	select {
	case <-read:
	case <-time.After(5 * time.Second):
		t.Fatal("the initial credential wasn't read before waiting for renewal")
	}
	var raw map[string]any
	json.Unmarshal(f.read(), &raw)
	raw["tokens"].(map[string]any)["access_token"] = "rotated-while-waiting"
	b, _ := json.Marshal(raw)
	f.write(b)
	release()
	select {
	case token := <-result:
		if token != "rotated-while-waiting" || refreshes.Load() != 0 {
			t.Fatalf("used the pre-lock snapshot: %q, refreshes %d", token, refreshes.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("credential read did not finish after the lock was released")
	}
}
