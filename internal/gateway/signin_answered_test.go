package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/provider"
)

// A request retried after renewing its sign-in may be refused again. The
// refusal belongs to the credential actually sent, not the first attempt.
func TestRevokedSignInUsesAnsweredRequest(t *testing.T) {
	for _, retried := range []bool{false, true} {
		name := "original"
		if retried {
			name = "renewed"
		}
		t.Run(name, func(t *testing.T) {
			codexSignedIn(t)
			p, _, ok := provider.Resolve("codex/gpt-5.5")
			if !ok || p.Account == nil {
				t.Fatal("the signed-in Codex account is not served")
			}
			provider.Logins("codex") // keep the active sign-in's bookmark
			firstToken := codexAccessToken(t)
			original := httptest.NewRequest(http.MethodPost, "http://codex.invalid/responses", nil)
			original.Header.Set("Authorization", "Bearer "+firstToken)
			original.Header.Set("chatgpt-account-id", "acct-1")
			answered := original.Clone(context.Background())
			answered.Header.Set("Authorization", "Bearer renewed-token")
			const body = `{"error":{"code":"token_revoked","message":"The token was revoked"}}`
			res := &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(strings.NewReader(body)),
			}
			if retried {
				path := filepath.Join(os.Getenv("HOME"), ".codex", "auth.json")
				b, err := os.ReadFile(path)
				var auth map[string]any
				if err != nil || json.Unmarshal(b, &auth) != nil {
					t.Fatalf("read the test's sign-in: %v", err)
				}
				auth["tokens"].(map[string]any)["access_token"] = "renewed-token"
				if err := os.WriteFile(path, mustJSON(auth), 0o600); err != nil {
					t.Fatal(err)
				}
				res.Request = answered
			}
			noteSignIn(context.Background(), p.Account, original, res)
			defer res.Body.Close()
			if _, marked := provider.RevokedSignIn(p.Account, original); marked == retried {
				t.Errorf("original credential marked = %v, retried = %v", marked, retried)
			}
			if _, marked := provider.RevokedSignIn(p.Account, answered); marked != retried {
				t.Errorf("answered credential marked = %v, retried = %v", marked, retried)
			}
			if original.Header.Get("Authorization") != "Bearer "+firstToken {
				t.Error("recording the answer changed the original request")
			}
			got, err := io.ReadAll(res.Body)
			if err != nil || string(got) != body {
				t.Fatalf("the caller lost the refusal: %q, %v", got, err)
			}
		})
	}
}
