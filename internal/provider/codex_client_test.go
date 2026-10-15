package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// Re-signing a request selects the complete account identity. A missing
// account id must not retain the previous account's, and none of that
// account's device or turn credentials can authenticate the replacement.
func TestCodexSignReplacesAccountIdentity(t *testing.T) {
	for _, account := range []string{"selected-account", ""} {
		t.Run(account, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, CodexBase+"/responses/compact", nil)
			for k, v := range map[string]string{
				"Authorization":                "Bearer previous-token",
				"chatgpt-account-id":           "previous-account",
				"x-openai-actor-authorization": "previous-actor",
				"x-oai-attestation":            "previous-attestation",
				"x-codex-turn-state":           "previous-route",
				"x-openai-codex-luna-reserve":  "1",
			} {
				// A relayed header may retain its client's spelling.
				req.Header[k] = []string{v}
			}
			sign := codexSign(func(context.Context) (string, string, error) { return "selected-token", account, nil })
			if err := sign(context.Background(), req, nil); err != nil {
				t.Fatal(err)
			}
			if req.Header.Get("Authorization") != "Bearer selected-token" || req.Header.Get("chatgpt-account-id") != account {
				t.Error("request did not get the selected account's identity")
			}
			for k := range req.Header {
				if k == "chatgpt-account-id" || k == "x-openai-actor-authorization" || k == "x-oai-attestation" || k == "x-codex-turn-state" || k == "x-openai-codex-luna-reserve" {
					t.Errorf("previous account's header %s retained", k)
				}
			}
		})
	}
}

// A source belongs to one outbound request and cannot change when a caller
// edits the original header map, or when another client reports a newer
// installed version. Session, thread and cache identities are independent.
func TestCodexClientRequestHeaders(t *testing.T) {
	codexSeen.Lock()
	was := codexSeen.v
	codexSeen.v = "9.9.9"
	codexSeen.Unlock()
	t.Cleanup(func() {
		codexSeen.Lock()
		codexSeen.v = was
		codexSeen.Unlock()
	})
	for _, c := range []struct {
		name, session, thread, wantSession, wantThread string
	}{
		{"distinct", "child-session", "child-thread", "child-session", "child-thread"},
		{"missing session", "", "child-thread", "parent-cache", "child-thread"},
		{"missing thread", "child-session", "", "child-session", "parent-cache"},
		{"missing both", "", "", "parent-cache", "parent-cache"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := http.Header{}
			const ua = "codex_exec/0.162.1 (Linux 6.8.0; x86_64) terminal"
			h.Set("User-Agent", ua)
			h.Set("originator", "codex_exec")
			h.Set("version", "0.162.1")
			h.Set("session-id", c.session)
			h.Set("thread-id", c.thread)
			ctx := CodexClientRequest(context.Background(), h)
			h["User-Agent"][0] = "changed-after-snapshot"
			h.Set("version", "8.8.8")
			h.Set("session-id", "changed-after-snapshot")
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, CodexBase+"/responses", nil)
			req.Header.Set("OpenAI-Beta", "not-sent-by-client")
			sign := codexSign(func(context.Context) (string, string, error) { return "token", "account", nil })
			if err := sign(ctx, req, []byte(`{"prompt_cache_key":"parent-cache"}`)); err != nil {
				t.Fatal(err)
			}
			if req.Header.Get("User-Agent") != ua || req.Header.Get("originator") != "codex_exec" || req.Header.Get("version") != "0.162.1" {
				t.Errorf("client identity changed: %v", req.Header)
			}
			if req.Header.Get("session-id") != c.wantSession || req.Header.Get("thread-id") != c.wantThread {
				t.Errorf("client session/thread changed: %v", req.Header)
			}
			if req.Header.Get("OpenAI-Beta") != "" {
				t.Error("a beta the client did not send was added")
			}
			if req.Header.Get("Accept") != "" {
				t.Error("a response format the client did not send was added")
			}
			req.Header["User-Agent"][0] = "changed-by-first-attempt"
			retry, _ := http.NewRequestWithContext(ctx, http.MethodPost, CodexBase+"/responses", nil)
			if err := sign(ctx, retry, []byte(`{"prompt_cache_key":"parent-cache"}`)); err != nil {
				t.Fatal(err)
			}
			if retry.Header.Get("User-Agent") != ua {
				t.Error("an earlier attempt changed the saved client identity")
			}
		})
	}
}

// The sender's identity alone cannot identify a translated or locally
// rebuilt request. An explicit generated source keeps the account's
// existing preparation even when it is asked to use the client's headers.
func TestCodexRequestSourceSeparatesBuiltPayload(t *testing.T) {
	p := Provider{Account: &Account{Agent: "codex", body: codexBody}}
	h := http.Header{"User-Agent": {"codex_cli_rs/0.162.1"}, "Originator": {"codex_cli_rs"}}
	ctx := CodexClientRequest(context.Background(), h)
	for _, body := range []string{
		`{"model":"gpt-5.5","input":[{"type":"message","id":"msg_base","role":"developer","content":"client instructions"}],"stream":true,"reasoning":{"effort":"low"}}`,
		`{"model":"gpt-5.5","input":[],"stream":true,"reasoning":{"effort":"none"},"include":["output.encrypted_content"]}`,
		`{"model":"gpt-5.5","input":[],"stream":true,"reasoning":{"effort":16},"parallel_tool_calls":false}`,
		`{"model":"gpt-5.5","instructions":"Custom legacy instructions","input":[],"stream":true}`,
	} {
		if got := p.PrepareFrom(ctx, []byte(body)); string(got) != body {
			t.Errorf("native payload changed: %s", got)
		}
	}
	ctx = CodexRequestSource{}.Context(ctx)
	ctx = CodexClientRequest(ctx, h)
	got := p.PrepareFrom(ctx, []byte(`{"model":"gpt-5.5","instructions":"Client instructions","input":"hello","stream":false}`))
	if !strings.Contains(string(got), `"stream":true`) || !strings.Contains(string(got), `"tool_choice":"auto"`) || !strings.Contains(string(got), `"text":{"verbosity":"medium"}`) {
		t.Errorf("a generated request skipped preparation: %s", got)
	}
	other := Provider{Account: &Account{Agent: "other", body: func([]byte) []byte { return []byte("other account") }}}
	if got := string(other.PrepareFrom(CodexClientRequest(context.Background(), h), nil)); got != "other account" {
		t.Errorf("another account's preparation changed: %q", got)
	}
}
