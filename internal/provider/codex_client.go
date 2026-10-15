package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/tidwall/gjson"
)

// CodexRequestSource describes the payload being sent, not just who called
// magpie. Its zero value is a request magpie built. A relayed Codex payload
// keeps a snapshot of its client's headers, never the client's credentials.
// The same source controls body preparation and signing, so a translation
// cannot claim the identity of a request whose shape it no longer carries.
type CodexRequestSource struct {
	head http.Header
}

type codexRequestSourceKey struct{}

// Context applies this source to one outbound request. A rebuilt request
// uses the zero source even when its caller was Codex. It is not a property
// of the caller, account, or conversation.
func (s CodexRequestSource) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, codexRequestSourceKey{}, s)
}

// CodexClientRequest marks an outbound payload that still carries Codex's
// own request shape. The gateway calls it only at a relay boundary, not
// at ingress or after an IR build. An explicitly rebuilt source takes
// precedence, including when a local compaction reuses the caller's headers.
func CodexClientRequest(ctx context.Context, h http.Header) context.Context {
	if _, explicit := ctx.Value(codexRequestSourceKey{}).(CodexRequestSource); explicit {
		return ctx
	}
	s := CodexRequestSource{head: http.Header{}}
	for k, vs := range h {
		if codexIdentityHeader(k) {
			s.head[http.CanonicalHeaderKey(k)] = slices.Clone(vs)
		}
	}
	return s.Context(ctx)
}

func codexSource(ctx context.Context) CodexRequestSource {
	s, _ := ctx.Value(codexRequestSourceKey{}).(CodexRequestSource)
	return s
}

// PrepareFrom fits a generated payload to its account, but preserves a
// Codex payload already built by that client: instructions may be input
// items, and the omitted parameters, IDs and Lite tools are meaningful.
// The account's existing tier restriction still holds, and a replayed web
// search still needs its declaration, as on the native relay.
func (p Provider) PrepareFrom(ctx context.Context, body []byte) []byte {
	if p.Account != nil && p.Account.Agent == "codex" {
		if src := codexSource(ctx); src.head != nil {
			if tier := gjson.GetBytes(body, "service_tier"); tier.Exists() && !codexTier(tier.Str) {
				var q map[string]json.RawMessage
				if json.Unmarshal(body, &q) == nil && q != nil {
					delete(q, "service_tier")
					if b, err := json.Marshal(q); err == nil {
						body = b
					}
				}
			}
			return DeclareSearch(body, strings.EqualFold(src.head.Get("X-OpenAI-Internal-Codex-Responses-Lite"), "true"))
		}
	}
	return p.Prepare(body)
}

func codexIdentityHeader(k string) bool {
	switch strings.ToLower(k) {
	case "user-agent", "originator", "version", "openai-beta", "accept",
		"session-id", "thread-id", "session_id", "conversation_id",
		"x-openai-internal-codex-responses-lite":
		return true
	}
	return false
}

// put restores the client's own header values, including deliberate
// omissions. It cannot restore an account's credentials: none were saved.
func (s CodexRequestSource) put(h http.Header) {
	for k := range h {
		if codexIdentityHeader(k) {
			delete(h, k)
		}
	}
	for k, vs := range s.head {
		h[k] = slices.Clone(vs)
	}
}

func (s CodexRequestSource) sessionHeaders(h http.Header, body []byte) {
	session, thread := h.Get("session-id"), h.Get("thread-id")
	if session == "" {
		session = h.Get("session_id")
	}
	if thread == "" {
		thread = h.Get("conversation_id")
	}
	sessionHeaders(h, body)
	if session != "" {
		h.Set("session-id", session)
	}
	if thread != "" {
		h.Set("thread-id", thread)
	}
}

// A translated request may still have the caller's Lite header, although
// its tools are now top-level functions and its reasoning no longer names
// all turns. Only keep that header when the final payload has Lite's shape.
func codexLiteBody(body []byte) bool {
	if gjson.GetBytes(body, "reasoning.context").Str == "all_turns" {
		return true
	}
	for _, item := range gjson.GetBytes(body, "input").Array() {
		if item.Get("type").Str == "additional_tools" {
			return true
		}
	}
	return false
}

// clearCodexAccount removes the previous signer before another account
// signs, even if its new token has no account id. Device attestation and
// backend turn routing belong to that previous sign-in and are not proof
// for this account. Other caller credentials, including gateway keys and
// cookies, are not this account's either. Match every header spelling.
func clearCodexAccount(h http.Header) {
	for k := range h {
		name := strings.ToLower(k)
		if strings.Contains(name, "authorization") || name == "chatgpt-account-id" ||
			name == "x-api-key" || name == "api-key" || name == "x-goog-api-key" || name == "cookie" ||
			name == "x-oai-attestation" || name == "x-codex-turn-state" || name == "x-openai-codex-luna-reserve" {
			delete(h, k)
		}
	}
}
