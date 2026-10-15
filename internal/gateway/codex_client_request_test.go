package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/yetone/magpie/internal/provider"
)

// codexClientBody follows openai/codex 8094365e6's build_responses_request:
// base instructions are a developer input item, not a top-level field;
// Lite tools are another input item, and omitted summary/text stay omitted.
// The request's shape, rather than generated wording, is the fixture here.
const codexClientBody = `{
  "model":"gpt-5.5","stream":true,"store":false,
  "input":[
    {"type":"additional_tools","id":"at_tools","role":"developer","tools":[{"type":"namespace","name":"functions","description":"Tools","tools":[{"type":"function","name":"echo","description":"Echo text","parameters":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"],"additionalProperties":false},"strict":false}]}]},
    {"type":"message","id":"msg_base","role":"developer","content":[{"type":"input_text","text":"You are Codex. Keep the client's instructions."}],"internal_chat_message_metadata_passthrough":{"content_item_kinds":["model.base_instructions"]}},
    {"type":"message","id":"msg_user","role":"user","content":[{"type":"input_text","text":"Reply pong."}]}
  ],
  "tool_choice":"auto","parallel_tool_calls":false,
  "reasoning":{"effort":"low","context":"all_turns"},
  "include":["reasoning.encrypted_content","output.encrypted_content"],
  "stream_options":{"reasoning_summary_delivery":"sequential_cutoff"},
  "prompt_cache_key":"parent-cache",
  "client_metadata":{"x-codex-turn-metadata":"{\"session_id\":\"child-session\",\"turn_id\":\"turn-1\"}"},
  "access_programs":{"cyber":"daybreak_blue"}
}`

func codexClientHead() http.Header {
	h := http.Header{}
	for k, v := range map[string]string{
		"User-Agent": "codex_exec/0.162.1 (Linux 6.8.0; x86_64) test-terminal",
		"originator": "codex_exec", "version": "0.162.1",
		"session-id": "child-session", "thread-id": "child-thread",
		"OpenAI-Beta": "responses=experimental", "Accept": "text/event-stream",
		"X-OpenAI-Internal-Codex-Responses-Lite": "true",
		"X-Codex-Turn-Metadata":                  `{"session_id":"child-session","turn_id":"turn-1"}`,
		"Authorization":                          "Bearer original-token",
		"chatgpt-account-id":                     "original-account",
		"x-openai-actor-authorization":           "original-actor",
		"x-oai-attestation":                      "original-attestation",
		"x-codex-turn-state":                     "original-route",
		"x-openai-codex-luna-reserve":            "1",
		"X-Api-Key":                              "original-gateway-key",
		"X-Goog-Api-Key":                         "original-google-key",
		"api-key":                                "original-api-key",
		"Cookie":                                 "session=original-cookie",
	} {
		h.Set(k, v)
	}
	return h
}

type codexClientCall struct {
	path, query string
	head        http.Header
	body        []byte
}

type codexClientBackend struct {
	mu    sync.Mutex
	calls []codexClientCall
	first func(http.ResponseWriter, codexClientCall) bool
}

func (b *codexClientBackend) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "not a turn", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err == nil && r.Header.Get("Content-Encoding") == "zstd" {
		var d *zstd.Decoder
		d, err = zstd.NewReader(nil)
		if err == nil {
			body, err = d.DecodeAll(body, nil)
			d.Close()
		}
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	call := codexClientCall{path: r.URL.Path, query: r.URL.RawQuery, head: r.Header.Clone(), body: body}
	b.mu.Lock()
	b.calls = append(b.calls, call)
	b.mu.Unlock()
	if b.first != nil && b.first(w, call) {
		return
	}
	if strings.HasSuffix(r.URL.Path, AlphaSearchPath) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"output":"found","encrypted_output":null}`)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/compact") {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"output":[{"type":"compaction","encrypted_content":"gAAAAAcompact"}]}`)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	io.WriteString(w, sse(
		`data: {"type":"response.created","response":{"id":"resp_1","model":"gpt-5.5","status":"in_progress","output":[]}}`,
		`data: {"type":"response.output_text.delta","delta":"pong"}`,
		`data: {"type":"response.output_item.done","output_index":0,"item":{"type":"message","id":"msg_reply","role":"assistant","content":[{"type":"output_text","text":"pong"}]}}`,
		`data: {"type":"response.completed","response":{"id":"resp_1","model":"gpt-5.5","status":"completed","output":[],"usage":{"input_tokens":5,"output_tokens":1}}}`,
	))
}

func (b *codexClientBackend) take() []codexClientCall {
	b.mu.Lock()
	defer b.mu.Unlock()
	calls := b.calls
	b.calls = nil
	return calls
}

func codexClientUpstream(t *testing.T, b *codexClientBackend) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(b.serve))
	t.Cleanup(up.Close)
	was := provider.CodexBase
	provider.CodexBase = up.URL + CodexPath
	t.Cleanup(func() { provider.CodexBase = was })
}

func postCodexClient(h http.Handler, path string, body []byte, head http.Header) *httptest.ResponseRecorder {
	if strings.EqualFold(head.Get("Content-Encoding"), "zstd") {
		enc, _ := zstd.NewWriter(nil)
		body = enc.EncodeAll(body, nil)
		enc.Close()
	}
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
	r.Header = head.Clone()
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func sameCodexBody(t *testing.T, got, want []byte) {
	t.Helper()
	var a, b map[string]any
	if json.Unmarshal(got, &a) != nil || json.Unmarshal(want, &b) != nil {
		t.Fatalf("invalid request JSON: got %s, want %s", got, want)
	}
	for k, v := range b {
		if !reflect.DeepEqual(a[k], v) {
			t.Errorf("Codex request field %q changed", k)
		}
	}
	for k := range a {
		if _, had := b[k]; !had {
			t.Errorf("Codex request gained the omitted field %q", k)
		}
	}
}

func sameCodexClient(t *testing.T, got, want http.Header) {
	t.Helper()
	for _, k := range []string{"User-Agent", "originator", "version", "session-id", "thread-id", "OpenAI-Beta", "X-OpenAI-Internal-Codex-Responses-Lite", "X-Codex-Turn-Metadata"} {
		if got.Get(k) != want.Get(k) {
			t.Errorf("Codex %s changed: got %q, want %q", k, got.Get(k), want.Get(k))
		}
	}
	for _, k := range []string{"x-openai-actor-authorization", "x-oai-attestation", "x-codex-turn-state", "x-openai-codex-luna-reserve", "x-api-key", "x-goog-api-key", "api-key", "cookie"} {
		if got.Get(k) != "" {
			t.Errorf("the previous account's %s was sent", k)
		}
	}
}

// Routing through the account pool must not reinterpret a request Codex
// already built. Both entrypoints and a second account receive its fields,
// omissions and client identity, with only their own credentials.
func TestCodexClientPoolKeepsRequest(t *testing.T) {
	for _, path := range []string{CodexPath + "/responses", "/v1/responses"} {
		t.Run(path, func(t *testing.T) {
			codexSignedIn(t, "spare@example.com")
			zstdTurns(t)
			backend := &codexClientBackend{first: func(w http.ResponseWriter, c codexClientCall) bool {
				if c.head.Get("chatgpt-account-id") != "acct-1" {
					return false
				}
				w.WriteHeader(http.StatusTooManyRequests)
				io.WriteString(w, `{"error":{"type":"usage_limit_reached","message":"The usage limit has been reached","resets_in_seconds":3600}}`)
				return true
			}}
			codexClientUpstream(t, backend)
			body := []byte(codexClientBody)
			if path == "/v1/responses" {
				body = withModel(body, "codex/gpt-5.5")
			}
			head := codexClientHead()
			w := postCodexClient(New().Handler(), path, body, head)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "pong") {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			calls := backend.take()
			if len(calls) != 2 {
				t.Fatalf("asked %d times, want first account then spare", len(calls))
			}
			for i, call := range calls {
				sameCodexBody(t, call.body, []byte(codexClientBody))
				sameCodexClient(t, call.head, head)
				if call.head.Get("Content-Encoding") != "zstd" {
					t.Error("Codex turn was not compressed")
				}
				wantAccount := []string{"acct-1", "acct-2"}[i]
				if call.head.Get("chatgpt-account-id") != wantAccount || call.head.Get("Authorization") == head.Get("Authorization") {
					t.Errorf("attempt %d did not use %s's own credentials", i, wantAccount)
				}
			}
		})
	}
}

// These inputs came from a real Codex binary against an offline fake
// backend, including its custom/namespace tools and literal metadata.
func TestCodexClientCapturedRequests(t *testing.T) {
	for _, name := range []string{"responses", "responses-lite"} {
		for _, path := range []string{CodexPath + "/responses", "/v1/responses"} {
			t.Run(name+path, func(t *testing.T) {
				codexSignedIn(t, "spare@example.com")
				zstdTurns(t)
				backend := &codexClientBackend{}
				codexClientUpstream(t, backend)
				base := "testdata/codex-client/0.162.1-" + name
				body, err := os.ReadFile(base + ".json")
				if err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(base + "-headers.json")
				if err != nil {
					t.Fatal(err)
				}
				var captured struct {
					Headers map[string]string `json:"headers"`
				}
				if err := json.Unmarshal(raw, &captured); err != nil {
					t.Fatal(err)
				}
				head := http.Header{}
				for k, v := range captured.Headers {
					head.Set(k, v)
				}
				head.Set("Authorization", "Bearer offline-capture")
				sent := body
				if path == "/v1/responses" {
					sent = withModel(sent, "codex/gpt-5.5")
				}
				w := postCodexClient(New().Handler(), path, sent, head)
				if w.Code != http.StatusOK {
					t.Fatalf("%d %s", w.Code, w.Body.String())
				}
				calls := backend.take()
				if len(calls) != 1 {
					t.Fatalf("asked %d times", len(calls))
				}
				sameCodexBody(t, calls[0].body, body)
				if !bytes.Equal(calls[0].body, body) {
					t.Errorf("native Codex bytes changed after routing: got %d bytes, want %d; model/stream field order and original escaping must survive", len(calls[0].body), len(body))
				}
				sameCodexClient(t, calls[0].head, head)
				for k, want := range captured.Headers {
					if k != "chatgpt-account-id" && calls[0].head.Get(k) != want {
						t.Errorf("captured %s changed: got %q, want %q", k, calls[0].head.Get(k), want)
					}
				}
			})
		}
	}
}

func TestCodexClientParametersStayNative(t *testing.T) {
	for _, c := range []struct {
		name   string
		fields map[string]any
		want   map[string]any
	}{
		{"legacy instructions", map[string]any{"instructions": "You are Codex. Custom legacy instructions."}, map[string]any{"instructions": "You are Codex. Custom legacy instructions."}},
		{"numeric effort", map[string]any{"reasoning": map[string]any{"effort": 16}}, map[string]any{"reasoning": map[string]any{"effort": 16}}},
		// The subscription backend's existing constraint is independent of
		// request ownership: unsupported tiers still stay out, while the
		// rest of the client's native request and headers remain intact.
		{"unsupported subscription tier", map[string]any{"service_tier": "flex"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			codexSignedIn(t)
			backend := &codexClientBackend{}
			codexClientUpstream(t, backend)
			body := withFields(withModel([]byte(codexClientBody), "codex/gpt-5.5"), c.fields)
			w := postCodexClient(New().Handler(), "/v1/responses", body, codexClientHead())
			if w.Code != http.StatusOK {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			calls := backend.take()
			if len(calls) != 1 {
				t.Fatalf("asked %d times", len(calls))
			}
			sameCodexBody(t, calls[0].body, withFields([]byte(codexClientBody), c.want))
			sameCodexClient(t, calls[0].head, codexClientHead())
		})
	}
}

// Search and native /responses/compact keep their own payloads and client
// identity when an account in the pool signs them. Compaction cannot carry
// the old account's device proof or turn routing to the replacement account.
func TestCodexClientSearchAndCompactKeepIdentity(t *testing.T) {
	for _, compact := range []bool{false, true} {
		name := "search"
		if compact {
			name = "compact"
		}
		t.Run(name, func(t *testing.T) {
			codexSignedIn(t, "spare@example.com")
			if err := provider.SetLoginOn("codex", "me@example.com", false); err != nil {
				t.Fatal(err)
			}
			backend := &codexClientBackend{}
			codexClientUpstream(t, backend)
			head := codexClientHead()
			head.Set("Accept", "application/json")
			path, body := "/v1"+AlphaSearchPath, []byte(codexSearchBody("codex/gpt-5.5"))
			if compact {
				path, body = CodexPath+"/responses/compact", []byte(`{"model":"gpt-5.5","input":[{"type":"message","id":"msg_user","role":"user","content":"summarize"}]}`)
			}
			const query = "key=caller-query&trace=a%2fb&%6bey=encoded-caller-query&tag=1&tag=2"
			req := httptest.NewRequest(http.MethodPost, path+"?"+query, strings.NewReader(string(body)))
			req.Header = head.Clone()
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			New().Handler().ServeHTTP(w, req)
			if req.URL.RawQuery != query {
				t.Error("re-signing changed the incoming request's query")
			}
			if w.Code != http.StatusOK {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			calls := backend.take()
			if len(calls) != 1 {
				t.Fatalf("asked %d times", len(calls))
			}
			call := calls[0]
			sameCodexClient(t, call.head, head)
			sameCodexBody(t, call.body, withModel(body, "gpt-5.5"))
			wantQuery := "" // search does not forward the incoming query
			if compact {
				wantQuery = "trace=a%2fb&tag=1&tag=2"
			}
			if call.query != wantQuery {
				t.Error("re-signed request retained a caller query key or changed another query field")
			}
			if call.head.Get("chatgpt-account-id") != "acct-2" || call.head.Get("Authorization") == head.Get("Authorization") {
				t.Error("did not use the enabled account's own credentials")
			}
			if call.head.Get("Accept") != "application/json" || call.head.Get("Content-Encoding") != "" {
				t.Errorf("search/compact transport changed: %v", call.head)
			}
		})
	}
}

// One native account's relay does not re-sign the request. In particular,
// its device proof and routing state stay with that same account.
func TestCodexClientSingleAccountStillRelayed(t *testing.T) {
	codexSignedIn(t)
	zstdTurns(t)
	backend := &codexClientBackend{}
	codexClientUpstream(t, backend)
	head := codexClientHead()
	const query = "key=caller-query&trace=a%2fb"
	w := postCodexClient(New().Handler(), CodexPath+"/responses?"+query, []byte(codexClientBody), head)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	calls := backend.take()
	if len(calls) != 1 {
		t.Fatalf("asked %d times", len(calls))
	}
	sameCodexBody(t, calls[0].body, []byte(codexClientBody))
	if calls[0].query != query {
		t.Error("unsigned relay changed the incoming query")
	}
	for k := range head {
		if calls[0].head.Get(k) != head.Get(k) {
			t.Errorf("unsigned relay changed %s", k)
		}
	}
}

// A native client's identity is not a licence to skip preparation after
// parsing its body into the common IR or rebuilding it as a local summary.
func TestCodexClientRebuiltRequestIsPrepared(t *testing.T) {
	for _, c := range []struct {
		name, path string
		body       []byte
	}{
		{"whole Responses", "/v1/responses", withFields(withModel([]byte(codexClientBody), "codex/gpt-5.5"), map[string]any{"stream": false})},
		{"Chat", "/v1/chat/completions", []byte(`{"model":"codex/gpt-5.5","messages":[{"role":"system","content":"Client instructions"},{"role":"user","content":"Reply pong."}],"stream":true}`)},
		{"local summary", "/v1/responses", []byte(`{"model":"codex/gpt-5.5","stream":true,"input":[{"type":"message","id":"msg_base","role":"developer","content":"Client instructions"},{"type":"message","id":"msg_user","role":"user","content":"Reply pong."},{"type":"compaction_trigger"}],"reasoning":{"effort":"low"},"prompt_cache_key":"parent-cache"}`)},
	} {
		t.Run(c.name, func(t *testing.T) {
			codexSignedIn(t)
			backend := &codexClientBackend{}
			codexClientUpstream(t, backend)
			head := codexClientHead()
			w := postCodexClient(New().Handler(), c.path, c.body, head)
			if w.Code != http.StatusOK {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			calls := backend.take()
			if len(calls) != 1 {
				t.Fatalf("asked %d times", len(calls))
			}
			call := calls[0]
			var body map[string]any
			if err := json.Unmarshal(call.body, &body); err != nil {
				t.Fatal(err)
			}
			if body["instructions"] == nil || body["stream"] != true || body["store"] != false || body["tool_choice"] != "auto" {
				t.Error("rebuilt request did not get the account's preparation")
			}
			if strings.Contains(string(call.body), `"id":"msg_base"`) || strings.Contains(string(call.body), `"compaction_trigger"`) {
				t.Error("rebuilt request kept the native input instead of its prepared history")
			}
			if call.head.Get("originator") != "codex_cli_rs" || !strings.HasPrefix(call.head.Get("User-Agent"), "codex_cli_rs/") {
				t.Error("rebuilt request claimed the original client's identity")
			}
			if call.head.Get("X-OpenAI-Internal-Codex-Responses-Lite") != "" {
				t.Error("rebuilt ordinary Responses request still claimed Responses Lite")
			}
		})
	}
}

// A field the backend actually rejects is still repaired, while the retry
// keeps the rest of Codex's request and identity rather than normalizing it.
func TestCodexClientRetryKeepsRequest(t *testing.T) {
	codexSignedIn(t)
	backend := &codexClientBackend{first: func(w http.ResponseWriter, call codexClientCall) bool {
		var body map[string]any
		json.Unmarshal(call.body, &body)
		if body["prompt_cache_options"] == nil {
			return false
		}
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":{"message":"Unsupported parameter: 'prompt_cache_options'.","param":"prompt_cache_options","code":"unsupported_parameter"}}`)
		return true
	}}
	codexClientUpstream(t, backend)
	head := codexClientHead()
	body := withFields(withModel([]byte(codexClientBody), "codex/gpt-5.5"), map[string]any{"prompt_cache_options": map[string]any{"mode": "explicit"}})
	w := postCodexClient(New().Handler(), "/v1/responses", body, head)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	calls := backend.take()
	if len(calls) != 2 {
		t.Fatalf("asked %d times, want refused field then repaired request", len(calls))
	}
	sameCodexBody(t, calls[0].body, withModel(body, "gpt-5.5"))
	sameCodexBody(t, calls[1].body, []byte(codexClientBody))
	for _, call := range calls {
		sameCodexClient(t, call.head, head)
	}
}
