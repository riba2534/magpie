# Codex request fixtures

These are HTTP Responses requests serialized by the real `codex-cli 0.162.1`
binary, captured on 2026-10-16. The JSON bodies are the literal decoded
requests, not a reconstruction from the API schema. The header files omit
Authorization; `acct-offline` and every installation/session identifier are
from the disposable test setup.

The CLI ran in a disposable filesystem and a Linux network namespace with
only loopback, fake authentication, a local model catalog, and a local server
answering a deterministic SSE reply. No real credentials or model endpoint
were used. Working-directory paths in the input are virtual `/capture/...`
paths. Both runs first tried a WebSocket, received 426, then completed over
HTTP with a zstd request and the reply `OFFLINE_CAPTURE_OK`.

The catalog is the `gpt-5.5` entry from `openai/codex` commit `8094365e6`.
`prefer_websockets` was set to false. The standard run set
`use_responses_lite=false`; the Lite run set it to true. Apps, plugins and
telemetry were disabled for the capture.

Both payloads put base instructions in a developer input item and omit the
top-level `instructions` field. They preserve item IDs and omit reasoning
summary. The Lite request puts its tools in an `additional_tools` item,
omits top-level `tools`, sets `parallel_tool_calls=false`, and names
`reasoning.context=all_turns` alongside its Lite header.

`TestCodexClientCapturedRequests` replays these fixtures through both gateway
entrypoints and checks the body and client headers the fake backend gets.
This verifies the gateway's contract with this CLI; it does not establish
compatibility with a live ChatGPT account.
