package gateway

import "testing"

// Codex serializes model and stream before input so a backend can route a
// large request without reading its whole conversation first. Adding the
// pool's namespace and removing it must not reorder or re-encode the body.
func TestWithModelKeepsNativeBytes(t *testing.T) {
	for _, c := range []struct {
		name, body, model, want string
	}{
		{
			"routing fields first",
			`{ "model" : "codex/gpt-5.5", "stream" : true, "input" : [{"text":"<context>&literal\u0041"}], "n" : 10000000000000000001, "ratio" : 1.2300e+04 }`,
			"gpt-5.5",
			`{ "model" : "gpt-5.5", "stream" : true, "input" : [{"text":"<context>&literal\u0041"}], "n" : 10000000000000000001, "ratio" : 1.2300e+04 }`,
		},
		{
			"escaped field name",
			`{"mo\u0064el":"a/b", "stream":true, "input":["<&>"], "n":1.00}`,
			"b",
			`{"mo\u0064el":"b", "stream":true, "input":["<&>"], "n":1.00}`,
		},
		{
			"nested model untouched",
			`{"input":[{"model":"nested","model":"nested-again","text":"<&>"}], "model":"a/b"}`,
			"b",
			`{"input":[{"model":"nested","model":"nested-again","text":"<&>"}], "model":"b"}`,
		},
		{
			"unchanged value",
			"\n{ \"model\" : \"same\", \"input\" : [\"<&>\"] }\n",
			"same",
			"\n{ \"model\" : \"same\", \"input\" : [\"<&>\"] }\n",
		},
		{
			"replacement escaped",
			`{ "model":"old", "input":["<&>"] }`,
			`a"b`,
			`{ "model":"a\"b", "input":["<&>"] }`,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := string(withModel([]byte(c.body), c.model)); got != c.want {
				t.Errorf("model replacement changed other JSON bytes:\ngot  %s\nwant %s", got, c.want)
			}
		})
	}
}

// An ambiguous model cannot use a first-match byte replacement: encoding/json
// reads the last field, including differently cased or escaped spellings.
// Keep the old object rewrite for these envelopes and for absent/non-string
// fields, and leave malformed JSON to the request validator as before.
func TestWithModelKeepsEnvelopeFallback(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"duplicate", `{"model":"a","model":"b","input":[]}`, `{"input":[],"model":"picked"}`},
		{"same-value duplicate", `{"model":"picked","model":"b","input":[]}`, `{"input":[],"model":"picked"}`},
		{"escaped duplicate", `{"model":"a","mo\u0064el":"b","n":1.00}`, `{"model":"picked","n":1.00}`},
		{"case alias", `{"model":"a","MODEL":"b","input":[]}`, `{"MODEL":"b","input":[],"model":"picked"}`},
		{"alias only", `{"MODEL":"a","input":[]}`, `{"MODEL":"a","input":[],"model":"picked"}`},
		{"non-string duplicate", `{"model":1,"model":"b","input":[]}`, `{"input":[],"model":"picked"}`},
		{"non-string last", `{"model":"a","model":1,"input":[]}`, `{"input":[],"model":"picked"}`},
		{"missing", `{"input":[]}`, `{"input":[],"model":"picked"}`},
		{"number", `{"model":1,"input":[]}`, `{"input":[],"model":"picked"}`},
		{"null value", `{"model":null,"input":[]}`, `{"input":[],"model":"picked"}`},
		{"incomplete JSON", `{"model":"a","input":[`, `{"model":"a","input":[`},
		{"trailing JSON", `{"model":"a"} {"model":"b"}`, `{"model":"a"} {"model":"b"}`},
		{"array", `[{"model":"a"}]`, `[{"model":"a"}]`},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := string(withModel([]byte(c.body), "picked"))
			if got != c.want {
				t.Errorf("envelope rewrite changed:\ngot  %s\nwant %s", got, c.want)
			}
			if c.name == "duplicate" || c.name == "same-value duplicate" || c.name == "escaped duplicate" || c.name == "case alias" {
				if got := modelOf([]byte(got)); got != "picked" {
					t.Errorf("another model field overrode the chosen route: %q", got)
				}
			}
		})
	}
}
