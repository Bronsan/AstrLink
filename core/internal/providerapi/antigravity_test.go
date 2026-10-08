package providerapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"testing"

	"github.com/QuantumNous/astrlink/core/internal/providerapi"
)

func TestAntigravityCatalogOmitsNonChatModels(t *testing.T) {
	var catalog providerapi.AntigravityCatalog
	if err := json.Unmarshal([]byte(`{"models":{
		"":{},"   ":{},"chat_20706":{},"chat_future":{},
		"tab_flash_lite_preview":{},"tab_future":{},
		"gemini-2.5-flash-thinking":{},"gemini-2.5-pro":{},
		"gemini-2.5-flash":{},"gemini-3-flash":{},
		"claude-sonnet-4-6":{},"gpt-oss-120b-medium":{},"future-chat-model":{}
	}}`), &catalog); err != nil {
		t.Fatal(err)
	}
	want := []string{"claude-sonnet-4-6", "future-chat-model", "gemini-2.5-flash", "gemini-2.5-flash-thinking", "gemini-2.5-pro", "gemini-3-flash", "gpt-oss-120b-medium"}
	if got := catalog.IDs(); !slices.Equal(got, want) {
		t.Fatalf("IDs() = %v, want %v", got, want)
	}
}

func antigravityRequestContents(t *testing.T, body string) []map[string]any {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "https://localhost/v1beta/models/claude-opus-4-6-thinking:streamGenerateContent?alt=sse", io.NopCloser(bytes.NewReader([]byte(body))))
	if err != nil {
		t.Fatal(err)
	}
	mode, err := providerapi.AntigravityRequest(request, "test-project")
	if err != nil {
		t.Fatal(err)
	}
	if mode != "stream" {
		t.Fatalf("mode = %q, want stream", mode)
	}
	if request.URL.Path != "/v1internal:streamGenerateContent" || request.URL.RawQuery != "alt=sse" {
		t.Fatalf("path = %q?%q, want /v1internal:streamGenerateContent?alt=sse", request.URL.Path, request.URL.RawQuery)
	}
	sent, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Request struct {
			Contents []map[string]any `json:"contents"`
		} `json:"request"`
	}
	if err := json.Unmarshal(sent, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Request.Contents
}

func partKinds(parts []any) []string {
	kinds := make([]string, 0, len(parts))
	for _, part := range parts {
		object, _ := part.(map[string]any)
		switch {
		case object["functionCall"] != nil:
			kinds = append(kinds, "call")
		case object["functionResponse"] != nil:
			kinds = append(kinds, "resp")
		case object["text"] != nil:
			kinds = append(kinds, "text")
		default:
			kinds = append(kinds, "other")
		}
	}
	return kinds
}

func TestAntigravityReordersMixedModelParts(t *testing.T) {
	contents := antigravityRequestContents(t, `{"contents":[
		{"role":"user","parts":[{"text":"hi"}]},
		{"role":"model","parts":[
			{"functionCall":{"id":"call_1","name":"exec_command","args":{"cmd":"a"}}},
			{"text":"working on it"}]},
		{"role":"user","parts":[
			{"functionResponse":{"id":"call_1","name":"exec_command","response":{"content":"done"}}}]}
	]}`)
	if len(contents) != 3 {
		t.Fatalf("contents = %d entries, want 3", len(contents))
	}
	if got := partKinds(contents[1]["parts"].([]any)); !slices.Equal(got, []string{"text", "call"}) {
		t.Fatalf("mixed model parts = %v, want [text call]", got)
	}
	if got := partKinds(contents[2]["parts"].([]any)); !slices.Equal(got, []string{"resp"}) {
		t.Fatalf("trailing user parts = %v, want [resp]", got)
	}
}

func TestAntigravityLeavesPureCallModelUntouched(t *testing.T) {
	contents := antigravityRequestContents(t, `{"contents":[
		{"role":"user","parts":[{"text":"hi"}]},
		{"role":"model","parts":[
			{"functionCall":{"id":"call_1","name":"exec_command","args":{"cmd":"a"}}}]},
		{"role":"user","parts":[
			{"functionResponse":{"id":"call_1","name":"exec_command","response":{"content":"done"}}}]}
	]}`)
	if got := partKinds(contents[1]["parts"].([]any)); !slices.Equal(got, []string{"call"}) {
		t.Fatalf("pure call model parts = %v, want [call]", got)
	}
	call := contents[1]["parts"].([]any)[0].(map[string]any)["functionCall"].(map[string]any)
	if call["id"] != "call_1" || call["name"] != "exec_command" {
		t.Fatalf("functionCall rewritten to %v", call)
	}
}
