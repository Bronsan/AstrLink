package agentmcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/astrlink/core/contract"
	"github.com/QuantumNous/astrlink/core/internal/controlapi"
	storage "github.com/QuantumNous/astrlink/core/internal/storage"
	"github.com/QuantumNous/astrlink/core/internal/storage/sqlite"
)

const (
	mcpRawOperatorToken = "mcp-raw-operator-token"
	mcpRawObserverToken = "mcp-raw-observer-token"
	mcpRawPassword      = "correct horse battery"
	mcpRawRequestID     = "request_mcp_raw"
	mcpRawMarker        = "privacy-MARKER@example.com"
)

// mcpRawVault accepts one fixed password and seals nothing, so raw parts
// stay readable with the audit key once a grant is approved.
type mcpRawVault struct {
	mu     sync.Mutex
	status controlapi.RawVaultStatus
}

type mcpRawOpener struct{}

func (mcpRawOpener) OpenBlobKey(storage.AuditBlob) ([]byte, error) {
	return nil, errors.New("mcp test vault seals nothing")
}

func (vault *mcpRawVault) Status(context.Context) (controlapi.RawVaultStatus, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	return vault.status, nil
}

func (vault *mcpRawVault) UnlockedOpener() (controlapi.RawKeyOpener, bool) { return nil, false }

func (vault *mcpRawVault) WithProof(_ context.Context, proof controlapi.RawProof, use func(controlapi.RawKeyOpener) error) error {
	if string(proof.Password) != mcpRawPassword {
		return controlapi.ErrRawPasswordInvalid
	}
	return use(mcpRawOpener{})
}

type mcpRawFixture struct {
	store  *sqlite.Store
	vault  *mcpRawVault
	server *httptest.Server
	client *Client
}

// newMCPRawFixture serves the real Control API over one redacted request:
// the client's request body is raw, the upstream body carries a placeholder.
func newMCPRawFixture(t *testing.T) mcpRawFixture {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "astrlink.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	key, err := store.GetOrCreateAuditKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	decision := contract.PrivacyDecisionRedact
	if err := store.InsertRequestRecord(ctx, contract.RequestRecord{
		ID: mcpRawRequestID, StartedAt: time.Now().UTC(), Status: contract.RequestStatusSucceeded,
		InputProtocol:   contract.ProtocolOpenAIChat,
		Audit:           contract.AuditRecordSummary{RequestBodyCaptured: true, UpstreamRequestBodyCaptured: true},
		PrivacyDecision: &decision,
		PrivacyFindings: []contract.PrivacyFinding{{Kind: contract.CanonicalKindEmail, JSONPath: "/messages/0/content", Count: 1}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, part := range []struct {
		direction storage.AuditDirection
		exposure  storage.AuditExposure
		plain     string
	}{
		{storage.AuditDirectionRequest, storage.AuditExposureRaw, `{"content":"mail ` + mcpRawMarker + `"}`},
		{storage.AuditDirectionUpstreamRequest, storage.AuditExposureShareable, `{"content":"mail <EMAIL_1>"}`},
	} {
		nonce, ciphertext, err := storage.SealAuditBlob(key, []byte(part.plain))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.InsertAuditBlob(ctx, storage.AuditBlob{
			RequestID: mcpRawRequestID, Direction: part.direction, MediaType: "application/json",
			Nonce: nonce, Ciphertext: ciphertext, CapturedBytes: len(part.plain), Exposure: part.exposure,
		}); err != nil {
			t.Fatal(err)
		}
	}
	vault := &mcpRawVault{status: controlapi.RawVaultStatus{Configured: true, PasswordSet: true}}
	handler, err := controlapi.NewWithDependencies(contract.DefaultVersionResponse("0.1.0-test", "abc1234"), controlapi.Dependencies{
		ServiceStore:   store,
		RequestRecords: store,
		AuditSettings:  store,
		AuditKeys:      store,
		AuditBlobs:     store,
		RawVault:       vault,
		ControlToken:   mcpRawOperatorToken,
		ObserverToken:  mcpRawObserverToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := Dial(DialOptions{ControlURL: server.URL, ControlToken: mcpRawObserverToken})
	if err != nil {
		t.Fatal(err)
	}
	return mcpRawFixture{store: store, vault: vault, server: server, client: client}
}

// operator calls the Control API as the desktop.
func (fixture mcpRawFixture) operator(t *testing.T, method, path, body string) (int, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequest(method, fixture.server.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+mcpRawOperatorToken)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var decoded map[string]any
	_ = json.NewDecoder(response.Body).Decode(&decoded)
	return response.StatusCode, decoded
}

func (fixture mcpRawFixture) decide(t *testing.T, grantID, body string) {
	t.Helper()
	if status, decoded := fixture.operator(t, http.MethodPost, controlapi.RawAccessPath+"/"+grantID+"/decision", body); status != http.StatusOK {
		t.Fatalf("decision status=%d body=%v", status, decoded)
	}
}

func rawAuditCall(t *testing.T, client *Client, arguments map[string]any) (map[string]any, string, error) {
	t.Helper()
	raw, err := callTool(context.Background(), client, "request_raw_audit", arguments)
	if err != nil {
		return nil, "", err
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded, string(raw), nil
}

func auditPart(t *testing.T, wrapped map[string]any, name string) map[string]any {
	t.Helper()
	part, ok := wrapped["audit"].(map[string]any)[name].(map[string]any)
	if !ok {
		t.Fatalf("%s missing from %v", name, wrapped)
	}
	return part
}

func TestGetRequestAuditReturnsShareableParts(t *testing.T) {
	fixture := newMCPRawFixture(t)
	raw, err := callTool(context.Background(), fixture.client, "get_request_audit", map[string]any{"id": mcpRawRequestID})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(mcpRawMarker)) {
		t.Fatal("shareable audit leaked the marked value")
	}
	var wrapped map[string]any
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		t.Fatal(err)
	}
	if wrapped["content_view"] != "shareable" || wrapped["bodies_captured"] != true {
		t.Fatalf("wrapper=%v", wrapped)
	}
	request := auditPart(t, wrapped, "request_body")
	if request["content_view"] != "withheld" || request["reason"] != "privacy_redacted" ||
		request["raw_available"] != true || request["reason_detail"] == nil {
		t.Fatalf("request_body=%v", request)
	}
	if _, hasContent := request["content"]; hasContent {
		t.Fatalf("withheld part carries content: %v", request)
	}
	upstream := auditPart(t, wrapped, "upstream_request_body")
	if upstream["content_view"] != "shareable" || !strings.Contains(upstream["content"].(string), "<EMAIL_1>") {
		t.Fatalf("upstream_request_body=%v", upstream)
	}
	if !strings.Contains(wrapped["hint"].(string), "request_raw_audit") {
		t.Fatalf("hint=%v", wrapped["hint"])
	}
	if findings := wrapped["audit"].(map[string]any)["privacy_findings"].([]any); len(findings) != 1 {
		t.Fatalf("privacy_findings=%v", findings)
	}

	// Without raw sealing the agent is told not to ask.
	fixture.vault.mu.Lock()
	fixture.vault.status = controlapi.RawVaultStatus{}
	fixture.vault.mu.Unlock()
	raw, err = callTool(context.Background(), fixture.client, "get_request_audit", map[string]any{"id": mcpRawRequestID})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		t.Fatal(err)
	}
	if auditPart(t, wrapped, "request_body")["raw_available"] != false ||
		!strings.Contains(wrapped["hint"].(string), "Do not call request_raw_audit") {
		t.Fatalf("unavailable wrapper=%v", wrapped)
	}
	if _, _, err := rawAuditCall(t, fixture.client, map[string]any{"request_id": mcpRawRequestID, "reason": "debug"}); err == nil ||
		!strings.HasPrefix(err.Error(), "raw_access_unavailable") {
		t.Fatalf("unavailable err=%v", err)
	}
}

func TestRequestRawAuditApprovalFlow(t *testing.T) {
	fixture := newMCPRawFixture(t)
	arguments := map[string]any{"request_id": mcpRawRequestID, "reason": "the upstream rejected the email field"}

	first, text, err := rawAuditCall(t, fixture.client, arguments)
	if err != nil {
		t.Fatal(err)
	}
	if first["status"] != "approval_required" || strings.Contains(text, "grant_token") ||
		strings.Contains(text, fixture.client.rawToken(mcpRawRequestID)) {
		t.Fatalf("first call=%s", text)
	}
	grantID := first["grant_id"].(string)
	if pending, _, err := rawAuditCall(t, fixture.client, arguments); err != nil || pending["status"] != "pending" {
		t.Fatalf("pending=%v err=%v", pending, err)
	}

	fixture.decide(t, grantID, `{"decision":"once","proof":{"password":"`+mcpRawPassword+`"}}`)
	approved, text, err := rawAuditCall(t, fixture.client, arguments)
	if err != nil {
		t.Fatal(err)
	}
	if approved["status"] != "approved" || approved["content_view"] != "raw" || !strings.Contains(text, mcpRawMarker) {
		t.Fatalf("approved=%s", text)
	}
	if part := auditPart(t, approved, "request_body"); part["content_view"] != "raw" {
		t.Fatalf("raw request_body=%v", part)
	}
	if part := auditPart(t, approved, "upstream_request_body"); part["content_view"] != "shareable" {
		t.Fatalf("raw upstream_request_body=%v", part)
	}

	// A once grant is spent: the next call files a new request.
	again, _, err := rawAuditCall(t, fixture.client, arguments)
	if err != nil {
		t.Fatal(err)
	}
	if again["status"] != "approval_required" || again["grant_id"] == grantID {
		t.Fatalf("after once=%v", again)
	}

	fixture.decide(t, again["grant_id"].(string), `{"decision":"deny"}`)
	if _, _, err := rawAuditCall(t, fixture.client, arguments); err == nil || !strings.HasPrefix(err.Error(), "raw_access_denied") {
		t.Fatalf("denied err=%v", err)
	}

	// An approved grant stops working once the user turns agent access off.
	window, _, err := rawAuditCall(t, fixture.client, arguments)
	if err != nil {
		t.Fatal(err)
	}
	fixture.decide(t, window["grant_id"].(string), `{"decision":"window_15m","proof":{"password":"`+mcpRawPassword+`"}}`)
	settings, err := fixture.store.GetAuditSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	settings.AgentRawAccessEnabled = false
	if err := fixture.store.UpdateAuditSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, _, err := rawAuditCall(t, fixture.client, arguments); err == nil || !strings.HasPrefix(err.Error(), "raw_access_disabled") {
			t.Fatalf("disabled err=%v", err)
		}
		if fixture.client.rawToken(mcpRawRequestID) != "" {
			t.Fatal("the grant token was kept after raw access was turned off")
		}
	}

	if _, _, err := rawAuditCall(t, fixture.client, map[string]any{"request_id": mcpRawRequestID}); err == nil {
		t.Fatal("missing reason accepted")
	}
	if _, _, err := rawAuditCall(t, fixture.client, map[string]any{
		"request_id": mcpRawRequestID, "reason": strings.Repeat("x", maxRawReasonRunes+1),
	}); err == nil {
		t.Fatal("oversized reason accepted")
	}
}

func TestRequestRawAuditNamesTheMCPClient(t *testing.T) {
	fixture := newMCPRawFixture(t)
	stdin, input := io.Pipe()
	output := &bytes.Buffer{}
	done := make(chan error, 1)
	go func() {
		done <- ServeStdio(context.Background(), &Server{Client: fixture.client}, stdin, output)
	}()
	writeRPC(t, input, 1, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"clientInfo":      map[string]any{"name": "claude-code", "version": "1"},
	})
	writeRPC(t, input, 2, "tools/call", map[string]any{
		"name":      "request_raw_audit",
		"arguments": map[string]any{"request_id": mcpRawRequestID, "reason": "debug"},
	})
	_ = input.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if call := callResult(t, readAllResponses(t, output)[2]); call["isError"] == true {
		t.Fatalf("request_raw_audit=%v", call)
	}
	status, list := fixture.operator(t, http.MethodGet, controlapi.RawAccessPath, "")
	items, _ := list["items"].([]any)
	if status != http.StatusOK || len(items) != 1 || items[0].(map[string]any)["client_name"] != "claude-code" {
		t.Fatalf("pending list status=%d body=%v", status, list)
	}
}
