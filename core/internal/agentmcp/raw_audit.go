package agentmcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/QuantumNous/astrlink/core/internal/controlapi"
)

const (
	maxRawReasonRunes = 500
	maxClientNameLen  = 64
)

// rawGrantTokens holds the raw access grant tokens this MCP process was
// issued, keyed by request id. They live only as long as the stdio process
// and are never returned to the agent.
type rawGrantTokens struct {
	mu     sync.Mutex
	agent  string
	tokens map[string]string
}

// setAgentName records the MCP client's self-reported name. It is shown to
// the user beside each raw access request and authorizes nothing.
func (client *Client) setAgentName(name string) {
	name = strings.TrimSpace(name)
	if len(name) > maxClientNameLen {
		name = strings.ToValidUTF8(name[:maxClientNameLen], "")
	}
	client.raw.mu.Lock()
	client.raw.agent = name
	client.raw.mu.Unlock()
}

func (client *Client) agentName() string {
	client.raw.mu.Lock()
	defer client.raw.mu.Unlock()
	return client.raw.agent
}

func (client *Client) rawToken(requestID string) string {
	client.raw.mu.Lock()
	defer client.raw.mu.Unlock()
	return client.raw.tokens[requestID]
}

func (client *Client) storeRawToken(requestID, token string) {
	client.raw.mu.Lock()
	defer client.raw.mu.Unlock()
	if client.raw.tokens == nil {
		client.raw.tokens = map[string]string{}
	}
	client.raw.tokens[requestID] = token
}

func (client *Client) dropRawToken(requestID string) {
	client.raw.mu.Lock()
	defer client.raw.mu.Unlock()
	delete(client.raw.tokens, requestID)
}

func requiredString(arguments map[string]any, name string) (string, error) {
	value, ok := arguments[name].(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s must be a non-empty string", name)
	}
	return value, nil
}

// requestRawAudit asks the user for a request's raw parts. The first call
// files a grant and returns at once; the user approves in the desktop with
// their raw password or Touch ID, and a later call reads with the grant.
var errRawAccessDisabled = errors.New("raw_access_disabled: the user turned off agent raw access requests in AstrLink; do not ask again")

func requestRawAudit(ctx context.Context, client *Client, arguments map[string]any) (json.RawMessage, error) {
	requestID, err := requiredString(arguments, "request_id")
	if err != nil {
		return nil, err
	}
	reason, err := requiredString(arguments, "reason")
	if err != nil {
		return nil, err
	}
	if utf8.RuneCountInString(reason) > maxRawReasonRunes {
		return nil, fmt.Errorf("reason must be at most %d characters", maxRawReasonRunes)
	}
	auditPath := controlapi.RequestsPath + "/" + url.PathEscape(requestID) + "/audit"
	if token := client.rawToken(requestID); token != "" {
		raw, err := client.do(ctx, http.MethodGet, auditPath, url.Values{"view": {"full"}}, nil,
			http.Header{controlapi.RawGrantHeader: {token}})
		switch apiErrorCode(err) {
		case "":
			if err != nil {
				return nil, err
			}
			wrapped, err := annotateAuditPayload(raw, "raw")
			if err != nil {
				return nil, err
			}
			wrapped["status"] = "approved"
			return json.Marshal(wrapped)
		case "raw_access_pending":
			return json.Marshal(map[string]any{
				"status": "pending",
				"hint":   "The user has not decided yet. Wait until the user says they approved in the AstrLink desktop, then call request_raw_audit again.",
			})
		case "raw_access_denied":
			client.dropRawToken(requestID)
			return nil, fmt.Errorf("raw_access_denied: the user denied raw access to this request; do not ask again unless the user asks you to")
		case "raw_access_disabled":
			client.dropRawToken(requestID)
			return nil, errRawAccessDisabled
		case "raw_grant_invalid":
			// Spent, expired, or Core restarted; file a new request below.
			client.dropRawToken(requestID)
		default:
			return nil, err
		}
	}
	created, err := client.post(ctx, auditPath+"/raw-access", map[string]string{
		"reason": reason, "client_name": client.agentName(),
	})
	switch apiErrorCode(err) {
	case "":
		if err != nil {
			return nil, err
		}
	case "raw_access_disabled":
		return nil, errRawAccessDisabled
	case "raw_access_unavailable":
		return nil, fmt.Errorf("raw_access_unavailable: no raw password is set in AstrLink, so raw content is not kept and cannot be approved; do not ask again")
	case "raw_access_limited":
		return nil, fmt.Errorf("raw_access_limited: too many raw access requests are awaiting the user's decision; wait for the user to decide")
	default:
		return nil, err
	}
	var grant struct {
		GrantID    string `json:"grant_id"`
		ExpiresAt  string `json:"expires_at"`
		GrantToken string `json:"grant_token"`
	}
	if err := json.Unmarshal(created, &grant); err != nil || grant.GrantToken == "" {
		return nil, fmt.Errorf("control API returned no raw access grant")
	}
	client.storeRawToken(requestID, grant.GrantToken)
	return json.Marshal(map[string]any{
		"status":     "approval_required",
		"grant_id":   grant.GrantID,
		"expires_at": grant.ExpiresAt,
		"hint":       "Ask the user to approve this request in the AstrLink desktop with their raw password (on macOS, Touch ID), then call request_raw_audit again with the same request_id. Only the user can approve it; do not try to complete the approval yourself.",
	})
}
