package agentcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/QuantumNous/astrlink/core/internal/controlapi"
)

const (
	maxRawReasonRunes = 500
	maxAgentNameLen   = 64
	// defaultRawWait matches how long the Control API keeps a request
	// pending; waiting longer cannot succeed.
	defaultRawWait = 10 * time.Minute
)

// rawPollInterval is how often a pending raw access request is checked.
var rawPollInterval = 2 * time.Second

var errRawAccessDisabled = errors.New("raw_access_disabled: the user turned off agent raw access requests in AstrLink; do not ask again")

func requiredString(arguments map[string]any, name string) (string, error) {
	value, ok := arguments[name].(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s must be a non-empty string", name)
	}
	return value, nil
}

// agentName bounds the agent's self-reported name.
func agentName(name string) string {
	name = strings.TrimSpace(name)
	if len(name) > maxAgentNameLen {
		name = strings.ToValidUTF8(name[:maxAgentNameLen], "")
	}
	return name
}

func (client *Client) progress(format string, args ...any) {
	if client.Progress != nil {
		_, _ = fmt.Fprintf(client.Progress, format+"\n", args...)
	}
}

// requestRawAudit asks the user for a request's raw parts and waits for the
// decision. The user approves in the desktop with their raw password or
// Touch ID. The grant token lives only in this process and is never printed,
// so an interrupted wait leaves nothing behind for the agent to reuse.
func requestRawAudit(ctx context.Context, client *Client, arguments map[string]any) (json.RawMessage, error) {
	requestID, err := requiredID(arguments)
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
	wait := defaultRawWait
	if value, ok := arguments["wait"].(time.Duration); ok {
		if value <= 0 {
			return nil, fmt.Errorf("wait must be positive")
		}
		wait = min(value, defaultRawWait)
	}
	agent, _ := arguments["agent"].(string)
	if strings.TrimSpace(agent) == "" {
		agent = client.Agent
	}
	auditPath := controlapi.RequestsPath + "/" + url.PathEscape(requestID) + "/audit"
	created, err := client.post(ctx, auditPath+"/raw-access", map[string]string{
		"reason": reason, "client_name": agentName(agent),
	})
	switch apiErrorCode(err) {
	case "":
		if err != nil {
			return nil, err
		}
	case "raw_access_disabled":
		return nil, errRawAccessDisabled
	case "raw_access_unavailable":
		return nil, fmt.Errorf("raw_access_unavailable: the user has not protected raw content with a raw password or Touch ID in AstrLink, so raw content is not kept and cannot be approved; do not ask again")
	case "raw_access_limited":
		return nil, fmt.Errorf("raw_access_limited: too many raw access requests are awaiting the user's decision; wait for the user to decide")
	default:
		return nil, err
	}
	var grant struct {
		GrantID    string `json:"grant_id"`
		GrantToken string `json:"grant_token"`
	}
	if err := json.Unmarshal(created, &grant); err != nil || grant.GrantToken == "" {
		return nil, fmt.Errorf("control API returned no raw access grant")
	}
	client.progress("Waiting up to %s for the user to approve raw access request %s in the AstrLink desktop.", wait, grant.GrantID)

	deadline := time.Now().Add(wait)
	header := http.Header{controlapi.RawGrantHeader: {grant.GrantToken}}
	for {
		raw, err := client.do(ctx, http.MethodGet, auditPath, url.Values{"view": {"full"}}, nil, header)
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
		case "raw_access_denied":
			return nil, fmt.Errorf("raw_access_denied: the user denied raw access to this request; do not ask again unless the user asks you to")
		case "raw_access_disabled":
			return nil, errRawAccessDisabled
		case "raw_grant_invalid":
			return nil, fmt.Errorf("raw_grant_invalid: the raw access request expired or AstrLink restarted before the user decided; ask the user before requesting again")
		default:
			return nil, err
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("raw_access_pending: the user did not decide within %s; the request lapses on its own. Ask the user whether they still want to approve before requesting again", wait)
		}
		timer := time.NewTimer(min(rawPollInterval, time.Until(deadline)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
