package agentmcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/QuantumNous/astrlink/core/internal/controlapi"
)

type toolDef struct {
	Name        string
	Description string
	Schema      map[string]any
	Call        func(ctx context.Context, client *Client, arguments map[string]any) (json.RawMessage, error)
}

func toolCatalog() []toolDef {
	listQuery := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"limit":                 map[string]any{"type": "integer", "minimum": 1, "maximum": 200},
			"cursor":                map[string]any{"type": "string"},
			"from":                  map[string]any{"type": "string", "description": "RFC3339 start timestamp"},
			"to":                    map[string]any{"type": "string", "description": "RFC3339 end timestamp"},
			"protocol":              map[string]any{"type": "string"},
			"service_id":            map[string]any{"type": "string"},
			"local_access_token_id": map[string]any{"type": "string"},
			"status":                map[string]any{"type": "string"},
		},
	}
	idQuery := map[string]any{
		"type":                 "object",
		"properties":           map[string]any{"id": map[string]any{"type": "string"}},
		"required":             []string{"id"},
		"additionalProperties": false,
	}
	return []toolDef{
		{
			Name:        "list_request_sessions",
			Description: "List recent AstrLink request sessions (grouped conversations) with metadata only. turn_count is the number of user turns; call_count is the number of model calls, so an agent tool loop shows as 1 turn with many calls.",
			Schema:      listQuery,
			Call: func(ctx context.Context, client *Client, arguments map[string]any) (json.RawMessage, error) {
				return client.get(ctx, controlapi.RequestSessionsPath, listQueryValues(arguments))
			},
		},
		{
			Name:        "get_request_session",
			Description: "Get one AstrLink request session and its records (metadata + trajectory events). Each record carries turn_index (1-based user turn shared by every call of one agent loop) and session_link (how it joined the session: explicit cursor, echoed id, or assistant-text fingerprint; null for the first record).",
			Schema:      idQuery,
			Call: func(ctx context.Context, client *Client, arguments map[string]any) (json.RawMessage, error) {
				id, err := requiredID(arguments)
				if err != nil {
					return nil, err
				}
				return client.get(ctx, controlapi.RequestSessionsPath+"/"+url.PathEscape(id), nil)
			},
		},
		{
			Name:        "list_request_records",
			Description: "List root AstrLink request records (metadata + trajectory events, no bodies).",
			Schema:      listQuery,
			Call: func(ctx context.Context, client *Client, arguments map[string]any) (json.RawMessage, error) {
				return client.get(ctx, controlapi.RequestsPath, listQueryValues(arguments))
			},
		},
		{
			Name:        "get_request_record",
			Description: "Get one AstrLink request record including events[] trajectory phases, routing_decision (why routing chose service_id: selected reason, and the higher-priority providers skipped with their reasons), turn_index, session_link, and cursors[] (the typed session cursors stored for linking; fingerprint values are keyed digests, never text).",
			Schema:      idQuery,
			Call: func(ctx context.Context, client *Client, arguments map[string]any) (json.RawMessage, error) {
				id, err := requiredID(arguments)
				if err != nil {
					return nil, err
				}
				return client.get(ctx, controlapi.RequestsPath+"/"+url.PathEscape(id), nil)
			},
		},
		{
			Name:        "get_request_children",
			Description: "List failed retry attempts under a root AstrLink request record.",
			Schema:      idQuery,
			Call: func(ctx context.Context, client *Client, arguments map[string]any) (json.RawMessage, error) {
				id, err := requiredID(arguments)
				if err != nil {
					return nil, err
				}
				return client.get(ctx, controlapi.RequestsPath+"/"+url.PathEscape(id)+"/children", nil)
			},
		},
		{
			Name:        "get_request_audit",
			Description: "Get the shareable audit content for a request. Bodies are present only when the user enabled body capture in AstrLink. Parts the privacy policy did not clear (the client's original request, restored responses, uninspected parts) are withheld with a reason; every part carries content_view. privacy_findings lists what was found by kind and JSON path, never the values.",
			Schema:      idQuery,
			Call: func(ctx context.Context, client *Client, arguments map[string]any) (json.RawMessage, error) {
				id, err := requiredID(arguments)
				if err != nil {
					return nil, err
				}
				raw, err := client.get(ctx, controlapi.RequestsPath+"/"+url.PathEscape(id)+"/audit",
					url.Values{"view": {"shareable"}})
				if err != nil {
					return nil, err
				}
				return annotateAudit(raw)
			},
		},
		{
			Name: "request_raw_audit",
			Description: "Ask the user to let you read the raw audit parts that get_request_audit withheld for one request. Use it only when a withheld part says raw_available: true and the shareable parts are not enough. " +
				"Raw content enters your context and is sent to the model provider you use, so first tell the user why you need it and pass that as reason. " +
				"The first call returns approval_required at once. Only the user can approve, in the AstrLink desktop with their raw password or Touch ID; never try to approve it yourself. " +
				"After the user says they approved, call again with the same arguments: it returns the audit with content_view raw, or pending, or an error if the user denied it or raw access is unavailable. An approval may allow only one read.",
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"request_id": map[string]any{"type": "string"},
					"reason": map[string]any{
						"type": "string", "minLength": 1, "maxLength": maxRawReasonRunes,
						"description": "Why you need the raw parts, as you explained it to the user; shown in the approval dialog",
					},
				},
				"required":             []string{"request_id", "reason"},
				"additionalProperties": false,
			},
			Call: requestRawAudit,
		},
		{
			Name:        "get_audit_settings",
			Description: "Read AstrLink audit settings to see whether request/response bodies are being captured.",
			Schema: map[string]any{
				"type":                 "object",
				"properties":           map[string]any{},
				"additionalProperties": false,
			},
			Call: func(ctx context.Context, client *Client, arguments map[string]any) (json.RawMessage, error) {
				return client.get(ctx, controlapi.AuditSettingsPath, nil)
			},
		},
		{
			Name:        "get_routing_settings",
			Description: "Read AstrLink routing settings: model_redirects (client model → routed model rules; only enabled rules apply, exact case-sensitive match, one hop), failover and retry settings (default_failure_policy, allow_unmatched_failover, strategy, max_attempts), channel_stickiness, and the Codex/Claude/Grok subscription identity enforcement flags.",
			Schema: map[string]any{
				"type":                 "object",
				"properties":           map[string]any{},
				"additionalProperties": false,
			},
			Call: func(ctx context.Context, client *Client, arguments map[string]any) (json.RawMessage, error) {
				return client.get(ctx, controlapi.RoutingSettingsPath, nil)
			},
		},
		{
			Name:        "search_requests",
			Description: "Search root AstrLink request records whose stored input preview contains q (case-insensitive literal text, not a pattern). Accepts the list_request_records filters as well. Previews are short, so this finds requests by how they began, not by full body content.",
			Schema:      searchQuery(listQuery),
			Call: func(ctx context.Context, client *Client, arguments map[string]any) (json.RawMessage, error) {
				q, ok := arguments["q"].(string)
				if !ok || strings.TrimSpace(q) == "" {
					return nil, fmt.Errorf("q must be a non-empty string")
				}
				query := listQueryValues(arguments)
				query.Set("q", q)
				return client.get(ctx, controlapi.RequestsPath, query)
			},
		},
		{
			Name:        "explain_request",
			Description: "Explain one AstrLink request: a summary (final status, HTTP status, service, attempt count, error, routing reason) plus the record, its failed retry attempts, and which audit parts were captured. It does not return bodies; call get_request_audit for those.",
			Schema:      idQuery,
			Call:        explainRequest,
		},
		{
			Name:        "list_services",
			Description: "List configured AstrLink upstream services: id, name, kind, enabled, models, capabilities, the base URL origin (scheme and host only), and subscription status. Credentials, credential references, proxy addresses, and provider account ids are never included.",
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"enabled": map[string]any{"type": "boolean", "description": "Only services with this enabled state"},
				},
				"additionalProperties": false,
			},
			Call: listServices,
		},
		{
			Name:        "get_service_status",
			Description: "Get the health of one AstrLink service: its projected configuration, subscription token and risk state, recent risk events for subscription services, and a summary of its latest 20 request records (counts by status, last success, last failure with error code).",
			Schema:      idQuery,
			Call:        getServiceStatus,
		},
		{
			Name:        "get_privacy_policy",
			Description: "Read AstrLink privacy policies: detector, enabled entity kinds, request/response actions, restore options, and match scope. Allowlist entries and custom regex patterns are reported as counts and types only; their values are never returned.",
			Schema: map[string]any{
				"type":                 "object",
				"properties":           map[string]any{},
				"additionalProperties": false,
			},
			Call: getPrivacyPolicy,
		},
	}
}

func searchQuery(listQuery map[string]any) map[string]any {
	properties := map[string]any{
		"q": map[string]any{"type": "string", "minLength": 1, "maxLength": 200, "description": "Text to find in the input preview"},
	}
	for key, value := range listQuery["properties"].(map[string]any) {
		properties[key] = value
	}
	return map[string]any{
		"type":       "object",
		"properties": properties,
		"required":   []string{"q"},
	}
}

func listQueryValues(arguments map[string]any) url.Values {
	query := url.Values{}
	for _, key := range []string{
		"limit", "cursor", "from", "to", "protocol", "service_id", "local_access_token_id", "status",
	} {
		value, ok := arguments[key]
		if !ok || value == nil {
			continue
		}
		query.Set(key, fmt.Sprint(value))
	}
	return query
}

func requiredID(arguments map[string]any) (string, error) {
	raw, ok := arguments["id"]
	if !ok {
		return "", fmt.Errorf("id is required")
	}
	id, ok := raw.(string)
	if !ok || strings.TrimSpace(id) == "" {
		return "", fmt.Errorf("id must be a non-empty string")
	}
	return id, nil
}

var auditBodyParts = []string{"request_body", "response_content", "upstream_request_body", "upstream_response_content"}

// withheldReasonDetails explains each withheld reason to the agent.
var withheldReasonDetails = map[string]string{
	"privacy_redacted":  "The privacy policy redacted this before it went upstream; the upstream parts show what the model saw, with placeholders.",
	"privacy_blocked":   "The privacy policy blocked this request.",
	"privacy_restored":  "Placeholders in this response were restored to the original values.",
	"privacy_fail_open": "Privacy inspection failed and the request went upstream uninspected.",
	"privacy_pending":   "Privacy inspection had not finished when this was read.",
	"privacy_unknown":   "Captured before AstrLink recorded privacy decisions, or its inspection never finished.",
	"raw_locked":        "Raw reading is locked in the desktop.",
}

// annotateAudit wraps a shareable audit read for the agent.
func annotateAudit(raw json.RawMessage) (json.RawMessage, error) {
	wrapped, err := annotateAuditPayload(raw, "shareable")
	if err != nil {
		return raw, nil
	}
	return json.Marshal(wrapped)
}

// annotateAuditPayload labels every body part with content_view — the view
// its content came from, or "withheld" — and explains what was withheld.
func annotateAuditPayload(raw json.RawMessage, view string) (map[string]any, error) {
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	bodiesCaptured := false
	withheld := []string{}
	rawAvailable := false
	for _, name := range auditBodyParts {
		part, ok := payload[name].(map[string]any)
		if !ok {
			continue
		}
		bodiesCaptured = true
		if part["withheld"] == true {
			part["content_view"] = "withheld"
			if detail, ok := withheldReasonDetails[fmt.Sprint(part["reason"])]; ok {
				part["reason_detail"] = detail
			}
			withheld = append(withheld, name)
			rawAvailable = rawAvailable || part["raw_available"] == true
			continue
		}
		if part["exposure"] == "raw" {
			part["content_view"] = "raw"
		} else {
			part["content_view"] = "shareable"
		}
	}
	wrapped := map[string]any{
		"audit":           payload,
		"content_view":    view,
		"bodies_captured": bodiesCaptured,
	}
	switch {
	case !bodiesCaptured:
		wrapped["hint"] = "Request/response bodies were not captured for this request. Enable body audit in the AstrLink desktop (risk confirmation required). Metadata, trajectory events, and optional HTTP meta may still be present."
	case len(withheld) > 0 && view == "raw":
		wrapped["withheld_parts"] = withheld
	case len(withheld) > 0 && rawAvailable:
		wrapped["withheld_parts"] = withheld
		wrapped["hint"] = "Some parts are withheld. Work from the shareable parts and privacy_findings first. If you still need the raw parts, tell the user why, then call request_raw_audit; the user must approve it in the AstrLink desktop."
	case len(withheld) > 0:
		wrapped["withheld_parts"] = withheld
		wrapped["hint"] = "Some parts are withheld and raw access is not available: the user has not set up raw sealing or has turned off agent raw access requests. Do not call request_raw_audit; work from the shareable parts and privacy_findings."
	}
	return wrapped, nil
}

func toolsListPayload() []map[string]any {
	tools := toolCatalog()
	items := make([]map[string]any, 0, len(tools))
	for _, tool := range tools {
		items = append(items, map[string]any{
			"name":        tool.Name,
			"description": tool.Description,
			"inputSchema": tool.Schema,
		})
	}
	return items
}

func callTool(ctx context.Context, client *Client, name string, arguments map[string]any) (json.RawMessage, error) {
	if arguments == nil {
		arguments = map[string]any{}
	}
	for _, tool := range toolCatalog() {
		if tool.Name == name {
			return tool.Call(ctx, client, arguments)
		}
	}
	return nil, fmt.Errorf("unknown tool %q", name)
}
