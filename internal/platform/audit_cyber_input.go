package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Keep all supplied user turns (not only heuristic continuation words), script
// and tool data. Historical material is marked as untrusted reference; hard
// policy hits are still vetoes. Never silently clip it and then call it safe.
// Control prompts and tool schemas are excluded, not executed or trusted as
// proof. Opaque remote history and non-text modalities remain unsupported.
func extractCyberAuditText(body []byte, limit int) AuditTextExtraction {
	out, _ := extractCyberAuditTextContext(context.Background(), body, limit, 0)
	return out
}

func extractCyberAuditTextContext(ctx context.Context, body []byte, limit, capacity int) (AuditTextExtraction, error) {
	if err := ctx.Err(); err != nil {
		return AuditTextExtraction{CoverageStatus: "incomplete"}, err
	}

	if limit <= 0 {
		limit = 256 * 1024
	}
	decoder := json.NewDecoder(auditContextReader{ctx: ctx, reader: bytes.NewReader(body)})
	decoder.UseNumber()
	root, decodeErr := readAuditJSONValue(decoder, 0)
	if err := ctx.Err(); err != nil {
		return AuditTextExtraction{CoverageStatus: "incomplete"}, err
	}
	if _, trailing := decoder.Token(); trailing != io.EOF && decodeErr == nil {
		decodeErr = io.ErrUnexpectedEOF
	}
	if decodeErr != nil || !utf8.Valid(body) {
		return AuditTextExtraction{CoverageStatus: "incomplete", CoverageIssues: []string{"invalid_request_json"}, Scope: "cyber_user_history_and_tool_data"}, nil
	}
	out := AuditTextExtraction{CoverageStatus: "complete", Scope: "cyber_user_history_and_tool_data"}
	var b, raw strings.Builder
	var workErr error
	var appendText func(string, string, bool)
	appendText = func(role, text string, reference bool) {
		if workErr != nil {
			return
		}
		if workErr = ctx.Err(); workErr != nil {
			return
		}
		if capacity > 0 && b.Len()+len(text)+len(role)+7 > capacity {
			out.RawIntentBytes += len(text)
			out.addCoverageIssue("audit_capacity_exceeded")
			workErr = newAuditModelCallError("audit_capacity_exceeded", 0, "auditable text exceeds the maximum two-pass capacity; no content was authorized or forwarded", nil)
			return
		}
		if strings.TrimSpace(text) == "" {
			return
		}
		out.RawIntentBytes += len(text)
		rawValue := "ROLE=" + role + "\n" + text
		if raw.Len()+len(rawValue)+1 > limit {
			out.addCoverageIssue("input_text_truncated")
		}
		appendAuditLine(&raw, rawValue, limit)
		if role == "USER" {
			out.ActiveUserMessages++
		}
		// Preserve the original representation for administrator rule matching.
		if role == "TOOL_DATA" {
			viewLimit := limit - b.Len() - len(role) - 7
			if capacity > 0 && capacity-b.Len()-len(role)-7 < viewLimit {
				viewLimit = capacity - b.Len() - len(role) - 7
			}
			view, decoded, err := auditToolJSONView(ctx, text, viewLimit)
			out.SerializedToolDocuments += decoded
			if err != nil {
				workErr = err
				out.addCoverageIssue("serialized_tool_projection_incomplete")
				return
			}
			text = view
		}
		// Mask secret values only; do NOT remove text preceding "My request",
		// clipboard-looking paths, tests, assertions or a safety reminder.
		// One match pass counts and replaces secret assignments. Never duplicate
		// an expensive full-text regex scan merely to compute a counter.
		var masked int
		text, masked = maskCyberCredentialAssignments(text)
		out.SecretPlaceholderCount += masked
		if workErr = ctx.Err(); workErr != nil {
			return
		}
		text = bearerSecretPattern.ReplaceAllString(text, "${1}[USER_PROVIDED_SECRET]")
		text = openAISecretPattern.ReplaceAllString(text, "[USER_PROVIDED_SECRET]")
		text = awsSecretPattern.ReplaceAllString(text, "[USER_PROVIDED_SECRET]")
		start := b.Len()
		if start > 0 {
			start++
		}
		value := "ROLE=" + role + "\n" + text
		if start+len(value) > limit {
			out.addCoverageIssue("input_text_truncated")
		}
		appendAuditLine(&b, value, limit)
		if reference && b.Len() > start {
			out.ReferenceSpans = append(out.ReferenceSpans, auditReferenceSpan{Start: start, End: b.Len(), Kind: "untrusted_conversation_data"})
		}
	}
	var collect func(any, string, string, int)
	collect = func(v any, role, path string, depth int) {
		if workErr != nil {
			return
		}
		if workErr = ctx.Err(); workErr != nil {
			return
		}
		if depth > 32 {
			out.coverageProblem("input_structure_depth", path, "unknown", role)
			return
		}
		switch x := v.(type) {
		case string:
			appendText(role, x, role != "USER")
		case []any:
			for index, item := range x {
				collect(item, role, path+"["+strconv.Itoa(index)+"]", depth+1)
			}
		case map[string]any:
			kind, _ := x["type"].(string)
			kind = strings.ToLower(kind)
			actual, _ := x["role"].(string)
			actual = strings.ToLower(actual)
			if actual != "" {
				switch {
				case isEndUserRole(actual):
					role = "USER"
				case actual == "assistant":
					role = "ASSISTANT_DATA"
				case actual == "tool" || actual == "function":
					role = "TOOL_DATA"
				case actual == "system" || actual == "developer":
					out.IgnoredRoles = append(out.IgnoredRoles, strings.ToUpper(actual))
					out.IgnoredContextBytes += countContextTextBytes(x, "")
					return
				default:
					out.coverageProblem("unsupported_role", path, kind, "unknown")
					return
				}
			}
			switch kind {
			case "reasoning":
				out.IgnoredInputTypes = append(out.IgnoredInputTypes, "REASONING")
				out.IgnoredContextBytes += countContextTextBytes(x, "")
				return
			case "function_call", "custom_tool_call", "tool_search_call", "function_call_output", "custom_tool_call_output", "tool_search_output", "function":
				role = "TOOL_DATA"
			case "", "message", "input_text", "text", "output_text":
			default:
				out.coverageProblem("unsupported_input_content", path, kind, role)
				return
			}
			found := false
			// Loaded tool definitions are returned under tools, not output. Keep
			// their whole JSON as untrusted text instead of silently skipping them.
			// This is not the request-root tools configuration exclusion.
			if kind == "tool_search_output" {
				if definitions, exists := x["tools"]; exists {
					found = true
					if !auditLoadedToolDefinitions(definitions, 0) {
						out.coverageProblem("unsupported_input_content", path+".tools", kind, role)
					} else if data, err := json.Marshal(definitions); err != nil {
						out.coverageProblem("unsupported_input_content", path+".tools", kind, role)
					} else {
						appendText(role, string(data), true)
					}
				}
			}
			for _, key := range []string{"content", "text", "input", "prompt", "query", "arguments", "output", "tool_calls", "function_call", "function"} {
				if child, exists := x[key]; exists {
					found = true
					if role == "TOOL_DATA" && (key == "arguments" || key == "output") {
						if str, ok := child.(string); ok {
							appendText(role, str, true)
						} else {
							data, err := json.Marshal(child)
							if err != nil {
								out.coverageProblem("unsupported_input_content", path, kind, role)
							} else {
								appendText(role, string(data), true)
							}
						}
					} else {
						collect(child, role, path+"."+key, depth+1)
					}
				}
			}
			if !found {
				out.coverageProblem("unsupported_input_content", path, kind, role)
			}
		case nil:
		default:
			out.coverageProblem("unsupported_input_content", path, "unknown", role)
		}
	}
	if obj, ok := root.(map[string]any); ok {
		if id, exists := obj["previous_response_id"]; exists && id != nil && id != "" {
			out.addCoverageIssue("unresolved_previous_response")
		}
		// Multiple alternate input fields are ambiguous: do not audit one and forward another.
		n := 0
		for _, key := range []string{"messages", "input", "prompt", "query", "content", "text"} {
			v, exists := obj[key]
			if !exists || v == nil {
				continue // A null optional alias is not a second input source.
			}
			// Responses "text" is an output configuration object. Only known
			// configuration shapes are excluded, and only at the request root.
			// Legacy text strings and unknown objects still follow input guards.
			if key == "text" && isResponsesOutputTextConfig(v) {
				out.IgnoredRoles = append(out.IgnoredRoles, "OUTPUT_TEXT_CONFIG")
				out.IgnoredContextBytes += countContextTextBytes(v, "")
				continue
			}
			n++
			collect(v, "USER", "$."+key, 0)
		}
		if n > 1 {
			out.addCoverageIssue("ambiguous_input_fields")
		}
		for _, key := range []string{"instructions", "system", "developer", "tools", "functions", "tool_choice", "response_format"} {
			if v, ok := obj[key]; ok {
				out.IgnoredRoles = append(out.IgnoredRoles, strings.ToUpper(key))
				out.IgnoredContextBytes += countContextTextBytes(v, "")
			}
		}
	} else {
		collect(root, "USER", "$", 0)
	}
	if workErr != nil {
		out.Text = b.String()
		out.ruleText = raw.String()
		out.IntentBytes = len(out.Text)
		out.CoverageStatus = "incomplete"
		return out, workErr
	}
	out.ContextActivated = out.ActiveUserMessages > 1 || len(out.ReferenceSpans) > 0
	out.Text = b.String()
	out.ruleText = raw.String()
	out.IntentBytes = len(out.Text)
	if out.Text == "" || out.ActiveUserMessages == 0 {
		out.addCoverageIssue("no_auditable_user_intent")
	}
	// Actual standalone continuations require history. No text-to-role parser is used.
	if obj, ok := root.(map[string]any); ok {
		if input, yes := obj["input"].(string); yes && standaloneContinuationPattern.MatchString(input) && len(auditReferenceSpans(input)) == 0 {
			out.addCoverageIssue("missing_continuation_context")
		}
	}
	if out.ActiveUserMessages == 1 && len(out.ReferenceSpans) == 0 {
		userText := strings.TrimPrefix(out.Text, "ROLE=USER\n")
		if (standaloneContinuationPattern.MatchString(userText) || executionFollowupPattern.MatchString(userText)) && len(auditReferenceSpans(userText)) == 0 {
			out.addCoverageIssue("missing_continuation_context")
		}
	}
	return out, ctx.Err()
}

// Responses API's top-level text config is analogous to response_format, not
// an alternative to input. Do not recursively interpret it as conversation
// content. Unknown keys/shapes deliberately return to the coverage guard; this
// must never become an exemption for arbitrary objects named "text".
func isResponsesOutputTextConfig(value any) bool {
	config, ok := value.(map[string]any)
	if !ok {
		return false
	}
	for key, value := range config {
		switch key {
		case "verbosity":
			if value == nil {
				continue
			}
			level, ok := value.(string)
			if !ok || (level != "low" && level != "medium" && level != "high") {
				return false
			}
		case "format":
			if value == nil {
				continue
			}
			format, ok := value.(map[string]any)
			if !ok {
				return false
			}
			kind, _ := format["type"].(string)
			switch kind {
			case "text", "json_object":
				if len(format) != 1 {
					return false
				}
			case "json_schema":
				name, ok := format["name"].(string)
				if !ok || strings.TrimSpace(name) == "" {
					return false
				}
				if _, ok := format["schema"].(map[string]any); !ok {
					return false
				}
				for field, item := range format {
					switch field {
					case "type", "name", "schema":
					case "strict":
						if item != nil {
							if _, ok := item.(bool); !ok {
								return false
							}
						}
					case "description":
						if item != nil {
							if _, ok := item.(string); !ok {
								return false
							}
						}
					default:
						return false
					}
				}
			default:
				return false
			}
		default:
			return false
		}
	}
	return true
}

// Only documented textual tool definitions; unknown modalities remain uncovered.
func auditLoadedToolDefinitions(value any, depth int) bool {
	list, ok := value.([]any)
	if !ok || depth > 16 || len(list) > 512 {
		return false
	}
	for _, item := range list {
		obj, ok := item.(map[string]any)
		if !ok {
			return false
		}
		switch obj["type"] {
		case "function", "custom":
			if name, ok := obj["name"].(string); !ok || strings.TrimSpace(name) == "" {
				return false
			}
		case "namespace":
			if !auditLoadedToolDefinitions(obj["tools"], depth+1) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
