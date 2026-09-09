package platform

import (
	"bytes"
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
	if limit <= 0 {
		limit = 256 * 1024
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	root, decodeErr := readAuditJSONValue(decoder, 0)
	if _, trailing := decoder.Token(); trailing != io.EOF && decodeErr == nil {
		decodeErr = io.ErrUnexpectedEOF
	}
	if decodeErr != nil || !utf8.Valid(body) {
		return AuditTextExtraction{CoverageStatus: "incomplete", CoverageIssues: []string{"invalid_request_json"}, Scope: "cyber_user_history_and_tool_data"}
	}
	out := AuditTextExtraction{CoverageStatus: "complete", Scope: "cyber_user_history_and_tool_data"}
	var b, raw strings.Builder
	var appendText func(string, string, bool)
	appendText = func(role, text string, reference bool) {
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
		// Mask secret values only; do NOT remove text preceding "My request",
		// clipboard-looking paths, tests, assertions or a safety reminder.
		out.SecretPlaceholderCount += len(secretAssignmentPattern.FindAllStringIndex(text, -1))
		text = secretAssignmentPattern.ReplaceAllString(text, "${1}[USER_PROVIDED_SECRET]")
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
	return out
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
