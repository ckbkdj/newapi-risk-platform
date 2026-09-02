from pathlib import Path

path = Path(__file__).resolve().parents[1] / "internal/platform/adaptive_rules.go"
text = path.read_text(encoding="utf-8")
old = '''	payload := map[string]any{
		"model":       profile.Model,
		"temperature": 0,
		"max_tokens":  500,
		"messages": []map[string]string{
			{"role": "system", "content": adaptiveLearningSystemPrompt},
			{"role": "user", "content": string(userPayload)},
		},
	}
	encoded, err := json.Marshal(payload)
'''
new = '''	payload := map[string]any{
		"model":       profile.Model,
		"temperature": 0,
		"max_tokens":  e.outputMaxTokens,
		"messages": []map[string]string{
			{"role": "system", "content": appendFastAuditDirective(adaptiveLearningSystemPrompt)},
			{"role": "user", "content": e.auditUserContent(profile, string(userPayload))},
		},
	}
	if len(profile.Extra) > 0 {
		var extra map[string]any
		if json.Unmarshal(profile.Extra, &extra) == nil {
			for key, value := range extra {
				if isInternalAuditExtraKey(key) {
					continue
				}
				switch key {
				case "model", "messages", "stream":
					continue
				default:
					payload[key] = value
				}
			}
		}
	}
	e.applyFastAuditDefaults(profile, payload)
	encoded, err := json.Marshal(payload)
'''
if text.count(old) != 1:
    raise SystemExit(f"adaptive payload anchor count={text.count(old)}")
text = text.replace(old, new, 1)
old = '''	timeout := time.Duration(profile.TimeoutMS) * time.Millisecond
	if timeout <= 0 || timeout > 20*time.Second {
		timeout = 8 * time.Second
	}
'''
new = '''	timeout := e.auditRequestTimeout(profile, len(userPayload))
	if timeout > 20*time.Second {
		timeout = 20 * time.Second
	}
'''
if text.count(old) != 1:
    raise SystemExit(f"adaptive timeout anchor count={text.count(old)}")
text = text.replace(old, new, 1)
old = '''	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)
	var result adaptiveModelResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return adaptiveModelResult{}, fmt.Errorf("adaptive audit model did not return valid JSON: %w", err)
	}
	result.Confidence = clampConfidence(result.Confidence)
	result.Category = strings.ToLower(strings.TrimSpace(result.Category))
	result.Reason = truncateString(strings.TrimSpace(result.Reason), 500)
	return result, nil
}

func validateAdaptiveIndicators(requestText string, raw []string) []string {
'''
new = '''	result, err := parseAdaptiveModelResponseContent(content)
	if err != nil {
		return adaptiveModelResult{}, err
	}
	return result, nil
}

func parseAdaptiveModelResponseContent(content string) (adaptiveModelResult, error) {
	content = strings.TrimSpace(strings.ToValidUTF8(content, ""))
	if content == "" {
		return adaptiveModelResult{}, errors.New("adaptive audit model returned empty content")
	}
	var direct adaptiveModelResult
	if json.Unmarshal([]byte(content), &direct) == nil {
		return normalizeAdaptiveModelResult(direct), nil
	}
	candidates := balancedJSONObjects(content)
	for index := len(candidates) - 1; index >= 0; index-- {
		var candidate adaptiveModelResult
		if json.Unmarshal([]byte(candidates[index]), &candidate) == nil {
			return normalizeAdaptiveModelResult(candidate), nil
		}
	}
	return adaptiveModelResult{}, errors.New("adaptive audit model did not return valid JSON")
}

func normalizeAdaptiveModelResult(result adaptiveModelResult) adaptiveModelResult {
	result.Confidence = clampConfidence(result.Confidence)
	result.Category = strings.ToLower(strings.TrimSpace(result.Category))
	result.Reason = truncateString(strings.TrimSpace(result.Reason), 500)
	return result
}

func validateAdaptiveIndicators(requestText string, raw []string) []string {
'''
if text.count(old) != 1:
    raise SystemExit(f"adaptive response parser anchor count={text.count(old)}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
print("adaptive Qwen fast mode applied")
