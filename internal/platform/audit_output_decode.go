package platform

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

const auditOutputContractVersion = "risk_audit_output.v2"
const maxAuditResponseBytes = 1024 * 1024
const maxAuditJSONDepth = 32
const maxAuditPolicyCandidates = 32

func auditSchemaError(field, detail string) error {
	return newAuditModelCallError("invalid_schema", 0, "audit model field "+field+" "+detail, nil)
}

// decodeAuditJSON detects duplicate keys BEFORE they disappear into a Go map.
// Input bytes, JSON nesting, wrapper depth and candidate counts are all bounded.
func decodeAuditJSON(text string) (any, error) {
	if len(text) > maxAuditResponseBytes {
		return nil, newAuditModelCallError("response_too_large", 0, "audit model response exceeds byte limit", nil)
	}
	if !utf8.ValidString(text) {
		return nil, newAuditModelCallError("invalid_json", 0, "audit model JSON is not valid UTF-8", nil)
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	value, err := readAuditJSONValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, newAuditModelCallError("invalid_json", 0, "audit model response contains trailing JSON data", nil)
	}
	return value, nil
}

func readAuditJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxAuditJSONDepth {
		return nil, newAuditModelCallError("output_limits", 0, "audit model JSON nesting limit exceeded", nil)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, newAuditModelCallError("invalid_json", 0, "audit model JSON syntax is incomplete or invalid", nil)
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return nil, newAuditModelCallError("invalid_json", 0, "audit model JSON has an invalid object key", nil)
			}
			if _, exists := object[key]; exists {
				return nil, newAuditModelCallError("ambiguous_output", 0, "audit model JSON contains a duplicate key", nil)
			}
			value, err := readAuditJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, newAuditModelCallError("invalid_json", 0, "audit model JSON object is incomplete", nil)
		}
		return object, nil
	case '[':
		values := make([]any, 0)
		for decoder.More() {
			value, err := readAuditJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, newAuditModelCallError("invalid_json", 0, "audit model JSON array is incomplete", nil)
		}
		return values, nil
	default:
		return nil, newAuditModelCallError("invalid_json", 0, "audit model JSON has an unexpected delimiter", nil)
	}
}

// Qualitative confidence is kept as a LABEL, never invented as a probability.
// Zero is only a compatibility placeholder when ConfidenceKind is qualitative.
func decodeAuditPolicyObject(object map[string]any) (modelAuditResponse, error) {
	var result modelAuditResponse
	for key := range object {
		lower := strings.ToLower(key)
		if lower != key {
			switch lower {
			case "decision", "confidence", "risk_code", "category", "reason", "evidence", "request_evidence", "evidence_relation", "harm_type":
				return result, auditSchemaError(lower, "must use its exact lowercase field name")
			}
		}
	}
	for key, destination := range map[string]*string{
		"decision": &result.Decision, "risk_code": &result.RiskCode, "category": &result.Category,
		"reason": &result.Reason, "evidence": &result.Evidence, "request_evidence": &result.RequestEvidence,
		"evidence_relation": &result.EvidenceRelation, "harm_type": &result.HarmType,
	} {
		if raw, exists := object[key]; exists {
			value, ok := raw.(string)
			if !ok {
				return result, auditSchemaError(key, "must be a string")
			}
			*destination = value
		}
	}
	result.Decision = strings.ToLower(strings.TrimSpace(result.Decision))
	switch result.Decision {
	case DecisionAllow, DecisionBlock, DecisionReview:
	default:
		return result, newAuditModelCallError("invalid_decision", 0, "audit model decision must be allow, block or review", nil)
	}
	raw, exists := object["confidence"]
	if !exists || raw == nil {
		return result, auditSchemaError("confidence", "is required")
	}
	switch value := raw.(type) {
	case json.Number:
		number, err := strconv.ParseFloat(string(value), 64)
		if err != nil {
			return result, auditSchemaError("confidence", "must be finite and between 0 and 1")
		}
		result.Confidence = number
		result.ConfidenceKind = "numeric"
	case float64:
		result.Confidence, result.ConfidenceKind = value, "numeric"
	case string:
		value = strings.ToLower(strings.TrimSpace(value))
		switch value {
		case "high", "medium", "low":
			result.ConfidenceKind, result.ConfidenceLabel = "qualitative", value
			result.OutputNormalizations = append(result.OutputNormalizations, "confidence_qualitative")
		default:
			number, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return result, auditSchemaError("confidence", "must be a number, numeric string, or high/medium/low")
			}
			result.Confidence, result.ConfidenceKind = number, "numeric_string"
			result.OutputNormalizations = append(result.OutputNormalizations, "confidence_numeric_string")
		}
	default:
		return result, auditSchemaError("confidence", "has an unsupported type")
	}
	if math.IsNaN(result.Confidence) || math.IsInf(result.Confidence, 0) || result.Confidence < 0 || result.Confidence > 1 {
		return result, auditSchemaError("confidence", "must be finite and between 0 and 1")
	}
	result.RiskCode = strings.TrimSpace(result.RiskCode)
	if strings.EqualFold(result.RiskCode, "NONE") {
		if result.Decision != DecisionAllow {
			return result, auditSchemaError("risk_code", "NONE contradicts a non-allow decision")
		}
		result.RiskCode = ""
		result.OutputNormalizations = append(result.OutputNormalizations, "allow_none_risk_code")
	}
	if result.Decision == DecisionAllow && (result.RiskCode != "" || strings.TrimSpace(result.Evidence) != "" || (result.HarmType != "" && result.HarmType != "none")) {
		return result, auditSchemaError("decision", "allow contradicts nonempty risk_code or evidence")
	}
	return validateAuditModelResponse(result)
}

// A categorical high can satisfy the DEFAULT high-confidence semantic gate,
// but cannot satisfy an explicitly stricter (>0.90) numerical threshold.
// Numeric thresholds remain unchanged for all numeric/numeric-string scores.
func auditConfidenceMeets(d AuditDecision, threshold float64) bool {
	if d.ConfidenceKind == "qualitative" {
		return d.ConfidenceLabel == "high" && threshold <= .90
	}
	return !math.IsNaN(d.Confidence) && !math.IsInf(d.Confidence, 0) && d.Confidence >= threshold
}

func parseAuditModelResponseContent(content string) (modelAuditResponse, error) {
	return parseAuditModelResponseContentDepth(content, 0)
}

func parseAuditModelResponseContentDepth(content string, depth int) (modelAuditResponse, error) {
	if len(content) > maxAuditResponseBytes {
		return modelAuditResponse{}, newAuditModelCallError("response_too_large", 0, "audit model response exceeds byte limit", nil)
	}
	if !utf8.ValidString(content) {
		return modelAuditResponse{}, newAuditModelCallError("invalid_json", 0, "audit model JSON is not valid UTF-8", nil)
	}
	content = strings.TrimSpace(content)
	if content == "" {
		return modelAuditResponse{}, newAuditModelCallError("empty_response", 0, "audit model returned empty content", nil)
	}
	if depth > 5 {
		return modelAuditResponse{}, newAuditModelCallError("output_limits", 0, "audit model encoded-wrapper depth exceeded", nil)
	}
	decoded, err := decodeAuditJSON(content)
	if err == nil {
		result, found, err := auditModelResponseFromValue(decoded, depth)
		if found || err != nil {
			return result, err
		}
		return modelAuditResponse{}, auditSchemaError("decision", "is missing from the response")
	}
	class, _, _ := auditModelErrorDetails(err)
	if class != "invalid_json" {
		return modelAuditResponse{}, err
	}
	// Only recover complete objects in prose/fences, never a valid substring of
	// a broken JSON container (e.g. a truncated array with an early allow).
	if strings.HasPrefix(content, "[") || strings.HasPrefix(content, "\"") {
		return modelAuditResponse{}, err
	}
	candidates := balancedJSONObjects(content)
	if len(candidates) > maxAuditPolicyCandidates {
		return modelAuditResponse{}, newAuditModelCallError("output_limits", 0, "audit model policy candidate limit exceeded", nil)
	}
	var selected modelAuditResponse
	foundCount := 0
	for _, candidate := range candidates {
		value, decodeErr := decodeAuditJSON(candidate)
		if decodeErr != nil {
			return modelAuditResponse{}, decodeErr
		}
		result, found, parseErr := auditModelResponseFromValue(value, depth)
		if parseErr != nil {
			return modelAuditResponse{}, parseErr
		}
		if found {
			selected = result
			foundCount++
		}
	}
	if foundCount > 1 {
		return modelAuditResponse{}, newAuditModelCallError("ambiguous_output", 0, "audit model emitted multiple policy objects; refusing to select an allow", nil)
	}
	if foundCount == 1 {
		if strings.HasPrefix(content, "{") && strings.TrimSpace(content) != strings.TrimSpace(candidates[0]) {
			return modelAuditResponse{}, newAuditModelCallError("invalid_json", 0, "audit model JSON contains trailing data", nil)
		}
		// Unmatched braces outside a recovered object indicate truncated output.
		rest := strings.Replace(content, candidates[0], "", 1)
		if strings.ContainsAny(rest, "{}") {
			return modelAuditResponse{}, newAuditModelCallError("invalid_json", 0, "audit model output includes an incomplete JSON object", nil)
		}
		return selected, nil
	}
	return modelAuditResponse{}, newAuditModelCallError("invalid_json", 0, "audit model output did not contain a policy JSON object", nil)
}

func auditModelResponseFromValue(value any, depth int) (modelAuditResponse, bool, error) {
	if depth > 5 {
		return modelAuditResponse{}, false, newAuditModelCallError("output_limits", 0, "audit model wrapper depth exceeded", nil)
	}
	switch typed := value.(type) {
	case map[string]any:
		if _, exists := typed["decision"]; exists {
			for _, key := range []string{"result", "policy", "decision_result", "output", "response", "data"} {
				if child, ok := typed[key]; ok {
					_, found, err := auditModelResponseFromValue(child, depth+1)
					if err != nil {
						return modelAuditResponse{}, false, err
					}
					if found {
						return modelAuditResponse{}, false, newAuditModelCallError("ambiguous_output", 0, "direct policy contains another nested policy", nil)
					}
				}
			}
			result, err := decodeAuditPolicyObject(typed)
			return result, true, err
		}
		var selected modelAuditResponse
		foundCount := 0
		for _, key := range []string{"result", "policy", "decision_result", "output", "response", "data"} {
			if child, exists := typed[key]; exists {
				result, found, err := auditModelResponseFromValue(child, depth+1)
				if err != nil {
					return result, found, err
				}
				if found {
					selected = result
					foundCount++
				}
			}
		}
		if foundCount > 1 {
			return selected, false, newAuditModelCallError("ambiguous_output", 0, "audit model emitted multiple nested policies", nil)
		}
		return selected, foundCount == 1, nil
	case []any:
		if len(typed) > maxAuditPolicyCandidates {
			return modelAuditResponse{}, false, newAuditModelCallError("output_limits", 0, "audit model array candidate limit exceeded", nil)
		}
		var selected modelAuditResponse
		foundCount := 0
		for _, child := range typed {
			result, found, err := auditModelResponseFromValue(child, depth+1)
			if err != nil {
				return result, found, err
			}
			if found {
				selected = result
				foundCount++
			}
		}
		if foundCount > 1 {
			return selected, false, newAuditModelCallError("ambiguous_output", 0, "audit model emitted multiple array policies", nil)
		}
		return selected, foundCount == 1, nil
	case string:
		if strings.TrimSpace(typed) == "" {
			return modelAuditResponse{}, false, nil
		}
		result, err := parseAuditModelResponseContentDepth(typed, depth+1)
		return result, err == nil, err
	}
	return modelAuditResponse{}, false, nil
}

func auditConfidenceDisplay(kind, label string, value float64) string {
	if kind == "qualitative" {
		return label + " (qualitative; not a probability)"
	}
	return fmt.Sprint(value)
}
