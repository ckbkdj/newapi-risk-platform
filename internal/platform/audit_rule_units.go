package platform

import (
	"regexp"
	"strings"
)

const auditRuleUnitMaxBytes = 8192

type auditRuleUnit struct {
	Index int
	Kind  string
	Text  string
}

type RuleSuppressionDiagnostic struct {
	RuleCode    string `json:"rule_code"`
	UnitIndex   int    `json:"unit_index"`
	Reason      string `json:"reason"`
	MatchedText string `json:"matched_text,omitempty"`
}

var (
	markdownListPattern       = regexp.MustCompile(`^\s*(?:[-*+]\s+|\d+[.)]\s+)`)
	artifactC2FragmentPattern = regexp.MustCompile(`(?i)(?:codex-clipboard|[cC][0-9a-f]{8,}|\[CLIPBOARD_IMAGE\]|\[ARTIFACT_ID\]|\[TEMP_PATH\])`)
)

func splitAuditRuleUnits(text string) []auditRuleUnit {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	units := make([]auditRuleUnit, 0, len(lines)/2+1)
	var builder strings.Builder
	kind := "paragraph"
	inFence := false
	flush := func() {
		value := strings.TrimSpace(builder.String())
		builder.Reset()
		if value == "" {
			return
		}
		appendAuditRuleUnit(&units, kind, value)
	}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ROLE=") {
			flush()
			continue
		}
		if strings.HasPrefix(trimmed, "```") {
			if !inFence {
				flush()
				kind = "code"
				inFence = true
			} else {
				if builder.Len() > 0 {
					builder.WriteByte('\n')
				}
				builder.WriteString(line)
				flush()
				kind = "paragraph"
				inFence = false
				continue
			}
		}
		if !inFence && (trimmed == "" || markdownListPattern.MatchString(line) || strings.HasPrefix(trimmed, "#")) {
			flush()
			if trimmed == "" {
				continue
			}
			kind = map[bool]string{true: "list_item", false: "heading"}[markdownListPattern.MatchString(line)]
			builder.WriteString(line)
			flush()
			kind = "paragraph"
			continue
		}
		if builder.Len() > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(line)
	}
	flush()
	return units
}

func appendAuditRuleUnit(units *[]auditRuleUnit, kind string, value string) {
	for len(value) > auditRuleUnitMaxBytes {
		end := auditRuleUnitMaxBytes
		for end > 0 && (value[end]&0xC0) == 0x80 {
			end--
		}
		if end <= 0 {
			end = auditRuleUnitMaxBytes
		}
		*units = append(*units, auditRuleUnit{Index: len(*units) + 1, Kind: kind, Text: value[:end]})
		next := end - 256
		if next < 0 {
			next = end
		}
		value = value[next:]
	}
	if strings.TrimSpace(value) != "" {
		*units = append(*units, auditRuleUnit{Index: len(*units) + 1, Kind: kind, Text: value})
	}
}

func shouldSuppressEngineeringRuleMatch(policy AuditPolicy, rule CyberRule, unit string, evidence cyberRuleEvidence) (bool, string) {
	code := strings.ToUpper(strings.TrimSpace(rule.Code))
	matched := unit
	if evidence.start >= 0 && evidence.end >= evidence.start && evidence.end <= len(unit) {
		matched = unit[evidence.start:evidence.end]
	}
	switch code {
	case "CYBER_C2_INFRASTRUCTURE":
		if artifactC2FragmentPattern.MatchString(matched) && !explicitC2Pattern.MatchString(matched) {
			return true, "artifact_or_hex_fragment_without_standalone_c2_semantics"
		}
		if !explicitC2Pattern.MatchString(matched) {
			return true, "generic_server_text_without_c2_semantics"
		}
	case "CYBER_SESSION_HIJACKING":
		if benignReplayPattern.MatchString(matched) && !authMaterialPattern.MatchString(matched) {
			return true, "engineering_replay_without_authentication_material"
		}
	case "CYBER_PERSISTENCE":
		if benignPersistencePattern.MatchString(matched) && !maliciousPersistencePattern.MatchString(matched) {
			return true, "application_data_persistence_without_startup_or_implant_semantics"
		}
	case "CYBER_CREDENTIAL_THEFT", "CYBER_CLOUD_SECRET_THEFT", "CYBER_CREDENTIAL_ACCESS_REVIEW":
		if policy.Mode == AuditPolicyModeInternalEngineering && !hasDangerousSecretIntent(unit) {
			if policy.AllowUserProvidedSecrets && isUserProvidedSecretConfiguration(unit) {
				return true, "requester_provided_secret_configuration_requires_semantic_policy_not_hard_block"
			}
			if policy.AllowLocalDebugCredentials && isLocalDebugCredentialUse(unit) {
				return true, "local_debug_credential_use_requires_semantic_policy_not_hard_block"
			}
		}
	}
	return false, ""
}
