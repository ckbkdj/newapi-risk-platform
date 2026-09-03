package platform

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

func normalizeManualCandidateAction(value string) (string, error) {
	action := strings.ToLower(strings.TrimSpace(value))
	switch action {
	case DecisionReview, DecisionBlock:
		return action, nil
	default:
		return "", errors.New("action must be review or block")
	}
}

func normalizeCandidateWorkflowStatus(value string) (string, error) {
	status := strings.ToLower(strings.TrimSpace(value))
	switch status {
	case "shadow", "rejected":
		return status, nil
	default:
		return "", errors.New("status must be shadow or rejected")
	}
}

func (s *Store) PromoteCyberRuleCandidateManual(
	ctx context.Context,
	id int64,
	requestedAction string,
) (CyberRuleCandidate, CyberRule, error) {
	action, err := normalizeManualCandidateAction(requestedAction)
	if err != nil {
		return CyberRuleCandidate{}, CyberRule{}, err
	}

	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return CyberRuleCandidate{}, CyberRule{}, err
	}
	defer transaction.Rollback(ctx)

	candidate, err := scanCyberRuleCandidate(transaction.QueryRow(ctx,
		`SELECT `+cyberRuleCandidateColumns+`
		 FROM cyber_rule_candidates
		 WHERE id=$1
		 FOR UPDATE`,
		id,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return CyberRuleCandidate{}, CyberRule{}, ErrNotFound
	}
	if err != nil {
		return CyberRuleCandidate{}, CyberRule{}, err
	}
	if candidate.Status != "candidate" && candidate.Status != "shadow" {
		return CyberRuleCandidate{}, CyberRule{}, fmt.Errorf(
			"candidate cannot be promoted from status %q",
			candidate.Status,
		)
	}

	ruleInput := CyberRule{
		Code:        candidate.ProposedCode,
		Name:        truncateString("Adaptive approved: "+candidate.Category, 200),
		Description: truncateString("Manually approved through the Shadow-first workflow. "+candidate.Reason, 2000),
		Category:    candidate.Category,
		Pattern:     candidate.Pattern,
		PatternType: candidate.PatternType,
		Action:      action,
		Priority:    1200,
		Enabled:     true,
	}
	if err := ValidateCyberRule(ruleInput); err != nil {
		return CyberRuleCandidate{}, CyberRule{}, fmt.Errorf("candidate rule is invalid: %w", err)
	}

	const ruleColumns = `id,code,name,description,category,pattern,pattern_type,action,priority,enabled,created_at,updated_at`
	rule, err := scanCyberRule(transaction.QueryRow(ctx, `INSERT INTO cyber_rules
		(code,name,description,category,pattern,pattern_type,action,priority,enabled)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,TRUE)
		ON CONFLICT(code) DO UPDATE SET
			name=EXCLUDED.name,
			description=EXCLUDED.description,
			category=EXCLUDED.category,
			pattern=EXCLUDED.pattern,
			pattern_type=EXCLUDED.pattern_type,
			action=EXCLUDED.action,
			priority=EXCLUDED.priority,
			enabled=TRUE,
			updated_at=now()
		RETURNING `+ruleColumns,
		ruleInput.Code,
		ruleInput.Name,
		ruleInput.Description,
		ruleInput.Category,
		ruleInput.Pattern,
		ruleInput.PatternType,
		ruleInput.Action,
		ruleInput.Priority,
	))
	if err != nil {
		return CyberRuleCandidate{}, CyberRule{}, err
	}

	command, err := transaction.Exec(ctx, `UPDATE cyber_rule_candidates
		SET status='promoted',
			proposed_action=$3,
			promoted_rule_id=$2,
			updated_at=now()
		WHERE id=$1 AND status IN ('candidate','shadow')`,
		candidate.ID,
		rule.ID,
		action,
	)
	if err != nil {
		return CyberRuleCandidate{}, CyberRule{}, err
	}
	if command.RowsAffected() != 1 {
		return CyberRuleCandidate{}, CyberRule{}, errors.New("candidate status changed during promotion")
	}
	if err := transaction.Commit(ctx); err != nil {
		return CyberRuleCandidate{}, CyberRule{}, err
	}

	candidate.Status = "promoted"
	candidate.ProposedAction = action
	candidate.PromotedRuleID = &rule.ID
	return candidate, rule, nil
}

func (s *HTTPService) adminListCyberRuleCandidates(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1000 {
			writeAPIError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 1000")
			return
		}
		limit = parsed
	}
	items, err := s.store.ListCyberRuleCandidates(r.Context(), limit)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "candidate_list_failed", "could not load adaptive rule candidates")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"policy": s.audit.AdaptivePolicy(),
	})
}

func (s *HTTPService) adminSetCyberRuleCandidateStatus(w http.ResponseWriter, r *http.Request) {
	id, err := parsePathID(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_id", "candidate id is invalid")
		return
	}
	var input struct {
		Status string `json:"status"`
	}
	if err := decodeJSONBody(w, r, 16*1024, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	status, err := normalizeCandidateWorkflowStatus(input.Status)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_status", err.Error())
		return
	}
	if err := s.store.SetCyberRuleCandidateStatus(r.Context(), id, status); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "candidate was not found or is already promoted")
			return
		}
		writeAPIError(w, http.StatusConflict, "candidate_update_failed", "candidate status could not be updated")
		return
	}
	s.auditAdmin(r, "set_status", "cyber_rule_candidate", strconv.FormatInt(id, 10), map[string]any{
		"status": status,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"id":     id,
		"status": status,
	})
}

func (s *HTTPService) adminPromoteCyberRuleCandidate(w http.ResponseWriter, r *http.Request) {
	id, err := parsePathID(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_id", "candidate id is invalid")
		return
	}
	var input struct {
		Action string `json:"action"`
	}
	if err := decodeJSONBody(w, r, 16*1024, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	action, err := normalizeManualCandidateAction(input.Action)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_action", err.Error())
		return
	}

	candidate, rule, err := s.store.PromoteCyberRuleCandidateManual(r.Context(), id, action)
	if errors.Is(err, ErrNotFound) {
		writeAPIError(w, http.StatusNotFound, "not_found", "candidate was not found")
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusConflict, "candidate_promotion_failed", err.Error())
		return
	}
	if err := s.audit.ReloadRules(r.Context()); err != nil {
		s.log.Warn("manual adaptive rule reload failed", "candidate_id", candidate.ID, "rule_id", rule.ID, "error", err)
		writeAPIError(w, http.StatusInternalServerError, "rule_reload_failed", "candidate was promoted but the in-memory rule set could not be reloaded")
		return
	}
	s.auditAdmin(r, "promote", "cyber_rule_candidate", strconv.FormatInt(id, 10), map[string]any{
		"action":  action,
		"rule_id": rule.ID,
		"code":    rule.Code,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"candidate": candidate,
		"rule":      rule,
	})
}
