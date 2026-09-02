package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	defaultTraceSearchLimit  = 200
	maximumTraceSearchLimit  = 1000
	maximumTraceSearchOffset = 1000000
	maximumTraceSearchWindow = 366 * 24 * time.Hour
)

type TraceSearchFilter struct {
	Query           string
	RequestID       string
	NewAPIRequestID string
	ExternalEventID string
	Source          string
	RouteSlug       string
	UserID          string
	UserMatch       string
	TenantID        string
	Model           string
	Endpoint        string
	Decision        string
	RiskCode        string
	HTTPStatus      *int
	UpstreamStatus  *int
	From            time.Time
	To              time.Time
	Limit           int
	Offset          int
}

type TraceSearchSummary struct {
	AllowedRequests  int64   `json:"allowed_requests"`
	BlockedRequests  int64   `json:"blocked_requests"`
	ErrorRequests    int64   `json:"error_requests"`
	ReviewRequests   int64   `json:"review_requests"`
	AverageLatencyMS float64 `json:"average_latency_ms"`
}

type TraceSearchResponse struct {
	Items   []TraceEvent       `json:"items"`
	Total   int64              `json:"total"`
	Limit   int                `json:"limit"`
	Offset  int                `json:"offset"`
	HasMore bool               `json:"has_more"`
	From    time.Time          `json:"from"`
	To      time.Time          `json:"to"`
	Summary TraceSearchSummary `json:"summary"`
}

func (s *HTTPService) adminSearchTraces(w http.ResponseWriter, r *http.Request) {
	filter, err := parseTraceSearchFilter(r.URL.Query(), time.Now().UTC())
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_trace_filter", err.Error())
		return
	}
	result, err := s.store.SearchTraces(r.Context(), filter)
	if err != nil {
		s.log.Warn("request trace search failed", "error", err)
		writeAPIError(w, http.StatusInternalServerError, "traces_error", "could not search request traces")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func parseTraceSearchFilter(values url.Values, now time.Time) (TraceSearchFilter, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	filter := TraceSearchFilter{
		Query:           traceSearchValue(values.Get("q"), 300),
		RequestID:       traceSearchValue(values.Get("request_id"), 128),
		NewAPIRequestID: traceSearchValue(values.Get("newapi_request_id"), 128),
		ExternalEventID: traceSearchValue(values.Get("external_event_id"), 200),
		Source:          strings.ToLower(traceSearchValue(values.Get("source"), 30)),
		RouteSlug:       strings.ToLower(traceSearchValue(values.Get("route_slug"), 100)),
		UserID:          traceSearchValue(values.Get("user_id"), 200),
		UserMatch:       strings.ToLower(traceSearchValue(values.Get("user_match"), 20)),
		TenantID:        traceSearchValue(values.Get("tenant_id"), 200),
		Model:           traceSearchValue(values.Get("model"), 200),
		Endpoint:        traceSearchValue(values.Get("endpoint"), 300),
		Decision:        strings.ToLower(traceSearchValue(values.Get("decision"), 30)),
		RiskCode:        strings.ToUpper(traceSearchValue(values.Get("risk_code"), 200)),
		From:            now.Add(-24 * time.Hour),
		To:              now,
		Limit:           defaultTraceSearchLimit,
	}
	if filter.UserMatch == "" {
		filter.UserMatch = "exact"
	}
	if filter.UserMatch != "exact" && filter.UserMatch != "prefix" && filter.UserMatch != "contains" {
		return TraceSearchFilter{}, fmt.Errorf("user_match must be exact, prefix, or contains")
	}
	if filter.Query != "" && utf8.RuneCountInString(filter.Query) < 3 {
		return TraceSearchFilter{}, fmt.Errorf("q must contain at least 3 characters")
	}
	if filter.UserID != "" && filter.UserMatch != "exact" && utf8.RuneCountInString(filter.UserID) < 2 {
		return TraceSearchFilter{}, fmt.Errorf("prefix or contains user search requires at least 2 characters")
	}
	switch filter.Decision {
	case "", DecisionAllow, DecisionBlock, DecisionReview, "error", "unknown":
	default:
		return TraceSearchFilter{}, fmt.Errorf("decision is invalid")
	}

	var err error
	if raw := strings.TrimSpace(values.Get("from")); raw != "" {
		filter.From, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return TraceSearchFilter{}, fmt.Errorf("from must use RFC3339")
		}
		filter.From = filter.From.UTC()
	}
	if raw := strings.TrimSpace(values.Get("to")); raw != "" {
		filter.To, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return TraceSearchFilter{}, fmt.Errorf("to must use RFC3339")
		}
		filter.To = filter.To.UTC()
	}
	if !filter.From.Before(filter.To) {
		return TraceSearchFilter{}, fmt.Errorf("from must be earlier than to")
	}
	if filter.To.Sub(filter.From) > maximumTraceSearchWindow {
		return TraceSearchFilter{}, fmt.Errorf("time range may not exceed 366 days")
	}

	if raw := strings.TrimSpace(values.Get("limit")); raw != "" {
		filter.Limit, err = strconv.Atoi(raw)
		if err != nil || filter.Limit < 1 || filter.Limit > maximumTraceSearchLimit {
			return TraceSearchFilter{}, fmt.Errorf("limit must be between 1 and %d", maximumTraceSearchLimit)
		}
	}
	if raw := strings.TrimSpace(values.Get("offset")); raw != "" {
		filter.Offset, err = strconv.Atoi(raw)
		if err != nil || filter.Offset < 0 || filter.Offset > maximumTraceSearchOffset {
			return TraceSearchFilter{}, fmt.Errorf("offset must be between 0 and %d", maximumTraceSearchOffset)
		}
	}
	filter.HTTPStatus, err = parseTraceStatus(values.Get("http_status"), "http_status")
	if err != nil {
		return TraceSearchFilter{}, err
	}
	filter.UpstreamStatus, err = parseTraceStatus(values.Get("upstream_status"), "upstream_status")
	if err != nil {
		return TraceSearchFilter{}, err
	}
	return filter, nil
}

func parseTraceStatus(raw string, name string) (*int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 || value > 999 {
		return nil, fmt.Errorf("%s must be an integer between 0 and 999", name)
	}
	return &value, nil
}

func traceSearchValue(value string, maximum int) string {
	value = strings.TrimSpace(value)
	value = truncateString(value, maximum)
	return strings.ToValidUTF8(value, "")
}

func (s *Store) SearchTraces(ctx context.Context, filter TraceSearchFilter) (TraceSearchResponse, error) {
	whereSQL, arguments := buildTraceSearchWhere(filter)
	result := TraceSearchResponse{
		Items:  make([]TraceEvent, 0, filter.Limit),
		Limit:  filter.Limit,
		Offset: filter.Offset,
		From:   filter.From,
		To:     filter.To,
	}
	if err := s.pool.QueryRow(ctx, `SELECT
		count(*),
		count(*) FILTER (WHERE decision='allow'),
		count(*) FILTER (WHERE decision='block'),
		count(*) FILTER (WHERE decision='error'),
		count(*) FILTER (WHERE decision='review'),
		COALESCE(avg(latency_ms),0)::double precision
		FROM request_traces WHERE `+whereSQL, arguments...).Scan(
		&result.Total,
		&result.Summary.AllowedRequests,
		&result.Summary.BlockedRequests,
		&result.Summary.ErrorRequests,
		&result.Summary.ReviewRequests,
		&result.Summary.AverageLatencyMS,
	); err != nil {
		return result, err
	}

	pageArguments := append([]any(nil), arguments...)
	pageArguments = append(pageArguments, filter.Limit, filter.Offset)
	limitPlaceholder := "$" + strconv.Itoa(len(pageArguments)-1)
	offsetPlaceholder := "$" + strconv.Itoa(len(pageArguments))
	rows, err := s.pool.Query(ctx, `SELECT request_id,external_event_id,source,route_slug,newapi_request_id,
		external_user_id,model,endpoint,decision,risk_code,http_status,upstream_status,
		latency_ms,audit_latency_ms,request_bytes,response_bytes,prompt_hmac,metadata,created_at
		FROM request_traces WHERE `+whereSQL+
		" ORDER BY created_at DESC, request_id DESC, external_event_id DESC LIMIT "+limitPlaceholder+
		" OFFSET "+offsetPlaceholder, pageArguments...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var event TraceEvent
		var metadata []byte
		if err := rows.Scan(
			&event.RequestID, &event.ExternalEventID, &event.Source, &event.RouteSlug,
			&event.NewAPIRequestID, &event.ExternalUserID, &event.Model, &event.Endpoint,
			&event.Decision, &event.RiskCode, &event.HTTPStatus, &event.UpstreamStatus,
			&event.LatencyMS, &event.AuditLatencyMS, &event.RequestBytes, &event.ResponseBytes,
			&event.PromptHMAC, &metadata, &event.CreatedAt,
		); err != nil {
			return result, err
		}
		event.Metadata = map[string]any{}
		_ = json.Unmarshal(metadata, &event.Metadata)
		result.Items = append(result.Items, event)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	result.HasMore = int64(filter.Offset+len(result.Items)) < result.Total
	return result, nil
}

func buildTraceSearchWhere(filter TraceSearchFilter) (string, []any) {
	clauses := []string{"created_at >= $1", "created_at <= $2"}
	arguments := []any{filter.From, filter.To}
	addEqual := func(expression string, value any, enabled bool) {
		if !enabled {
			return
		}
		arguments = append(arguments, value)
		clauses = append(clauses, expression+" = $"+strconv.Itoa(len(arguments)))
	}
	addPattern := func(expression string, pattern string) {
		arguments = append(arguments, pattern)
		clauses = append(clauses, "lower("+expression+") LIKE lower($"+strconv.Itoa(len(arguments))+")")
	}
	addContains := func(expression string, value string) {
		if value == "" {
			return
		}
		addPattern(expression, "%"+escapeLikePattern(value)+"%")
	}

	addEqual("request_id", filter.RequestID, filter.RequestID != "")
	addEqual("newapi_request_id", filter.NewAPIRequestID, filter.NewAPIRequestID != "")
	addEqual("external_event_id", filter.ExternalEventID, filter.ExternalEventID != "")
	addEqual("source", filter.Source, filter.Source != "")
	addEqual("route_slug", filter.RouteSlug, filter.RouteSlug != "")
	addEqual("metadata ->> 'tenant_id'", filter.TenantID, filter.TenantID != "")
	addEqual("decision", filter.Decision, filter.Decision != "")
	addEqual("risk_code", filter.RiskCode, filter.RiskCode != "")
	if filter.HTTPStatus != nil {
		addEqual("http_status", *filter.HTTPStatus, true)
	}
	if filter.UpstreamStatus != nil {
		addEqual("upstream_status", *filter.UpstreamStatus, true)
	}

	if filter.UserID != "" {
		switch filter.UserMatch {
		case "prefix":
			addPattern("external_user_id", escapeLikePattern(filter.UserID)+"%")
		case "contains":
			addPattern("external_user_id", "%"+escapeLikePattern(filter.UserID)+"%")
		default:
			addEqual("external_user_id", filter.UserID, true)
		}
	}
	addContains("model", filter.Model)
	addContains("endpoint", filter.Endpoint)

	if filter.Query != "" {
		arguments = append(arguments, "%"+escapeLikePattern(filter.Query)+"%")
		placeholder := "$" + strconv.Itoa(len(arguments))
		columns := []string{
			"request_id",
			"newapi_request_id",
			"external_event_id",
			"external_user_id",
			"model",
			"endpoint",
			"route_slug",
			"risk_code",
			"source",
			"COALESCE(metadata ->> 'tenant_id','')",
		}
		matches := make([]string, 0, len(columns))
		for _, column := range columns {
			matches = append(matches, "lower("+column+") LIKE lower("+placeholder+")")
		}
		clauses = append(clauses, "("+strings.Join(matches, " OR ")+")")
	}
	return strings.Join(clauses, " AND "), arguments
}

func escapeLikePattern(value string) string {
	return strings.NewReplacer(
		`\`, `\\`,
		`%`, `\%`,
		`_`, `\_`,
	).Replace(value)
}
