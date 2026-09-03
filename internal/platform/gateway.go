package platform

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	gatewayRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "newapi_risk",
			Name:      "gateway_requests_total",
			Help:      "Gateway requests by route and outcome.",
		},
		[]string{"route", "outcome"},
	)
	gatewayDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "newapi_risk",
			Name:      "gateway_duration_seconds",
			Help:      "End-to-end gateway latency.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"route"},
	)
	auditDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "newapi_risk",
			Name:      "audit_duration_seconds",
			Help:      "Rule and model audit latency.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"route"},
	)
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
)

func init() {
	prometheus.MustRegister(gatewayRequests, gatewayDuration, auditDuration)
}

type cachedRoute struct {
	route     Route
	expiresAt time.Time
}

type Gateway struct {
	cfg         Config
	store       *Store
	security    *Security
	redis       *RedisGuard
	audit       *AuditEngine
	traces      *TraceWriter
	client      *http.Client
	global      chan struct{}
	largeBodies chan struct{}
	log         *slog.Logger
	cacheMu     sync.RWMutex
	routeCache  map[string]cachedRoute
}

func NewGateway(
	cfg Config,
	store *Store,
	security *Security,
	redis *RedisGuard,
	audit *AuditEngine,
	traces *TraceWriter,
	log *slog.Logger,
) *Gateway {
	return &Gateway{
		cfg:      cfg,
		store:    store,
		security: security,
		redis:    redis,
		audit:    audit,
		traces:   traces,
		client: &http.Client{
			Transport: NewSafeTransport(cfg.AllowPrivateUpstreams, cfg.UpstreamTLSMinVersion),
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("upstream redirects are disabled")
			},
		},
		global:      make(chan struct{}, cfg.GlobalMaxConcurrency),
		largeBodies: make(chan struct{}, cfg.LargeRequestMaxConcurrency),
		log:         log,
		routeCache:  make(map[string]cachedRoute),
	}
}

func (g *Gateway) InvalidateRoute(slug string) {
	g.cacheMu.Lock()
	defer g.cacheMu.Unlock()
	if slug == "" {
		clear(g.routeCache)
		return
	}
	delete(g.routeCache, slug)
}

func (g *Gateway) getRoute(ctx context.Context, slug string) (Route, error) {
	now := time.Now()
	g.cacheMu.RLock()
	cached, ok := g.routeCache[slug]
	g.cacheMu.RUnlock()
	if ok && cached.expiresAt.After(now) {
		return cached.route, nil
	}
	route, err := g.store.GetRouteBySlug(ctx, slug)
	if err != nil {
		return Route{}, err
	}
	g.cacheMu.Lock()
	g.routeCache[slug] = cachedRoute{route: route, expiresAt: now.Add(g.cfg.RouteCacheTTL)}
	g.cacheMu.Unlock()
	return route, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	startedAt := started.UTC()
	inboundRequestID := normalizeRequestID(r.Header.Get("X-Request-ID"))
	requestID := inboundRequestID
	requestIDSource := "x_request_id"
	if requestID == "" {
		requestID = NewRequestID()
		requestIDSource = "generated"
	}
	w.Header().Set("X-Risk-Request-ID", requestID)
	w.Header().Set("X-Risk-Started-At", startedAt.Format(time.RFC3339Nano))

	if r.Method == http.MethodConnect || r.Method == http.MethodTrace {
		writeGatewayError(w, http.StatusMethodNotAllowed, requestID, "METHOD_NOT_ALLOWED", "method is not allowed")
		return
	}
	slug := chi.URLParam(r, "route")
	if slug == "" {
		writeGatewayError(w, http.StatusNotFound, requestID, "ROUTE_NOT_FOUND", "risk route not found")
		return
	}
	trace := TraceEvent{
		RequestID:       requestID,
		Source:          "gateway",
		RouteSlug:       slug,
		NewAPIRequestID: firstNonEmpty(normalizeRequestID(r.Header.Get("X-NewAPI-Request-ID")), inboundRequestID),
		ExternalUserID: normalizeIdentifier(firstNonEmpty(
			r.Header.Get("X-NewAPI-User-ID"),
			r.Header.Get("X-User-ID"),
		)),
		Endpoint:  truncateString(chi.URLParam(r, "*"), 300),
		StartedAt: startedAt,
		CreatedAt: startedAt,
		Metadata: map[string]any{
			"request_id_source":  requestIDSource,
			"gateway_started_at": startedAt.Format(time.RFC3339Nano),
		},
	}
	finished := false
	finish := func(decision string, riskCode string, status int, upstreamStatus int, responseBytes int64) {
		if finished {
			return
		}
		finished = true
		trace.Decision = decision
		trace.RiskCode = riskCode
		trace.HTTPStatus = status
		trace.UpstreamStatus = upstreamStatus
		trace.ResponseBytes = responseBytes
		trace.CompletedAt = time.Now().UTC()
		trace.LatencyMS = time.Since(started).Milliseconds()
		trace.Metadata["gateway_completed_at"] = trace.CompletedAt.Format(time.RFC3339Nano)
		trace.Metadata["timeline_duration_ms"] = trace.LatencyMS
		if riskCode != "" {
			trace.Metadata["error_reason"] = traceFailureReason(riskCode, upstreamStatus, trace.Metadata)
		}
		g.traces.Submit(trace)
		gatewayRequests.WithLabelValues(slug, decision).Inc()
		gatewayDuration.WithLabelValues(slug).Observe(time.Since(started).Seconds())
	}

	route, err := g.getRoute(r.Context(), slug)
	if err != nil || !route.Enabled {
		finish("error", "ROUTE_NOT_FOUND", http.StatusNotFound, 0, 0)
		writeGatewayError(w, http.StatusNotFound, requestID, "ROUTE_NOT_FOUND", "risk route not found")
		return
	}
	inboundCredential := strings.TrimSpace(r.Header.Get("X-Risk-Gateway-Key"))
	if inboundCredential == "" {
		inboundCredential = bearerToken(r.Header.Get("Authorization"))
	}
	if !g.security.VerifyDigest("route-inbound-key-v1", inboundCredential, route.InboundKeyDigest) {
		finish("error", "GATEWAY_AUTH_FAILED", http.StatusUnauthorized, 0, 0)
		writeGatewayError(w, http.StatusUnauthorized, requestID, "GATEWAY_AUTH_FAILED", "invalid gateway credential")
		return
	}

	clientIdentity := firstNonEmpty(trace.ExternalUserID, remoteIP(r))
	rateDigest := g.security.Digest("rate-limit-key-v1", slug+"|"+clientIdentity)
	if !g.redis.Allow(r.Context(), rateDigest[:32], route.RateLimitRPS, route.RateLimitBurst) {
		finish("error", "RATE_LIMITED", http.StatusTooManyRequests, 0, 0)
		w.Header().Set("Retry-After", "1")
		writeGatewayError(w, http.StatusTooManyRequests, requestID, "RATE_LIMITED", "request rate limit exceeded")
		return
	}
	select {
	case g.global <- struct{}{}:
		defer func() { <-g.global }()
	default:
		finish("error", "GATEWAY_OVERLOADED", http.StatusServiceUnavailable, 0, 0)
		writeGatewayError(w, http.StatusServiceUnavailable, requestID, "GATEWAY_OVERLOADED", "gateway concurrency limit reached")
		return
	}

	bodyPolicy := resolveRequestBodyLimit(g.cfg.RequestMaxBytes, g.cfg.RequestHardMaxBytes, r.ContentLength)
	trace.Metadata["request_body_limit_mode"] = bodyPolicy.Mode
	trace.Metadata["request_body_effective_limit_bytes"] = bodyPolicy.EffectiveLimitBytes
	trace.Metadata["request_body_hard_limit_bytes"] = bodyPolicy.HardLimitBytes
	if bodyPolicy.ConfiguredLimitBytes > 0 {
		trace.Metadata["request_body_configured_limit_bytes"] = bodyPolicy.ConfiguredLimitBytes
	}

	// In automatic mode a known Content-Length is admitted at its actual size
	// up to the hard ceiling. This lets large but valid NewAPI payloads pass
	// without an operator manually chasing each observed body size.
	if bodyPolicy.ExceedsKnownLength(r.ContentLength) {
		reason := markRequestTooLarge(&trace, r.ContentLength, bodyPolicy, true)
		w.Header().Set("X-Risk-Request-Bytes", fmt.Sprintf("%d", trace.RequestBytes))
		w.Header().Set("X-Risk-Request-Limit-Bytes", fmt.Sprintf("%d", bodyPolicy.EffectiveLimitBytes))
		w.Header().Set("X-Risk-Request-Hard-Limit-Bytes", fmt.Sprintf("%d", bodyPolicy.HardLimitBytes))
		w.Header().Set("X-Risk-Request-Limit-Mode", bodyPolicy.Mode)
		w.Header().Set("X-Risk-Request-Size-Exact", "true")
		finish("error", "REQUEST_TOO_LARGE", g.cfg.ErrorHTTPStatus, 0, 0)
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "REQUEST_TOO_LARGE", reason)
		return
	}

	if requestBodyNeedsLargeSlot(r.ContentLength, g.cfg.LargeRequestThresholdBytes) {
		select {
		case g.largeBodies <- struct{}{}:
			defer func() { <-g.largeBodies }()
			trace.Metadata["large_request_slot"] = true
			trace.Metadata["large_request_max_concurrency"] = g.cfg.LargeRequestMaxConcurrency
		default:
			trace.Metadata["error_origin"] = "risk_gateway"
			trace.Metadata["failure_stage"] = "gateway_ingress"
			trace.Metadata["failure_component"] = "large_request_memory_guard"
			trace.Metadata["error_reason"] = "large request concurrency limit reached; retry when another large request finishes"
			finish("error", "LARGE_REQUEST_CONCURRENCY_LIMITED", http.StatusServiceUnavailable, 0, 0)
			w.Header().Set("Retry-After", "1")
			writeGatewayError(w, http.StatusServiceUnavailable, requestID, "LARGE_REQUEST_CONCURRENCY_LIMITED", "large request concurrency limit reached")
			return
		}
	}

	bodyReader := http.MaxBytesReader(w, r.Body, bodyPolicy.EffectiveLimitBytes)
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			// Unknown-length requests are read only to the effective safety
			// boundary. Record a lower bound rather than claiming an exact size.
			observed := bodyPolicy.EffectiveLimitBytes + 1
			if int64(len(body)) > observed {
				observed = int64(len(body))
			}
			reason := markRequestTooLarge(&trace, observed, bodyPolicy, false)
			w.Header().Set("X-Risk-Request-Bytes", fmt.Sprintf("%d", trace.RequestBytes))
			w.Header().Set("X-Risk-Request-Limit-Bytes", fmt.Sprintf("%d", bodyPolicy.EffectiveLimitBytes))
			w.Header().Set("X-Risk-Request-Hard-Limit-Bytes", fmt.Sprintf("%d", bodyPolicy.HardLimitBytes))
			w.Header().Set("X-Risk-Request-Limit-Mode", bodyPolicy.Mode)
			w.Header().Set("X-Risk-Request-Size-Exact", "false")
			finish("error", "REQUEST_TOO_LARGE", g.cfg.ErrorHTTPStatus, 0, 0)
			writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "REQUEST_TOO_LARGE", reason)
			return
		}
		trace.RequestBytes = int64(len(body))
		trace.Metadata["error_class"] = "request_body_read"
		trace.Metadata["error_reason"] = truncateString("failed to read request body: "+err.Error(), auditDiagnosticTextLimit)
		finish("error", "REQUEST_READ_ERROR", g.cfg.ErrorHTTPStatus, 0, 0)
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "REQUEST_READ_ERROR", "gateway could not read the request body")
		return
	}
	trace.RequestBytes = int64(len(body))
	trace.Model = ExtractRequestedModel(body)

	auditResult := g.audit.Audit(r.Context(), route, body)
	trace.AuditLatencyMS = auditResult.Latency.Milliseconds()
	trace.PromptHMAC = auditResult.PromptHMAC
	trace.Metadata["audit_source"] = auditResult.Source
	trace.Metadata["audit_category"] = auditResult.Category
	trace.Metadata["audit_input_scope"] = auditResult.AuditInputScope
	trace.Metadata["audit_intent_bytes"] = auditResult.AuditIntentBytes
	trace.Metadata["audit_ignored_context_bytes"] = auditResult.AuditIgnoredContextBytes
	if len(auditResult.AuditIgnoredRoles) > 0 {
		trace.Metadata["audit_ignored_roles"] = auditResult.AuditIgnoredRoles
	}
	if match := auditResult.RuleMatch; match != nil {
		trace.Metadata["audit_rule_id"] = match.RuleID
		trace.Metadata["audit_rule_position"] = match.RulePosition
		trace.Metadata["audit_rule_code"] = match.RuleCode
		trace.Metadata["audit_rule_name"] = match.RuleName
		trace.Metadata["audit_rule_description"] = truncateString(match.RuleDescription, 1000)
		trace.Metadata["audit_rule_category"] = match.Category
		trace.Metadata["audit_rule_action"] = match.Action
		trace.Metadata["audit_rule_priority"] = match.Priority
		trace.Metadata["audit_rule_pattern_type"] = match.PatternType
		trace.Metadata["audit_rule_pattern"] = truncateString(match.Pattern, 1600)
		trace.Metadata["audit_rule_indicators"] = match.Indicators
		trace.Metadata["audit_rule_match"] = truncateString(match.MatchedText, 1200)
		trace.Metadata["audit_rule_context"] = truncateString(match.Context, 1600)
		trace.Metadata["audit_user_guidance"] = truncateString(match.UserGuidance, 1200)
		if match.Downgraded {
			trace.Metadata["audit_rule_downgraded_to_review"] = true
			trace.Metadata["audit_rule_downgrade_reason"] = truncateString(match.DowngradeReason, 1200)
		}
	}
	if auditResult.Model != "" {
		trace.Metadata["audit_model"] = auditResult.Model
	}
	if auditResult.Reason != "" {
		trace.Metadata["audit_reason"] = truncateString(auditResult.Reason, auditDiagnosticTextLimit)
	}
	if strings.HasPrefix(auditResult.Source, "model") {
		trace.Metadata["audit_model_decision"] = auditResult.Decision
		trace.Metadata["audit_model_risk_code"] = auditResult.RiskCode
		trace.Metadata["audit_model_confidence"] = auditResult.Confidence
	}
	if auditResult.EvidenceVerified {
		trace.Metadata["audit_model_evidence"] = truncateString(auditResult.Evidence, 1200)
		trace.Metadata["audit_model_evidence_context"] = truncateString(auditResult.EvidenceContext, 1600)
		trace.Metadata["audit_model_evidence_verified"] = true
		trace.Metadata["audit_model_evidence_match_mode"] = auditResult.EvidenceMatchMode
		if auditResult.EvidenceChunkIndex > 0 {
			trace.Metadata["audit_model_evidence_chunk_index"] = auditResult.EvidenceChunkIndex
			trace.Metadata["audit_model_evidence_chunk_count"] = auditResult.EvidenceChunkCount
		}
		trace.Metadata["audit_trigger_input"] = truncateString(auditResult.Evidence, 1200)
		trace.Metadata["audit_trigger_context"] = truncateString(auditResult.EvidenceContext, 1600)
		trace.Metadata["audit_model_user_guidance"] = truncateString(auditModelUserGuidance(auditResult.Category), 1200)
	} else if match := auditResult.RuleMatch; match != nil {
		trace.Metadata["audit_trigger_input"] = truncateString(match.MatchedText, 1200)
		trace.Metadata["audit_trigger_context"] = truncateString(match.Context, 1600)
	}
	if auditResult.ErrorClass != "" {
		trace.Metadata["audit_error_class"] = auditResult.ErrorClass
	}
	if auditResult.AuditHTTPStatus > 0 {
		trace.Metadata["audit_http_status"] = auditResult.AuditHTTPStatus
	}
	if auditResult.AuditMode != "" {
		trace.Metadata["audit_mode"] = auditResult.AuditMode
	}
	if auditResult.AuditChunkCount > 0 {
		trace.Metadata["audit_chunk_count"] = auditResult.AuditChunkCount
	}
	if auditResult.AuditChunkBytes > 0 {
		trace.Metadata["audit_chunk_bytes"] = auditResult.AuditChunkBytes
	}
	if auditResult.AuditRequestedTokens > 0 {
		trace.Metadata["audit_requested_tokens"] = auditResult.AuditRequestedTokens
	}
	if auditResult.AuditContextWindowTokens > 0 {
		trace.Metadata["audit_context_window_tokens"] = auditResult.AuditContextWindowTokens
	}
	if auditResult.AuditRetryCount > 0 {
		trace.Metadata["audit_retry_count"] = auditResult.AuditRetryCount
		trace.Metadata["audit_chunk_retry_count"] = auditResult.AuditRetryCount
	}
	if auditResult.AuditRequestedTokens > 0 {
		trace.Metadata["audit_input_tokens"] = auditResult.AuditRequestedTokens
	}
	if auditResult.AuditTokensOverLimit > 0 {
		trace.Metadata["audit_tokens_over_limit"] = auditResult.AuditTokensOverLimit
	}
	if auditResult.AuditProfileID > 0 {
		trace.Metadata["audit_profile_id"] = auditResult.AuditProfileID
	}
	if auditResult.AuditProfileName != "" {
		trace.Metadata["audit_profile_name"] = auditResult.AuditProfileName
	}
	if auditResult.AuditModelAttempts > 0 {
		trace.Metadata["audit_model_attempts"] = auditResult.AuditModelAttempts
	}
	if auditResult.AuditModelRetries > 0 {
		trace.Metadata["audit_model_retries"] = auditResult.AuditModelRetries
	}
	if auditResult.AuditFallbackCount > 0 {
		trace.Metadata["audit_fallback_count"] = auditResult.AuditFallbackCount
	}
	if len(auditResult.AuditModelsTried) > 0 {
		trace.Metadata["audit_models_tried"] = auditResult.AuditModelsTried
	}
	if len(auditResult.AuditAttempts) > 0 {
		trace.Metadata["audit_attempts"] = auditResult.AuditAttempts
	}
	auditDuration.WithLabelValues(slug).Observe(auditResult.Latency.Seconds())
	if auditResult.Decision == DecisionBlock {
		riskCode := firstNonEmpty(auditResult.RiskCode, "CYBER_POLICY_BLOCK")
		finish(DecisionBlock, riskCode, g.cfg.ErrorHTTPStatus, 0, 0)
		message := "request rejected by risk control"
		if auditResult.RuleMatch != nil && strings.TrimSpace(auditResult.RuleMatch.UserGuidance) != "" {
			message = auditResult.RuleMatch.UserGuidance
		} else if auditResult.EvidenceVerified {
			message = auditModelUserGuidance(auditResult.Category)
		}
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, riskCode, message)
		return
	}

	timeout := time.Duration(route.RequestTimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	release, ok := g.redis.Acquire(
		r.Context(),
		"route:"+slug,
		route.MaxConcurrency,
		timeout+30*time.Second,
	)
	if !ok {
		finish("error", "ROUTE_CONCURRENCY_LIMITED", http.StatusServiceUnavailable, 0, 0)
		writeGatewayError(w, http.StatusServiceUnavailable, requestID, "ROUTE_CONCURRENCY_LIMITED", "route concurrency limit reached")
		return
	}
	defer release()

	upstreamRequest, err := g.buildUpstreamRequest(r, route, body, requestID)
	if err != nil {
		g.log.Warn("route configuration rejected at request time", "route", slug, "error", err)
		trace.Metadata["error_class"] = "route_configuration"
		finish("error", "GATEWAY_CONFIG_ERROR", g.cfg.ErrorHTTPStatus, 0, 0)
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "GATEWAY_CONFIG_ERROR", "gateway route configuration is invalid")
		return
	}
	requestContext, cancelRequest := context.WithCancelCause(r.Context())
	requestTimer := time.AfterFunc(timeout, func() {
		cancelRequest(errUpstreamRequestTimeout)
	})
	defer func() {
		requestTimer.Stop()
		cancelRequest(context.Canceled)
	}()
	upstreamRequest = upstreamRequest.WithContext(requestContext)
	upstreamStarted := time.Now()
	response, err := g.client.Do(upstreamRequest)
	trace.Metadata["upstream_header_latency_ms"] = time.Since(upstreamStarted).Milliseconds()
	if err != nil {
		riskCode := "UPSTREAM_CONNECTION_ERROR"
		if errors.Is(context.Cause(requestContext), errUpstreamRequestTimeout) ||
			errors.Is(err, context.DeadlineExceeded) || errors.Is(context.Cause(requestContext), context.DeadlineExceeded) {
			riskCode = "UPSTREAM_TIMEOUT"
		}
		trace.Metadata["failure_stage"] = "upstream_connect"
		trace.Metadata["error_class"] = riskCode
		finish("error", riskCode, g.cfg.ErrorHTTPStatus, 0, 0)
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, riskCode, "upstream model request failed")
		return
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		failureBody, _ := io.ReadAll(io.LimitReader(response.Body, adaptiveProviderErrorLimit))
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
		g.audit.ObserveUpstreamFailure(
			route,
			requestID,
			clientIdentity,
			body,
			response.StatusCode,
			"UPSTREAM_MODEL_ERROR",
			failureBody,
		)
		trace.Metadata["error_class"] = "upstream_http_error"
		recordUpstreamFailureMetadata(&trace, "UPSTREAM_MODEL_ERROR", response.StatusCode, failureBody, "upstream_http")
		finish("error", "UPSTREAM_MODEL_ERROR", g.cfg.ErrorHTTPStatus, response.StatusCode, 0)
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "UPSTREAM_MODEL_ERROR", "upstream model returned an error")
		return
	}

	isEventStream := strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream")
	if isEventStream {
		// request_timeout_ms used to be a hard wall-clock deadline for the full
		// generation. A 4,970-token response at 41 t/s already takes more than
		// 120 seconds, so healthy streams were canceled and mislabeled as
		// UPSTREAM_STREAM_INTERRUPTED. Once SSE headers arrive, use the route
		// timeout as an inactivity deadline that is reset by every SSE event.
		requestTimer.Stop()
		trace.Metadata["upstream_timeout_scope"] = "response_headers_then_stream_idle"
		trace.Metadata["upstream_stream_idle_timeout_ms"] = timeout.Milliseconds()
		streamIdleTimer := time.AfterFunc(timeout, func() {
			cancelRequest(errUpstreamStreamIdleTimeout)
		})
		resetStreamIdleTimer := func() {
			streamIdleTimer.Reset(timeout)
		}
		var observation upstreamResponseObservation
		bytesWritten, riskCode, status, failureEvidence, streamCommitted := g.proxySSE(
			w, response, requestID, &observation, resetStreamIdleTimer,
		)
		streamIdleTimer.Stop()
		recordUpstreamObservationMetadata(&trace, observation)
		if riskCode != "" {
			if riskCode == "UPSTREAM_STREAM_ERROR" {
				g.audit.ObserveUpstreamFailure(route, requestID, clientIdentity, body, response.StatusCode, riskCode, failureEvidence)
			}
			stage := "upstream_stream"
			if riskCode == "CLIENT_DISCONNECT" {
				stage = "client_disconnect"
			}
			recordUpstreamFailureMetadata(&trace, riskCode, response.StatusCode, failureEvidence, stage)
			if streamCommitted && (riskCode == "UPSTREAM_STREAM_ERROR" || riskCode == "UPSTREAM_STREAM_INTERRUPTED" || riskCode == "UPSTREAM_STREAM_TIMEOUT") {
				trace.Metadata["stream_error_semantics"] = "logical_555_after_headers"
			}
			finish("error", riskCode, status, response.StatusCode, bytesWritten)
			return
		}
		finish(DecisionAllow, "", status, response.StatusCode, bytesWritten)
		return
	}

	trace.Metadata["upstream_timeout_scope"] = "full_response"
	var observation upstreamResponseObservation
	bytesWritten, riskCode, status, failureEvidence := g.proxyBuffered(w, response, requestID, &observation)
	recordUpstreamObservationMetadata(&trace, observation)
	if riskCode != "" {
		if riskCode == "UPSTREAM_MODEL_ERROR" {
			g.audit.ObserveUpstreamFailure(route, requestID, clientIdentity, body, response.StatusCode, riskCode, failureEvidence)
		}
		stage := "upstream_response"
		if riskCode == "CLIENT_DISCONNECT" {
			stage = "client_disconnect"
		}
		recordUpstreamFailureMetadata(&trace, riskCode, response.StatusCode, failureEvidence, stage)
		finish("error", riskCode, status, response.StatusCode, bytesWritten)
		return
	}
	finish(DecisionAllow, "", status, response.StatusCode, bytesWritten)
}

func markRequestTooLarge(trace *TraceEvent, requestBytes int64, policy requestBodyLimitPolicy, exact bool) string {
	limitBytes := policy.EffectiveLimitBytes
	if limitBytes < 1 {
		limitBytes = 1
	}
	if requestBytes <= limitBytes {
		requestBytes = limitBytes + 1
	}
	overBytes := requestBytes - limitBytes
	trace.RequestBytes = requestBytes
	trace.Metadata["error_class"] = "request_body_too_large"
	trace.Metadata["error_origin"] = "risk_gateway"
	trace.Metadata["failure_stage"] = "gateway_ingress"
	trace.Metadata["failure_component"] = "request_body_guard"
	trace.Metadata["limit_owner"] = "risk_gateway"
	trace.Metadata["limit_config"] = map[bool]string{true: "REQUEST_HARD_MAX_BYTES", false: "REQUEST_MAX_BYTES"}[policy.Mode != "configured"]
	trace.Metadata["limit_scope"] = "inbound_http_request_body"
	trace.Metadata["limit_unit"] = "bytes"
	trace.Metadata["request_body_limit_mode"] = policy.Mode
	trace.Metadata["request_body_hard_limit_bytes"] = policy.HardLimitBytes
	trace.Metadata["audit_started"] = false
	trace.Metadata["upstream_started"] = false
	trace.Metadata["request_body_bytes"] = requestBytes
	trace.Metadata["request_body_limit_bytes"] = limitBytes
	trace.Metadata["request_body_over_limit_bytes"] = overBytes
	trace.Metadata["request_body_size_exact"] = exact

	var remediation string
	switch policy.Mode {
	case "configured":
		trace.Metadata["request_body_recommended_limit_bytes"] = recommendedRequestMaxBytes(requestBytes, policy.HardLimitBytes)
		remediation = "The explicit REQUEST_MAX_BYTES soft limit rejected this body before audit and upstream. Set REQUEST_MAX_BYTES=0 to use automatic actual-size admission, or reduce/externalize the payload."
	default:
		remediation = fmt.Sprintf(
			"The request exceeds the automatic hard ceiling REQUEST_HARD_MAX_BYTES=%d. Reduce/split the payload, replace inline base64 files or images with URLs, or raise the hard ceiling only with a bounded large-request concurrency budget. Audit and upstream were not called.",
			policy.HardLimitBytes,
		)
	}
	trace.Metadata["request_body_remediation"] = remediation

	qualifier := ""
	if !exact {
		qualifier = "at least "
	}
	reason := fmt.Sprintf(
		"Risk Gateway ingress rejected the request before audit and upstream: request body is %s%d bytes; %s effective limit is %d bytes; hard ceiling is %d bytes; over limit by %s%d bytes",
		qualifier, requestBytes, policy.Mode, limitBytes, policy.HardLimitBytes, qualifier, overBytes,
	)
	trace.Metadata["error_reason"] = reason
	return reason
}

func (g *Gateway) buildUpstreamRequest(
	inbound *http.Request,
	route Route,
	body []byte,
	requestID string,
) (*http.Request, error) {
	base, err := url.Parse(route.BaseURL)
	if err != nil {
		return nil, err
	}
	wildcard := chi.URLParam(inbound, "*")
	if wildcard == "" {
		wildcard = "/"
	}
	base.Path = joinURLPath(base.Path, wildcard)
	base.RawQuery = inbound.URL.RawQuery
	request, err := http.NewRequest(inbound.Method, base.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	copyRequestHeaders(request.Header, inbound.Header)
	inboundAuthorization := request.Header.Get("Authorization")
	for _, key := range []string{
		"Authorization",
		"X-API-Key",
		"X-Goog-Api-Key",
		"Api-Key",
		"X-Risk-Gateway-Key",
		"X-NewAPI-User-ID",
		"X-User-ID",
		"Cookie",
		"Forwarded",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"Accept-Encoding",
	} {
		request.Header.Del(key)
	}
	request.Header.Set("X-Risk-Request-ID", requestID)
	if inbound.Header.Get("X-Request-ID") == "" {
		request.Header.Set("X-Request-ID", requestID)
	}
	secret, err := g.security.Decrypt("route-upstream-secret-v1", route.UpstreamSecretCiphertext)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(route.AuthMode) {
	case "", "none":
		request.Header.Del("Authorization")
	case "passthrough":
		if inbound.Header.Get("X-Risk-Gateway-Key") == "" || inboundAuthorization == "" {
			return nil, errors.New("passthrough auth requires X-Risk-Gateway-Key and an Authorization header")
		}
		request.Header.Set("Authorization", inboundAuthorization)
	case "bearer":
		request.Header.Set("Authorization", "Bearer "+string(secret))
	case "anthropic":
		request.Header.Del("Authorization")
		request.Header.Set("X-API-Key", string(secret))
		if request.Header.Get("Anthropic-Version") == "" {
			request.Header.Set("Anthropic-Version", "2023-06-01")
		}
	case "gemini":
		request.Header.Del("Authorization")
		request.Header.Set("X-Goog-Api-Key", string(secret))
	case "header":
		if route.SecretHeader == "" {
			return nil, errors.New("secret_header is required for header auth mode")
		}
		request.Header.Set(route.SecretHeader, string(secret))
	case "query":
		parameter := route.SecretHeader
		if parameter == "" {
			parameter = "key"
		}
		query := request.URL.Query()
		query.Set(parameter, string(secret))
		request.URL.RawQuery = query.Encode()
	default:
		return nil, fmt.Errorf("unsupported auth mode %q", route.AuthMode)
	}
	return request, nil
}

func (g *Gateway) proxyBuffered(
	w http.ResponseWriter,
	response *http.Response,
	requestID string,
	observation *upstreamResponseObservation,
) (int64, string, int, []byte) {
	started := time.Now()
	defer func() {
		if observation != nil {
			observation.Duration = time.Since(started)
		}
	}()
	prefix, err := io.ReadAll(io.LimitReader(response.Body, g.cfg.ResponseInspectMaxBytes+1))
	if err != nil {
		if observation != nil {
			observation.ReadError = err.Error()
		}
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "UPSTREAM_READ_ERROR", "upstream model response failed")
		return 0, "UPSTREAM_READ_ERROR", g.cfg.ErrorHTTPStatus, []byte("upstream buffered response read failed: " + err.Error())
	}
	completeBody := int64(len(prefix)) <= g.cfg.ResponseInspectMaxBytes
	if observation != nil {
		observation.ObserveBufferedBody(prefix, completeBody)
	}
	if completeBody && responseContainsErrorEnvelope(prefix) {
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "UPSTREAM_MODEL_ERROR", "upstream model returned an error")
		return 0, "UPSTREAM_MODEL_ERROR", g.cfg.ErrorHTTPStatus, append([]byte(nil), prefix...)
	}
	copyResponseHeaders(w.Header(), response.Header)
	w.Header().Set("X-Risk-Request-ID", requestID)
	w.WriteHeader(response.StatusCode)
	written, writeError := w.Write(prefix)
	total := int64(written)
	if writeError == nil && !completeBody {
		copied, copyError := io.Copy(w, response.Body)
		total += copied
		writeError = copyError
		if writeError == nil && observation != nil {
			observation.CompletionObserved = true
			observation.CompletionSemantics = "buffered_response_streamed"
		}
	}
	if writeError != nil {
		return total, "CLIENT_DISCONNECT", response.StatusCode, nil
	}
	return total, "", response.StatusCode, nil
}

func (g *Gateway) proxySSE(
	w http.ResponseWriter,
	response *http.Response,
	requestID string,
	observation *upstreamResponseObservation,
	onProgress func(),
) (int64, string, int, []byte, bool) {
	started := time.Now()
	defer func() {
		if observation != nil {
			observation.Duration = time.Since(started)
		}
	}()
	observeEvent := func(event []string) {
		if onProgress != nil {
			onProgress()
		}
		if observation != nil {
			observation.ObserveSSEEvent(event)
		}
	}
	readFailure := func(readError error) (string, []byte) {
		if observation != nil {
			observation.ReadError = readError.Error()
		}
		return classifyUpstreamStreamReadError(response, readError)
	}

	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 64*1024), g.cfg.SSELineMaxBytes)
	buffered := make([][]string, 0, 4)
	bufferedBytes := 0
	for len(buffered) < 16 && bufferedBytes < 64*1024 {
		event, ok, err := nextSSEEvent(scanner)
		if err != nil {
			riskCode, evidence := readFailure(err)
			if riskCode != "CLIENT_DISCONNECT" {
				writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, riskCode, "upstream stream failed before starting")
			}
			return 0, riskCode, g.cfg.ErrorHTTPStatus, evidence, false
		}
		if !ok {
			break
		}
		observeEvent(event)
		if isSSEErrorEvent(event) {
			writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "UPSTREAM_STREAM_ERROR", "upstream model returned a stream error")
			return 0, "UPSTREAM_STREAM_ERROR", g.cfg.ErrorHTTPStatus, sseEventEvidence(event), false
		}
		buffered = append(buffered, event)
		bufferedBytes += sseEventSize(event)
		if isMeaningfulSSEEvent(event) {
			break
		}
	}

	copyResponseHeaders(w.Header(), response.Header)
	w.Header().Set("X-Risk-Request-ID", requestID)
	w.WriteHeader(response.StatusCode)
	flusher, canFlush := w.(http.Flusher)
	var total int64
	writeEvent := func(lines []string) error {
		for _, line := range lines {
			count, err := io.WriteString(w, line+"\n")
			total += int64(count)
			if err != nil {
				return err
			}
		}
		if canFlush {
			flusher.Flush()
		}
		return nil
	}
	for _, event := range buffered {
		if err := writeEvent(event); err != nil {
			return total, "CLIENT_DISCONNECT", response.StatusCode, nil, true
		}
	}
	for {
		event, hasEvent, readError := nextSSEEvent(scanner)
		if readError != nil {
			if observation != nil {
				observation.ReadError = readError.Error()
				if observation.CompletionObserved {
					observation.TransportClosedAfterTerminal = true
					if observation.CompletionSemantics != "" {
						observation.CompletionSemantics += "_then_transport_close"
					}
					// A provider may close with a TCP reset immediately after a
					// valid finish_reason/[DONE]/response.completed event. The
					// generation is already complete and must not become a false 555.
					return total, "", response.StatusCode, nil, true
				}
			}
			riskCode, evidence := readFailure(readError)
			if riskCode == "CLIENT_DISCONNECT" {
				return total, riskCode, response.StatusCode, nil, true
			}
			written, _ := writeSSELogicalError(w, requestID, riskCode)
			total += written
			if canFlush {
				flusher.Flush()
			}
			return total, riskCode, response.StatusCode, evidence, true
		}
		if !hasEvent {
			if observation != nil && observation.CompletionSemantics == "" {
				observation.CompletionSemantics = "clean_eof"
			}
			break
		}
		observeEvent(event)
		if isSSEErrorEvent(event) {
			written, _ := writeSSELogicalError(w, requestID, "UPSTREAM_STREAM_ERROR")
			total += written
			if canFlush {
				flusher.Flush()
			}
			return total, "UPSTREAM_STREAM_ERROR", response.StatusCode, sseEventEvidence(event), true
		}
		if err := writeEvent(event); err != nil {
			return total, "CLIENT_DISCONNECT", response.StatusCode, nil, true
		}
	}
	return total, "", response.StatusCode, nil, true
}

func nextSSEEvent(scanner *bufio.Scanner) ([]string, bool, error) {
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
		if line == "" {
			return lines, true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, false, err
	}
	if len(lines) > 0 {
		lines = append(lines, "")
		return lines, true, nil
	}
	return nil, false, nil
}

func isMeaningfulSSEEvent(lines []string) bool {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "data:") || strings.HasPrefix(trimmed, "event:") {
			return true
		}
	}
	return false
}

func sseEventSize(lines []string) int {
	total := 0
	for _, line := range lines {
		total += len(line) + 1
	}
	return total
}

func sseEventEvidence(lines []string) []byte {
	text := strings.Join(lines, "\n")
	if len(text) > adaptiveProviderErrorLimit {
		text = text[:adaptiveProviderErrorLimit]
	}
	return []byte(text)
}

func isSSEErrorEvent(lines []string) bool {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.EqualFold(trimmed, "event: error") {
			return true
		}
		if !strings.HasPrefix(trimmed, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}
		var payload map[string]any
		if json.Unmarshal([]byte(data), &payload) != nil {
			continue
		}
		if value, exists := payload["error"]; exists && value != nil {
			return true
		}
		if value, _ := payload["type"].(string); strings.EqualFold(value, "error") {
			return true
		}
	}
	return false
}

func writeSSELogicalError(w io.Writer, requestID string, riskCode string) (int64, error) {
	payload := map[string]any{
		"error": map[string]any{
			"message":    "upstream model stream failed",
			"type":       "upstream_error",
			"code":       555,
			"risk_code":  riskCode,
			"request_id": requestID,
		},
	}
	encoded, _ := json.Marshal(payload)
	count, err := fmt.Fprintf(w, "event: error\ndata: %s\n\n", encoded)
	return int64(count), err
}

func responseContainsErrorEnvelope(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	var payload map[string]any
	if json.Unmarshal(trimmed, &payload) != nil {
		return false
	}
	if value, exists := payload["error"]; exists && value != nil {
		return true
	}
	if value, _ := payload["type"].(string); strings.EqualFold(value, "error") || strings.HasSuffix(strings.ToLower(value), "_error") {
		return true
	}
	if success, ok := payload["success"].(bool); ok && !success {
		if _, hasMessage := payload["message"]; hasMessage {
			return true
		}
	}
	return false
}

func writeRiskError(w http.ResponseWriter, status int, requestID string, riskCode string, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Risk-Request-ID", requestID)
	w.Header().Set("X-Risk-Error-Code", "555")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message":    message,
			"type":       "risk_control_error",
			"code":       555,
			"risk_code":  riskCode,
			"request_id": requestID,
		},
	})
}

func writeGatewayError(w http.ResponseWriter, status int, requestID string, code string, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Risk-Request-ID", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message":    message,
			"type":       "gateway_error",
			"code":       code,
			"request_id": requestID,
		},
	})
}

func copyRequestHeaders(destination http.Header, source http.Header) {
	for key, values := range source {
		if isHopByHopHeader(key) || strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

func copyResponseHeaders(destination http.Header, source http.Header) {
	for key, values := range source {
		if isHopByHopHeader(key) ||
			strings.EqualFold(key, "Content-Length") ||
			strings.EqualFold(key, "Set-Cookie") ||
			strings.EqualFold(key, "Server") ||
			strings.EqualFold(key, "Alt-Svc") {
			continue
		}
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

func isHopByHopHeader(key string) bool {
	switch strings.ToLower(key) {
	case "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
		"proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func joinURLPath(basePath string, requestPath string) string {
	if basePath == "" {
		basePath = "/"
	}
	return strings.TrimRight(basePath, "/") + "/" + strings.TrimLeft(requestPath, "/")
}

func normalizeRequestID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || !requestIDPattern.MatchString(value) {
		return ""
	}
	return value
}

func normalizeIdentifier(value string) string {
	return truncateString(strings.TrimSpace(value), 200)
}

func truncateString(value string, maximum int) string {
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	if len(header) < 7 || !strings.EqualFold(header[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(header[7:])
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func ValidateUpstreamURL(rawURL string, allowPrivate bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return errors.New("upstream URL scheme must be http or https")
	}
	if parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("upstream URL must contain a host and must not contain userinfo or a fragment")
	}
	if parsed.Scheme == "http" && !allowPrivate {
		return errors.New("plain HTTP upstreams require explicitly enabled private-upstream mode")
	}
	if allowPrivate {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, parsed.Hostname())
	if err != nil {
		return fmt.Errorf("resolve upstream host: %w", err)
	}
	if len(addresses) == 0 {
		return errors.New("upstream host did not resolve")
	}
	for _, address := range addresses {
		if isForbiddenIP(address.IP) {
			return fmt.Errorf("upstream host resolves to forbidden address %s", address.IP)
		}
	}
	return nil
}

func NewSafeTransport(allowPrivate bool, minimumTLSVersion uint16) *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4096,
		MaxIdleConnsPerHost: 1024,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		// Route request_timeout_ms controls response-header timeouts. Keeping
		// another fixed 120-second transport deadline would silently override
		// routes configured with a larger value.
		ResponseHeaderTimeout: 0,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: minimumTLSVersion},
	}
	transport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastError error
		for _, candidate := range addresses {
			if !allowPrivate && isForbiddenIP(candidate.IP) {
				lastError = fmt.Errorf("dial blocked for forbidden address %s", candidate.IP)
				continue
			}
			connection, err := dialer.DialContext(
				ctx,
				network,
				net.JoinHostPort(candidate.IP.String(), port),
			)
			if err == nil {
				return connection, nil
			}
			lastError = err
		}
		if lastError == nil {
			lastError = errors.New("host did not resolve to a usable address")
		}
		return nil, lastError
	}
	return transport
}

var forbiddenNetworks = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4",
		"240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10",
		"ff00::/8", "2001:db8::/32",
	}
	result := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			result = append(result, network)
		}
	}
	return result
}()

func isForbiddenIP(ip net.IP) bool {
	if ip == nil ||
		ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() {
		return true
	}
	for _, network := range forbiddenNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
