package platform

import (
	"encoding/json"
	"time"
)

const (
	DecisionAllow  = "allow"
	DecisionBlock  = "block"
	DecisionReview = "review"
)

type Route struct {
	ID                       int64      `json:"id"`
	Slug                     string     `json:"slug"`
	Name                     string     `json:"name"`
	BaseURL                  string     `json:"base_url"`
	Provider                 string     `json:"provider"`
	AuthMode                 string     `json:"auth_mode"`
	SecretHeader             string     `json:"secret_header,omitempty"`
	AuditProfileID           *int64     `json:"audit_profile_id,omitempty"`
	Enabled                  bool       `json:"enabled"`
	FailClosed               bool       `json:"fail_closed"`
	RequestTimeoutMS         int        `json:"request_timeout_ms"`
	MaxConcurrency           int        `json:"max_concurrency"`
	RateLimitRPS             float64    `json:"rate_limit_rps"`
	RateLimitBurst           int        `json:"rate_limit_burst"`
	UpstreamSecretCiphertext []byte     `json:"-"`
	InboundKeyDigest         string     `json:"-"`
	CreatedAt                time.Time  `json:"created_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
	DeletedAt                *time.Time `json:"-"`
}

type RouteInput struct {
	ID               int64   `json:"id"`
	Slug             string  `json:"slug"`
	Name             string  `json:"name"`
	BaseURL          string  `json:"base_url"`
	Provider         string  `json:"provider"`
	AuthMode         string  `json:"auth_mode"`
	SecretHeader     string  `json:"secret_header"`
	UpstreamSecret   string  `json:"upstream_secret"`
	InboundKey       string  `json:"inbound_key"`
	AuditProfileID   *int64  `json:"audit_profile_id"`
	Enabled          bool    `json:"enabled"`
	FailClosed       bool    `json:"fail_closed"`
	RequestTimeoutMS int     `json:"request_timeout_ms"`
	MaxConcurrency   int     `json:"max_concurrency"`
	RateLimitRPS     float64 `json:"rate_limit_rps"`
	RateLimitBurst   int     `json:"rate_limit_burst"`
}

type AuditProfile struct {
	ID                 int64           `json:"id"`
	Name               string          `json:"name"`
	Endpoint           string          `json:"endpoint"`
	Model              string          `json:"model"`
	SystemPrompt       string          `json:"system_prompt"`
	TimeoutMS          int             `json:"timeout_ms"`
	BlockThreshold     float64         `json:"block_threshold"`
	Enabled            bool            `json:"enabled"`
	FailClosed         bool            `json:"fail_closed"`
	IsDefault          bool            `json:"is_default"`
	RetryCount         int             `json:"retry_count"`
	FallbackProfileIDs []int64         `json:"fallback_profile_ids"`
	Extra              json.RawMessage `json:"extra,omitempty"`
	APIKeyCiphertext   []byte          `json:"-"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

type AuditProfileInput struct {
	ID                 int64           `json:"id"`
	Name               string          `json:"name"`
	Endpoint           string          `json:"endpoint"`
	Model              string          `json:"model"`
	APIKey             string          `json:"api_key"`
	SystemPrompt       string          `json:"system_prompt"`
	TimeoutMS          int             `json:"timeout_ms"`
	BlockThreshold     float64         `json:"block_threshold"`
	Enabled            bool            `json:"enabled"`
	FailClosed         bool            `json:"fail_closed"`
	IsDefault          bool            `json:"is_default"`
	RetryCount         int             `json:"retry_count"`
	FallbackProfileIDs []int64         `json:"fallback_profile_ids"`
	Extra              json.RawMessage `json:"extra"`
}

type CyberRule struct {
	ID          int64     `json:"id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
	Pattern     string    `json:"pattern"`
	PatternType string    `json:"pattern_type"`
	Action      string    `json:"action"`
	Priority    int       `json:"priority"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type AuditDecision struct {
	ConfidenceKind       string   `json:"confidence_kind,omitempty"`
	ConfidenceLabel      string   `json:"confidence_label,omitempty"`
	OutputNormalizations []string `json:"output_normalizations,omitempty"`

	RequestEvidence    string               `json:"request_evidence,omitempty"`
	EvidenceRelation   string               `json:"evidence_relation,omitempty"`
	HarmType           string               `json:"harm_type,omitempty"`
	SemanticReview     *AuditSemanticReview `json:"-"`
	Decision           string               `json:"decision"`
	RiskCode           string               `json:"risk_code,omitempty"`
	Category           string               `json:"category,omitempty"`
	Confidence         float64              `json:"confidence"`
	Reason             string               `json:"reason,omitempty"`
	Source             string               `json:"source"`
	RuleID             int64                `json:"rule_id,omitempty"`
	Evidence           string               `json:"evidence,omitempty"`
	EvidenceContext    string               `json:"evidence_context,omitempty"`
	EvidenceVerified   bool                 `json:"evidence_verified,omitempty"`
	EvidenceMatchMode  string               `json:"evidence_match_mode,omitempty"`
	EvidenceChunkIndex int                  `json:"evidence_chunk_index,omitempty"`
	EvidenceChunkCount int                  `json:"evidence_chunk_count,omitempty"`
}

type AuditAttempt struct {
	ConfidenceKind       string   `json:"confidence_kind,omitempty"`
	ConfidenceLabel      string   `json:"confidence_label,omitempty"`
	OutputNormalizations []string `json:"output_normalizations,omitempty"`

	ProfileID            int64   `json:"profile_id"`
	ProfileName          string  `json:"profile_name"`
	Model                string  `json:"model"`
	Attempt              int     `json:"attempt"`
	Success              bool    `json:"success"`
	Decision             string  `json:"decision,omitempty"`
	RiskCode             string  `json:"risk_code,omitempty"`
	Confidence           float64 `json:"confidence,omitempty"`
	Evidence             string  `json:"evidence,omitempty"`
	ErrorClass           string  `json:"error_class,omitempty"`
	HTTPStatus           int     `json:"http_status,omitempty"`
	Reason               string  `json:"reason,omitempty"`
	OutputMode           string  `json:"output_mode,omitempty"`
	OutputMaxTokens      int     `json:"output_max_tokens,omitempty"`
	FinishReason         string  `json:"finish_reason,omitempty"`
	ResponseContentBytes int     `json:"response_content_bytes,omitempty"`
	ResponseSource       string  `json:"response_source,omitempty"`
	ResponsePreview      string  `json:"response_preview,omitempty"`
	ResponseID           string  `json:"response_id,omitempty"`
}

type AuditResult struct {
	AuditOutputContract         string                `json:"audit_output_contract"`
	GatewayBuild                BuildInformation      `json:"gateway_build"`
	AuditInputContract          string                `json:"audit_input_contract,omitempty"`
	AuditEmbeddedReferenceCount int                   `json:"audit_embedded_reference_count,omitempty"`
	AuditHTTPCalls              int                   `json:"audit_http_calls,omitempty"`
	AuditSemanticReviewCalls    int                   `json:"audit_semantic_review_calls,omitempty"`
	AuditSemanticReviewCount    int                   `json:"audit_semantic_review_count,omitempty"`
	AuditSemanticReviews        []AuditSemanticReview `json:"audit_semantic_reviews,omitempty"`
	AuditDecision

	AuditModelDecision             *AuditDecision `json:"audit_model_decision_raw,omitempty"`
	AuditRequestedTokensLowerBound bool           `json:"audit_requested_tokens_lower_bound,omitempty"`
	AuditObservedOutputTokens      int            `json:"audit_observed_output_tokens,omitempty"`

	PromptHMAC                  string                      `json:"prompt_hmac"`
	TextBytes                   int                         `json:"text_bytes"`
	Latency                     time.Duration               `json:"-"`
	Model                       string                      `json:"model,omitempty"`
	ErrorClass                  string                      `json:"error_class,omitempty"`
	AuditHTTPStatus             int                         `json:"audit_http_status,omitempty"`
	AuditMode                   string                      `json:"audit_mode,omitempty"`
	AuditChunkCount             int                         `json:"audit_chunk_count,omitempty"`
	AuditChunkBytes             int                         `json:"audit_chunk_bytes,omitempty"`
	AuditRequestedTokens        int                         `json:"audit_requested_tokens,omitempty"`
	AuditContextWindowTokens    int                         `json:"audit_context_window_tokens,omitempty"`
	AuditRetryCount             int                         `json:"audit_retry_count,omitempty"`
	AuditProfileID              int64                       `json:"audit_profile_id,omitempty"`
	AuditProfileName            string                      `json:"audit_profile_name,omitempty"`
	AuditModelAttempts          int                         `json:"audit_model_attempts,omitempty"`
	AuditModelRetries           int                         `json:"audit_model_retries,omitempty"`
	AuditFallbackCount          int                         `json:"audit_fallback_count,omitempty"`
	AuditModelsTried            []string                    `json:"audit_models_tried,omitempty"`
	AuditTokensOverLimit        int                         `json:"audit_tokens_over_limit,omitempty"`
	AuditAttempts               []AuditAttempt              `json:"audit_attempts,omitempty"`
	RuleMatch                   *RuleMatchDiagnostics       `json:"rule_match,omitempty"`
	AuditInputScope             string                      `json:"audit_input_scope,omitempty"`
	AuditIntentBytes            int                         `json:"audit_intent_bytes,omitempty"`
	AuditIgnoredContextBytes    int                         `json:"audit_ignored_context_bytes,omitempty"`
	AuditIgnoredRoles           []string                    `json:"audit_ignored_roles,omitempty"`
	AuditIgnoredInputTypes      []string                    `json:"audit_ignored_input_types,omitempty"`
	AuditTextLimitMode          string                      `json:"audit_text_limit_mode,omitempty"`
	AuditTextLimitBytes         int                         `json:"audit_text_limit_bytes,omitempty"`
	AuditRawIntentBytes         int                         `json:"audit_raw_intent_bytes,omitempty"`
	AuditPriorUserContextBytes  int                         `json:"audit_prior_user_context_bytes,omitempty"`
	AuditActiveUserMessages     int                         `json:"audit_active_user_messages,omitempty"`
	AuditContextActivated       bool                        `json:"audit_context_activated,omitempty"`
	AuditEphemeralArtifactCount int                         `json:"audit_ephemeral_artifact_count,omitempty"`
	AuditSecretPlaceholderCount int                         `json:"audit_secret_placeholder_count,omitempty"`
	AuditRuleSuppressions       []RuleSuppressionDiagnostic `json:"audit_rule_suppressions,omitempty"`
	AuditPolicyMode             string                      `json:"audit_policy_mode,omitempty"`
	AuditPolicyAdjustment       *AuditPolicyAdjustment      `json:"audit_policy_adjustment,omitempty"`
	AuditOutputMode             string                      `json:"audit_output_mode,omitempty"`
	AuditOutputMaxTokens        int                         `json:"audit_output_max_tokens,omitempty"`
	AuditFinishReason           string                      `json:"audit_finish_reason,omitempty"`
	AuditResponseContentBytes   int                         `json:"audit_response_content_bytes,omitempty"`
	AuditResponseSource         string                      `json:"audit_response_source,omitempty"`
	AuditResponsePreview        string                      `json:"audit_response_preview,omitempty"`
	AuditResponseID             string                      `json:"audit_response_id,omitempty"`
}

type TraceEvent struct {
	RequestID       string         `json:"request_id"`
	ExternalEventID string         `json:"external_event_id,omitempty"`
	Source          string         `json:"source"`
	RouteSlug       string         `json:"route_slug,omitempty"`
	NewAPIRequestID string         `json:"newapi_request_id,omitempty"`
	ExternalUserID  string         `json:"external_user_id,omitempty"`
	Model           string         `json:"model,omitempty"`
	Endpoint        string         `json:"endpoint,omitempty"`
	Decision        string         `json:"decision"`
	RiskCode        string         `json:"risk_code,omitempty"`
	HTTPStatus      int            `json:"http_status"`
	UpstreamStatus  int            `json:"upstream_status,omitempty"`
	LatencyMS       int64          `json:"latency_ms"`
	AuditLatencyMS  int64          `json:"audit_latency_ms"`
	RequestBytes    int64          `json:"request_bytes"`
	ResponseBytes   int64          `json:"response_bytes"`
	PromptHMAC      string         `json:"prompt_hmac,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	StartedAt       time.Time      `json:"started_at"`
	CompletedAt     time.Time      `json:"completed_at"`
	IngestedAt      time.Time      `json:"ingested_at"`
	CreatedAt       time.Time      `json:"created_at"`
}

type TrackingEvent struct {
	EventID         string         `json:"event_id"`
	RequestID       string         `json:"request_id"`
	RouteSlug       string         `json:"route_slug"`
	NewAPIRequestID string         `json:"newapi_request_id"`
	ExternalUserID  string         `json:"external_user_id"`
	Model           string         `json:"model"`
	Endpoint        string         `json:"endpoint"`
	Decision        string         `json:"decision"`
	RiskCode        string         `json:"risk_code"`
	HTTPStatus      int            `json:"http_status"`
	UpstreamStatus  int            `json:"upstream_status"`
	LatencyMS       int64          `json:"latency_ms"`
	AuditLatencyMS  int64          `json:"audit_latency_ms"`
	RequestBytes    int64          `json:"request_bytes"`
	ResponseBytes   int64          `json:"response_bytes"`
	PromptHMAC      string         `json:"prompt_hmac"`
	StartedAt       time.Time      `json:"started_at,omitempty"`
	CompletedAt     time.Time      `json:"completed_at,omitempty"`
	OccurredAt      time.Time      `json:"occurred_at,omitempty"`
	Metadata        map[string]any `json:"metadata"`
}

type TrackingEnvelope struct {
	Events []TrackingEvent `json:"events"`
}

type AdminUser struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type TrackingClient struct {
	ID               int64     `json:"id"`
	KeyID            string    `json:"key_id"`
	Name             string    `json:"name"`
	SecretCiphertext []byte    `json:"-"`
	Enabled          bool      `json:"enabled"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type DashboardStats struct {
	WindowHours      int64            `json:"window_hours"`
	TotalRequests    int64            `json:"total_requests"`
	AllowedRequests  int64            `json:"allowed_requests"`
	BlockedRequests  int64            `json:"blocked_requests"`
	ErrorRequests    int64            `json:"error_requests"`
	P95LatencyMS     float64          `json:"p95_latency_ms"`
	BlockRate        float64          `json:"block_rate"`
	ByRiskCode       map[string]int64 `json:"by_risk_code"`
	ByRoute          map[string]int64 `json:"by_route"`
	TraceQueueDepth  int              `json:"trace_queue_depth"`
	KafkaQueueDepth  int              `json:"kafka_queue_depth"`
	RedisAvailable   bool             `json:"redis_available"`
	KafkaEnabled     bool             `json:"kafka_enabled"`
	PostgresHealthy  bool             `json:"postgres_healthy"`
	ConfiguredRoutes int64            `json:"configured_routes"`
}

type TraceFilter struct {
	RouteSlug string
	Decision  string
	RiskCode  string
	UserID    string
	From      time.Time
	To        time.Time
	Limit     int
}

type OutboxEvent struct {
	ID       int64
	Topic    string
	Key      string
	Payload  []byte
	Attempts int
}
