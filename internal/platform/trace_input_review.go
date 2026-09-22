package platform

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
)

//go:embed web/trace-inputs.js
var traceInputReviewJS string

const traceInputColumns = `id,request_id,route_slug,started_at_text,expires_unix,body_bytes`

var traceInputIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (s *Store) SaveInput(ctx context.Context, record traceInputRecord, sealed []byte) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO trace_input_archives (`+traceInputColumns+`,body_ciphertext) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO NOTHING`, record.ID, record.RequestID, record.RouteSlug, record.StartedAt, record.ExpiresUnix, record.BodyBytes, sealed)
	return err
}
func (s *Store) FindInput(ctx context.Context, id string) (traceInputRecord, []byte, error) {
	var record traceInputRecord
	var sealed []byte
	err := s.pool.QueryRow(ctx, `SELECT `+traceInputColumns+`,body_ciphertext FROM trace_input_archives WHERE id=$1`, id).Scan(&record.ID, &record.RequestID, &record.RouteSlug, &record.StartedAt, &record.ExpiresUnix, &record.BodyBytes, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return record, sealed, err
}
func (s *Store) ListInputs(ctx context.Context, requestID string, days, offset int) ([]traceInputRecord, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+traceInputColumns+` FROM trace_input_archives WHERE request_id=$1 AND expires_unix>extract(epoch FROM now()) AND started_at_text::timestamptz>=now()-($2::int * interval '1 day') ORDER BY created_at DESC,id LIMIT 50 OFFSET $3`, requestID, days, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]traceInputRecord, 0)
	for rows.Next() {
		var record traceInputRecord
		if err := rows.Scan(&record.ID, &record.RequestID, &record.RouteSlug, &record.StartedAt, &record.ExpiresUnix, &record.BodyBytes); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}
func (s *Store) inputRetentionDays(ctx context.Context, maximum int) int {
	configured := s.GetIntSetting(ctx, "retention_days", maximum)
	if configured < 1 {
		configured = maximum
	}
	return min(maximum, configured)
}
func (s *Store) PurgeInputs(ctx context.Context, maximum int) error {
	days := s.inputRetentionDays(ctx, maximum)
	// Bounded deletion avoids an unbounded maintenance transaction. Read APIs
	// enforce expiry even before physical deletion catches up during an outage.
	for i := 0; i < 5; i++ {
		tag, err := s.pool.Exec(ctx, `DELETE FROM trace_input_archives WHERE id IN (SELECT id FROM trace_input_archives WHERE expires_unix<=extract(epoch FROM now()) OR started_at_text::timestamptz<now()-($1::int * interval '1 day') LIMIT 1000)`, days)
		if err != nil {
			return err
		}
		if tag.RowsAffected() < 1000 {
			break
		}
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM trace_input_accesses WHERE id IN (SELECT id FROM trace_input_accesses WHERE created_at<now()-($1::int * interval '1 day') LIMIT 5000)`, days)
	return err
}

// This wrapper keeps original input out of TraceEvent/metadata, Redis and Kafka.
// It does not change audit decisions, SSE bytes, route credentials or timeouts.
func (s *HTTPService) HandlerWithInputReview(ctx context.Context) (http.Handler, func(), error) {
	maxBytes := s.cfg.RequestHardMaxBytes
	if maxBytes <= 0 {
		maxBytes = 64 * 1024 * 1024
	}
	memoryBytes := int64(envInt("TRACE_INPUT_MEMORY_BUDGET_BYTES", 512*1024*1024))
	queueSize := envInt("TRACE_INPUT_QUEUE_SIZE", 64)
	days := envInt("TRACE_INPUT_RETENTION_DAYS", 7)
	if s.cfg.RetentionDays > 0 {
		days = min(days, s.cfg.RetentionDays)
	}
	if err := validateTraceInputOptions(maxBytes, memoryBytes, queueSize, days); err != nil {
		return nil, nil, err
	}
	if _, err := traceInputAEAD(s.cfg.MasterKey); err != nil {
		return nil, nil, err
	}
	recorder := newTraceInputRecorder(ctx, s.store, s.cfg.MasterKey, envBool("TRACE_INPUT_CAPTURE_ENABLED", true), maxBytes, memoryBytes, queueSize, days, s.log)
	base := recorder.Wrap(s.Handler())
	readers := make(chan struct{}, 2)
	router := chi.NewRouter()
	router.Use(middleware.RequestID, middleware.Recoverer, s.securityHeaders, s.accessLog)
	router.Get("/admin/input-review.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(traceInputReviewJS))
	})
	router.Get("/admin", s.serveAdminWithInputReview)
	router.Get("/admin/*", s.serveAdminWithInputReview)
	router.Group(func(admin chi.Router) {
		admin.Use(s.requireAdmin, s.requireRole("admin"), s.requireCurrentInputAdmin)
		admin.Get("/api/admin/v1/trace-inputs/status", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]any{"capture_enabled": recorder.enabled, "retention_days": s.store.inputRetentionDays(r.Context(), days), "max_body_bytes": maxBytes, "memory_budget_bytes": memoryBytes, "memory_charged_bytes": recorder.budget.used.Load(), "queue_depth": len(recorder.queue), "queued": recorder.queued.Load(), "stored": recorder.stored.Load(), "not_captured": recorder.dropped.Load(), "store_failed": recorder.failed.Load(), "counter_scope": "current_process", "access": "admin_only", "storage": "gzip+AES-256-GCM"})
		})
		admin.Get("/api/admin/v1/trace-inputs", func(w http.ResponseWriter, r *http.Request) {
			id := normalizeRequestID(r.URL.Query().Get("request_id"))
			if id == "" {
				writeAPIError(w, 400, "request_id_required", "需要有效的 Request ID")
				return
			}
			offset := 0
			if value := r.URL.Query().Get("offset"); value != "" {
				var err error
				offset, err = strconv.Atoi(value)
				if err != nil || offset < 0 || offset > 1000000 {
					writeAPIError(w, 400, "invalid_offset", "分页位置无效")
					return
				}
			}
			records, err := s.store.ListInputs(r.Context(), id, s.store.inputRetentionDays(r.Context(), days), offset)
			if err != nil {
				writeAPIError(w, 503, "input_store_unavailable", "原文存储暂不可用，不能视为输入为空")
				return
			}
			writeJSON(w, 200, map[string]any{"items": records, "offset": offset, "limit": 50, "has_more": len(records) == 50, "capture_enabled": recorder.enabled, "missing_explanation": "未找到已保存原文可能是旧版本未留存、写入尚未完成、容量/存储失败或已过期，不能从 HMAC 还原。"})
		})
		admin.Get("/api/admin/v1/trace-inputs/{id}/body", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "id")
			if !traceInputIDPattern.MatchString(id) {
				writeAPIError(w, 400, "invalid_input_id", "原文记录 ID 无效")
				return
			}
			select {
			case readers <- struct{}{}:
				defer func() { <-readers }()
			default:
				writeAPIError(w, 429, "input_read_busy", "原文读取繁忙，请稍后重试")
				return
			}
			record, sealed, err := s.store.FindInput(r.Context(), id)
			if errors.Is(err, ErrNotFound) {
				writeAPIError(w, 404, "input_not_retained", "此请求原文未留存或已过期")
				return
			}
			if err != nil {
				writeAPIError(w, 503, "input_store_unavailable", "原文存储暂不可用")
				return
			}
			if traceInputExpired(record, time.Now(), s.store.inputRetentionDays(r.Context(), days)) {
				writeAPIError(w, 410, "input_expired", "请求原文已过保留期")
				return
			}
			claims := claimsFromContext(r.Context())
			// Reading original user content requires an independently durable access log.
			action := "view"
			if r.URL.Query().Get("download") == "1" {
				action = "download"
			}
			if _, err = s.store.pool.Exec(r.Context(), `INSERT INTO trace_input_accesses(input_id,admin_user_id,action) VALUES($1,$2,$3)`, id, claims.UserID, action); err != nil {
				writeAPIError(w, 503, "input_access_audit_failed", "无法记录原文访问审计，已拒绝本次读取")
				return
			}
			body, err := openTraceInput(s.cfg.MasterKey, record, sealed)
			if err != nil {
				writeAPIError(w, 500, "input_integrity_error", "原文解密或完整性校验失败，请核对 MASTER_KEY_B64，不能返回截断内容")
				return
			}
			w.Header().Set("Cache-Control", "no-store, private")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Trace-Input-Bytes", strconv.FormatInt(record.BodyBytes, 10))
			w.Header().Set("X-Trace-Input-Complete", "true")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			if action == "download" {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Content-Disposition", `attachment; filename="request-`+id+`.json"`)
			}
			_, _ = w.Write(body)
		})
	})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/") || r.URL.Path == "/api/admin/v1/trace-inputs" || strings.HasPrefix(r.URL.Path, "/api/admin/v1/trace-inputs/") {
			router.ServeHTTP(w, r)
			return
		}
		base.ServeHTTP(w, r)
	})
	return handler, recorder.Wait, nil
}

func (s *HTTPService) requireCurrentInputAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFromContext(r.Context())
		if claims == nil || claims.Role != "admin" {
			writeAPIError(w, 403, "forbidden", "完整原文仅限管理员查看")
			return
		}
		user, err := s.store.GetAdminUser(r.Context(), claims.Username)
		if err != nil || !user.Enabled || user.Role != "admin" || user.ID != claims.UserID {
			writeAPIError(w, 403, "forbidden", "管理员权限已变更或账号不可用")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *HTTPService) serveAdminWithInputReview(w http.ResponseWriter, r *http.Request) {
	data, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		writeAPIError(w, 500, "ui_unavailable", "admin UI unavailable")
		return
	}
	nonce, err := GenerateSecret(18)
	if err != nil {
		writeAPIError(w, 500, "ui_unavailable", "admin UI unavailable")
		return
	}
	page := strings.Replace(string(data), "</body>", `<script nonce="{{NONCE}}" src="/admin/input-review.js"></script></body>`, 1)
	page = strings.ReplaceAll(page, "{{NONCE}}", nonce)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'", nonce, nonce))
	_, _ = w.Write([]byte(page))
}
