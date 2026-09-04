from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def replace_once(path: str, old: str, new: str, label: str) -> None:
    content = read(path)
    if new in content:
        return
    count = content.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match in {path}, found {count}")
    write(path, content.replace(old, new, 1))


write(
    "internal/platform/attachment_types.go",
    r'''package platform

import "time"

const (
	attachmentKindImage   = "image"
	attachmentKindText    = "text"
	attachmentKindDocument = "document"
	attachmentKindArchive = "archive"
	attachmentKindBinary  = "binary"
	attachmentKindUnknown = "unknown"
)

type AttachmentSampleRange struct {
	Start  int64  `json:"start"`
	End    int64  `json:"end"`
	Reason string `json:"reason"`
}

type AttachmentAuditItem struct {
	Index                 int                     `json:"index"`
	ParentIndex           int                     `json:"parent_index,omitempty"`
	Name                  string                  `json:"name"`
	Kind                  string                  `json:"kind"`
	MIMEType              string                  `json:"mime_type,omitempty"`
	Source                string                  `json:"source"`
	SHA256                string                  `json:"sha256,omitempty"`
	OriginalBytes         int64                   `json:"original_bytes,omitempty"`
	MaterializedBytes     int64                   `json:"materialized_bytes,omitempty"`
	ExtractedTextBytes    int                     `json:"extracted_text_bytes,omitempty"`
	AuditedTextBytes      int                     `json:"audited_text_bytes,omitempty"`
	Sampled               bool                    `json:"sampled,omitempty"`
	Truncated             bool                    `json:"truncated,omitempty"`
	SampleRanges          []AttachmentSampleRange `json:"sample_ranges,omitempty"`
	ExtractionMethod      string                  `json:"extraction_method,omitempty"`
	SegmentCount          int                     `json:"segment_count,omitempty"`
	SegmentsAudited       int                     `json:"segments_audited,omitempty"`
	Decision              string                  `json:"decision"`
	RiskCode              string                  `json:"risk_code,omitempty"`
	Category              string                  `json:"category,omitempty"`
	Confidence            float64                 `json:"confidence,omitempty"`
	Reason                string                  `json:"reason,omitempty"`
	Evidence              string                  `json:"evidence,omitempty"`
	EvidenceMatchMode     string                  `json:"evidence_match_mode,omitempty"`
	Model                 string                  `json:"model,omitempty"`
	ProfileID             int64                   `json:"profile_id,omitempty"`
	ProfileName           string                  `json:"profile_name,omitempty"`
	ModelAttempts         int                     `json:"model_attempts,omitempty"`
	ModelRetries          int                     `json:"model_retries,omitempty"`
	FallbackCount         int                     `json:"fallback_count,omitempty"`
	Attempts              []AuditAttempt          `json:"attempts,omitempty"`
	ErrorClass            string                  `json:"error_class,omitempty"`
	ErrorReason           string                  `json:"error_reason,omitempty"`
	ChildCount            int                     `json:"child_count,omitempty"`
	LatencyMS             int64                   `json:"latency_ms"`
}

type AttachmentAuditReport struct {
	Items          []AttachmentAuditItem `json:"items"`
	Discovered     int                   `json:"discovered"`
	Skipped        int                   `json:"skipped"`
	Audited        int                   `json:"audited"`
	Allowed        int                   `json:"allowed"`
	Reviewed       int                   `json:"reviewed"`
	Blocked        int                   `json:"blocked"`
	Errors         int                   `json:"errors"`
	Sampled        int                   `json:"sampled"`
	TotalBytes     int64                 `json:"total_bytes"`
	FailClosed     bool                  `json:"fail_closed"`
	Strongest      AuditDecision         `json:"strongest"`
	Latency        time.Duration         `json:"-"`
}

type attachmentCandidate struct {
	Index        int
	ParentIndex  int
	Name         string
	DeclaredMIME string
	Source       string
	URL          string
	EncodedData  string
	OpaqueFileID string
	Data         []byte
	Depth        int
}

type attachmentMaterial struct {
	Candidate            attachmentCandidate
	Name                 string
	MIMEType             string
	Kind                 string
	Data                 []byte
	RemoteVisionURL      string
	OriginalBytes        int64
	MaterializedBytes    int64
	SHA256               string
	SampledAtFetch       bool
	FetchSampleRanges    []AttachmentSampleRange
	ExtractionHint       string
}

type attachmentTextSegment struct {
	Text   string
	Start  int64
	End    int64
	Reason string
}
''',
)

write(
    "internal/platform/attachment_discovery.go",
    r'''package platform

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
)

var attachmentPartTypes = map[string]string{
	"image":       attachmentKindImage,
	"image_url":   attachmentKindImage,
	"input_image": attachmentKindImage,
	"file":        attachmentKindDocument,
	"input_file":  attachmentKindDocument,
	"document":    attachmentKindDocument,
	"attachment":  attachmentKindDocument,
}

func discoverAuditAttachments(body []byte, maximum int) ([]attachmentCandidate, int, error) {
	if maximum < 1 {
		return nil, 0, nil
	}
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, 0, err
	}
	candidates := make([]attachmentCandidate, 0, minInt(maximum, 8))
	skipped := 0
	seen := make(map[string]struct{})
	index := 0

	var walk func(any, bool, string)
	walk = func(value any, eligible bool, path string) {
		switch typed := value.(type) {
		case []any:
			for itemIndex, item := range typed {
				walk(item, eligible, fmt.Sprintf("%s[%d]", path, itemIndex))
			}
		case map[string]any:
			role := strings.ToLower(strings.TrimSpace(stringFromAny(typed["role"])))
			if role != "" {
				if !isAttachmentEndUserRole(role) {
					return
				}
				eligible = true
			}
			partType := strings.ToLower(strings.TrimSpace(stringFromAny(typed["type"])))
			kind, recognized := attachmentPartTypes[partType]
			if recognized && eligible {
				candidate, ok := parseAttachmentPart(typed, kind, partType)
				if ok {
					identity := attachmentCandidateIdentity(candidate)
					if _, duplicate := seen[identity]; !duplicate {
						seen[identity] = struct{}{}
						if len(candidates) >= maximum {
							skipped++
						} else {
							index++
							candidate.Index = index
							candidates = append(candidates, candidate)
						}
					}
					return
				}
			}

			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				lowerKey := strings.ToLower(strings.TrimSpace(key))
				if attachmentDiscoveryIgnoredKey(lowerKey) {
					continue
				}
				childEligible := eligible
				if lowerKey == "attachments" || lowerKey == "files" || lowerKey == "input" || lowerKey == "messages" || lowerKey == "content" {
					childEligible = true
				}
				walk(typed[key], childEligible, path+"."+lowerKey)
			}
		}
	}
	walk(root, false, "$request")
	return candidates, skipped, nil
}

func attachmentDiscoveryIgnoredKey(key string) bool {
	switch key {
	case "instructions", "system", "developer", "tools", "tool_choice", "response_format", "reasoning", "metadata":
		return true
	default:
		return false
	}
}

func isAttachmentEndUserRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "user", "end_user", "human", "customer", "client":
		return true
	default:
		return false
	}
}

func parseAttachmentPart(part map[string]any, kind string, partType string) (attachmentCandidate, bool) {
	candidate := attachmentCandidate{
		Name:         firstAttachmentString(part, "filename", "file_name", "name"),
		DeclaredMIME: firstAttachmentString(part, "mime_type", "media_type", "content_type"),
	}
	if nested, ok := part["file"].(map[string]any); ok {
		mergeAttachmentNested(&candidate, nested)
	}
	if nested, ok := part["image_url"].(map[string]any); ok {
		mergeAttachmentNested(&candidate, nested)
	} else if value, ok := part["image_url"].(string); ok {
		candidate.URL = strings.TrimSpace(value)
	}
	if nested, ok := part["image"].(map[string]any); ok {
		mergeAttachmentNested(&candidate, nested)
	}
	if candidate.URL == "" {
		candidate.URL = firstAttachmentString(part, "file_url", "url", "download_url")
	}
	candidate.OpaqueFileID = firstAttachmentString(part, "file_id", "id")
	candidate.EncodedData = firstAttachmentString(part, "file_data", "image_data", "base64", "data")
	if candidate.EncodedData == "" {
		if content, ok := part["content"].(string); ok && looksLikeInlineAttachmentData(content) {
			candidate.EncodedData = strings.TrimSpace(content)
		}
	}
	if candidate.Name == "" {
		candidate.Name = attachmentNameFromURL(candidate.URL)
	}
	if candidate.Name == "" {
		extension := extensionForDeclaredMIME(candidate.DeclaredMIME)
		candidate.Name = partType + extension
	}
	candidate.Name = sanitizeAttachmentName(candidate.Name)

	switch {
	case candidate.EncodedData != "":
		candidate.Source = "inline_data"
	case candidate.URL != "":
		candidate.Source = "remote_url"
	case candidate.OpaqueFileID != "":
		candidate.Source = "opaque_file_id"
	default:
		return attachmentCandidate{}, false
	}
	if kind == attachmentKindImage && candidate.DeclaredMIME == "" {
		candidate.DeclaredMIME = "image/*"
	}
	return candidate, true
}

func mergeAttachmentNested(candidate *attachmentCandidate, nested map[string]any) {
	if candidate == nil {
		return
	}
	if candidate.Name == "" {
		candidate.Name = firstAttachmentString(nested, "filename", "file_name", "name")
	}
	if candidate.DeclaredMIME == "" {
		candidate.DeclaredMIME = firstAttachmentString(nested, "mime_type", "media_type", "content_type")
	}
	if candidate.URL == "" {
		candidate.URL = firstAttachmentString(nested, "url", "file_url", "download_url")
	}
	if candidate.OpaqueFileID == "" {
		candidate.OpaqueFileID = firstAttachmentString(nested, "file_id", "id")
	}
	if candidate.EncodedData == "" {
		candidate.EncodedData = firstAttachmentString(nested, "file_data", "image_data", "base64", "data")
	}
}

func firstAttachmentString(object map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(stringFromAny(object[key])); value != "" {
			return value
		}
	}
	return ""
}

func stringFromAny(value any) string {
	text, _ := value.(string)
	return text
}

func attachmentCandidateIdentity(candidate attachmentCandidate) string {
	return strings.Join([]string{
		candidate.Source,
		candidate.Name,
		candidate.URL,
		candidate.OpaqueFileID,
		truncateString(candidate.EncodedData, 96),
	}, "|")
}

func looksLikeInlineAttachmentData(value string) bool {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(value), "data:") {
		return true
	}
	if len(value) < 32 || len(value)%4 != 0 {
		return false
	}
	for _, r := range value[:minInt(len(value), 256)] {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '+' && r != '/' && r != '=' && r != '-' && r != '_' && r != '\r' && r != '\n' {
			return false
		}
	}
	return true
}

func decodeInlineAttachmentData(value string, maximum int64) (string, []byte, error) {
	value = strings.TrimSpace(value)
	declaredMIME := ""
	encoded := value
	if strings.HasPrefix(strings.ToLower(value), "data:") {
		comma := strings.IndexByte(value, ',')
		if comma < 0 {
			return "", nil, errors.New("invalid data URL")
		}
		metadata := value[5:comma]
		encoded = value[comma+1:]
		parts := strings.Split(metadata, ";")
		if len(parts) > 0 {
			declaredMIME = strings.TrimSpace(parts[0])
		}
		isBase64 := false
		for _, part := range parts[1:] {
			if strings.EqualFold(strings.TrimSpace(part), "base64") {
				isBase64 = true
			}
		}
		if !isBase64 {
			decoded, err := url.PathUnescape(encoded)
			if err != nil {
				return "", nil, fmt.Errorf("decode data URL: %w", err)
			}
			data := []byte(decoded)
			if int64(len(data)) > maximum {
				return declaredMIME, nil, fmt.Errorf("inline attachment is %d bytes; limit is %d", len(data), maximum)
			}
			return declaredMIME, data, nil
		}
	}
	encoded = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' || r == ' ' {
			return -1
		}
		return r
	}, encoded)
	decodedMaximum := int64(base64.StdEncoding.DecodedLen(len(encoded)))
	if decodedMaximum > maximum+3 {
		return declaredMIME, nil, fmt.Errorf("inline attachment exceeds %d-byte decoded limit", maximum)
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(encoded, "="))
	}
	if err != nil {
		data, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(encoded, "="))
	}
	if err != nil {
		return declaredMIME, nil, fmt.Errorf("decode inline base64: %w", err)
	}
	if int64(len(data)) > maximum {
		return declaredMIME, nil, fmt.Errorf("inline attachment is %d bytes; limit is %d", len(data), maximum)
	}
	return declaredMIME, data, nil
}

func sanitizeAttachmentName(value string) string {
	value = strings.TrimSpace(strings.ToValidUTF8(value, ""))
	value = strings.ReplaceAll(value, "\\", "/")
	value = strings.TrimLeft(value, "/")
	parts := strings.Split(value, "/")
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "." || part == ".." {
			continue
		}
		part = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, part)
		if part != "" {
			clean = append(clean, part)
		}
	}
	if len(clean) == 0 {
		return "attachment"
	}
	value = strings.Join(clean, "/")
	return truncateString(value, 300)
}

func attachmentNameFromURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return filepath.Base(parsed.Path)
}

func extensionForDeclaredMIME(value string) string {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		mediaType = strings.TrimSpace(value)
	}
	extensions, _ := mime.ExtensionsByType(mediaType)
	if len(extensions) == 0 {
		return ""
	}
	return extensions[0]
}

func minInt(left int, right int) int {
	if left < right {
		return left
	}
	return right
}
''',
)

write(
    "internal/platform/attachment_fetch.go",
    r'''package platform

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func newAttachmentHTTPClient(allowPrivate bool, tlsMinimum uint16, timeout time.Duration) *http.Client {
	if tlsMinimum == 0 {
		tlsMinimum = tls.VersionTLS12
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &http.Client{
		Transport: NewSafeTransport(allowPrivate, tlsMinimum),
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("attachment URL redirects are disabled")
		},
	}
}

func materializeAttachment(
	ctx context.Context,
	client *http.Client,
	candidate attachmentCandidate,
	maximum int64,
	allowRemote bool,
) (attachmentMaterial, error) {
	material := attachmentMaterial{
		Candidate: candidate,
		Name:      sanitizeAttachmentName(candidate.Name),
	}
	declaredMIME := normalizeAttachmentMIME(candidate.DeclaredMIME)

	switch candidate.Source {
	case "inline_data":
		inlineMIME, data, err := decodeInlineAttachmentData(candidate.EncodedData, maximum)
		if err != nil {
			return material, err
		}
		material.Data = data
		material.OriginalBytes = int64(len(data))
		material.MaterializedBytes = int64(len(data))
		if declaredMIME == "" || declaredMIME == "application/octet-stream" || declaredMIME == "image/*" {
			declaredMIME = normalizeAttachmentMIME(inlineMIME)
		}
	case "remote_url":
		if !allowRemote {
			return material, errors.New("remote attachment URLs are disabled")
		}
		return fetchRemoteAttachment(ctx, client, candidate, maximum, declaredMIME)
	case "opaque_file_id":
		return material, errors.New("opaque file_id cannot be audited without inline file_data or a safe file_url")
	default:
		return material, fmt.Errorf("unsupported attachment source %q", candidate.Source)
	}

	material.MIMEType = detectAttachmentMIME(material.Name, declaredMIME, material.Data)
	material.Kind = classifyAttachmentKind(material.Name, material.MIMEType, material.Data)
	material.SHA256 = attachmentSHA256(material.Data)
	return material, nil
}

func fetchRemoteAttachment(
	ctx context.Context,
	client *http.Client,
	candidate attachmentCandidate,
	maximum int64,
	declaredMIME string,
) (attachmentMaterial, error) {
	material := attachmentMaterial{
		Candidate: candidate,
		Name:      sanitizeAttachmentName(candidate.Name),
	}
	parsed, err := url.Parse(strings.TrimSpace(candidate.URL))
	if err != nil || parsed == nil {
		return material, errors.New("invalid remote attachment URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return material, errors.New("remote attachment URL must use http or https")
	}
	if parsed.User != nil || parsed.Hostname() == "" {
		return material, errors.New("remote attachment URL contains invalid authority")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return material, err
	}
	request.Header.Set("Accept", "application/octet-stream,image/*,text/*;q=0.9,*/*;q=0.5")
	response, err := client.Do(request)
	if err != nil {
		return material, fmt.Errorf("fetch remote attachment: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return material, fmt.Errorf("remote attachment returned HTTP %d", response.StatusCode)
	}
	contentLength := response.ContentLength
	if contentLength > 0 {
		material.OriginalBytes = contentLength
	}
	responseMIME := normalizeAttachmentMIME(response.Header.Get("Content-Type"))
	if material.Name == "attachment" || material.Name == "" {
		if filename := filenameFromContentDisposition(response.Header.Get("Content-Disposition")); filename != "" {
			material.Name = sanitizeAttachmentName(filename)
		} else if name := attachmentNameFromURL(parsed.String()); name != "" {
			material.Name = sanitizeAttachmentName(name)
		}
	}
	provisionalMIME := firstNonEmpty(responseMIME, declaredMIME)
	if contentLength > maximum && strings.HasPrefix(provisionalMIME, "image/") {
		// The URL has already passed the SSRF-safe transport. Let the configured
		// multimodal model retrieve/downsample a large public image rather than
		// buffering it in the gateway.
		material.RemoteVisionURL = parsed.String()
		material.MIMEType = provisionalMIME
		material.Kind = attachmentKindImage
		material.MaterializedBytes = 0
		material.ExtractionHint = "remote_image_reference"
		return material, nil
	}
	if contentLength > maximum && attachmentLooksTextual(material.Name, provisionalMIME) {
		response.Body.Close()
		return fetchRemoteTextRanges(ctx, client, candidate, maximum, contentLength, provisionalMIME)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return material, fmt.Errorf("read remote attachment: %w", err)
	}
	if int64(len(data)) > maximum {
		return material, fmt.Errorf("remote attachment exceeds %d-byte materialization limit", maximum)
	}
	material.Data = data
	if material.OriginalBytes == 0 {
		material.OriginalBytes = int64(len(data))
	}
	material.MaterializedBytes = int64(len(data))
	material.MIMEType = detectAttachmentMIME(material.Name, provisionalMIME, data)
	material.Kind = classifyAttachmentKind(material.Name, material.MIMEType, data)
	material.SHA256 = attachmentSHA256(data)
	return material, nil
}

func fetchRemoteTextRanges(
	ctx context.Context,
	client *http.Client,
	candidate attachmentCandidate,
	maximum int64,
	total int64,
	declaredMIME string,
) (attachmentMaterial, error) {
	material := attachmentMaterial{
		Candidate:         candidate,
		Name:              sanitizeAttachmentName(candidate.Name),
		MIMEType:          declaredMIME,
		Kind:              attachmentKindText,
		OriginalBytes:     total,
		SampledAtFetch:    true,
		ExtractionHint:    "remote_http_ranges",
	}
	if maximum < 12*1024 {
		return material, errors.New("attachment materialization limit is too small for ranged text sampling")
	}
	window := maximum / 3
	if window < 4096 {
		window = 4096
	}
	starts := []int64{0, maxInt64(0, total/2-window/2), maxInt64(0, total-window)}
	var builder strings.Builder
	seen := make(map[int64]struct{})
	for _, start := range starts {
		if _, duplicate := seen[start]; duplicate {
			continue
		}
		seen[start] = struct{}{}
		end := minInt64(total-1, start+window-1)
		part, partial, err := fetchAttachmentRange(ctx, client, candidate.URL, start, end, window)
		if err != nil {
			return material, err
		}
		if !partial && start > 0 {
			continue
		}
		builder.WriteString(fmt.Sprintf("\n[REMOTE_FILE_RANGE %d-%d OF %d]\n", start, start+int64(len(part)), total))
		builder.Write(part)
		material.FetchSampleRanges = append(material.FetchSampleRanges, AttachmentSampleRange{
			Start: start,
			End:   start + int64(len(part)),
			Reason: "remote_range",
		})
	}
	material.Data = []byte(builder.String())
	material.MaterializedBytes = int64(len(material.Data))
	material.SHA256 = attachmentSHA256(material.Data)
	return material, nil
}

func fetchAttachmentRange(ctx context.Context, client *http.Client, rawURL string, start int64, end int64, maximum int64) ([]byte, bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, err
	}
	request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	response, err := client.Do(request)
	if err != nil {
		return nil, false, fmt.Errorf("fetch attachment range: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusPartialContent && response.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("attachment range returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maximum {
		data = data[:maximum]
	}
	return data, response.StatusCode == http.StatusPartialContent, nil
}

func filenameFromContentDisposition(value string) string {
	_, parameters, err := mime.ParseMediaType(value)
	if err != nil {
		return ""
	}
	return parameters["filename"]
}

func normalizeAttachmentMIME(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if mediaType, _, err := mime.ParseMediaType(value); err == nil {
		return strings.ToLower(strings.TrimSpace(mediaType))
	}
	return value
}

func detectAttachmentMIME(name string, declared string, data []byte) string {
	declared = normalizeAttachmentMIME(declared)
	detected := ""
	if len(data) > 0 {
		detected = normalizeAttachmentMIME(http.DetectContentType(data[:minInt(len(data), 512)]))
	}
	extensionMIME := normalizeAttachmentMIME(mime.TypeByExtension(strings.ToLower(filepath.Ext(name))))
	for _, candidate := range []string{detected, declared, extensionMIME} {
		if candidate != "" && candidate != "application/octet-stream" && candidate != "image/*" {
			return candidate
		}
	}
	return firstNonEmpty(declared, detected, extensionMIME, "application/octet-stream")
}

func classifyAttachmentKind(name string, mimeType string, data []byte) string {
	lowerMIME := strings.ToLower(mimeType)
	extension := strings.ToLower(filepath.Ext(name))
	if strings.HasPrefix(lowerMIME, "image/") || isImageExtension(extension) {
		return attachmentKindImage
	}
	if isArchiveAttachment(extension, lowerMIME, data) {
		return attachmentKindArchive
	}
	if attachmentLooksTextual(name, lowerMIME) {
		return attachmentKindText
	}
	if isDocumentExtension(extension) || isDocumentMIME(lowerMIME) {
		return attachmentKindDocument
	}
	if len(data) > 0 {
		return attachmentKindBinary
	}
	return attachmentKindUnknown
}

func attachmentLooksTextual(name string, mimeType string) bool {
	if strings.HasPrefix(mimeType, "text/") {
		return true
	}
	switch mimeType {
	case "application/json", "application/xml", "application/yaml", "application/x-yaml", "application/javascript", "application/sql", "application/graphql", "application/x-httpd-php", "message/rfc822":
		return true
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".txt", ".md", ".markdown", ".json", ".jsonl", ".yaml", ".yml", ".xml", ".csv", ".tsv", ".log", ".ini", ".conf", ".config", ".env", ".properties", ".toml", ".sql", ".graphql", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".py", ".go", ".rs", ".java", ".kt", ".kts", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".php", ".rb", ".lua", ".swift", ".dart", ".html", ".htm", ".css", ".scss", ".vue", ".svelte", ".rtf", ".eml":
		return true
	default:
		return false
	}
}

func isImageExtension(extension string) bool {
	switch extension {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".avif":
		return true
	default:
		return false
	}
}

func isDocumentExtension(extension string) bool {
	switch extension {
	case ".pdf", ".docx", ".pptx", ".xlsx", ".odt", ".ods", ".odp":
		return true
	default:
		return false
	}
}

func isDocumentMIME(value string) bool {
	for _, marker := range []string{"pdf", "wordprocessingml", "presentationml", "spreadsheetml", "opendocument"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func isArchiveAttachment(extension string, mimeType string, data []byte) bool {
	if extension == ".zip" || extension == ".tar" || extension == ".tgz" || extension == ".gz" || extension == ".gzip" {
		// OOXML and ODF documents are ZIP containers but are documents first.
		if isDocumentExtension(extension) {
			return false
		}
		return true
	}
	if strings.Contains(mimeType, "zip") || strings.Contains(mimeType, "tar") || strings.Contains(mimeType, "gzip") {
		return true
	}
	return len(data) >= 4 && (string(data[:4]) == "PK\x03\x04" || string(data[:2]) == "\x1f\x8b")
}

func attachmentSHA256(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func parseContentLength(value string) int64 {
	parsed, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if parsed < 0 {
		return 0
	}
	return parsed
}

func maxInt64(left int64, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

func minInt64(left int64, right int64) int64 {
	if left < right {
		return left
	}
	return right
}
''',
)

write(
    "internal/platform/attachment_extract.go",
    r'''package platform

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	pdf "github.com/ledongthuc/pdf"
)

var attachmentHTMLTagPattern = regexp.MustCompile(`(?s)<[^>]{1,4096}>`)
var attachmentRTFControlPattern = regexp.MustCompile(`\\[a-zA-Z]+-?[0-9]* ?|\\'[0-9a-fA-F]{2}|[{}]`)

var attachmentSignalTerms = []string{
	"password", "credential", "authorization", "bearer", "api key", "api_key", "token", "cookie", "session",
	"keylogger", "stealer", "ransomware", "malware", "backdoor", "reverse shell", "c2", "command and control",
	"exfiltrat", "bypass", "disable antivirus", "persistence", "mimikatz", "powershell -enc", "curl http",
	"密码", "凭据", "密钥", "令牌", "会话", "窃取", "外传", "木马", "后门", "勒索", "持久化", "绕过",
}

func extractAttachmentText(material attachmentMaterial, maximum int) (string, string, bool, error) {
	if maximum < 4096 {
		maximum = 4096
	}
	data := material.Data
	name := strings.ToLower(material.Name)
	extension := strings.ToLower(filepath.Ext(name))
	mimeType := strings.ToLower(material.MIMEType)
	var text string
	var method string
	var err error

	switch {
	case extension == ".pdf" || mimeType == "application/pdf":
		text, err = extractPDFText(data, maximum)
		method = "pdf_text"
	case extension == ".docx" || strings.Contains(mimeType, "wordprocessingml"):
		text, err = extractZIPXMLText(data, maximum, []string{"word/document.xml", "word/header", "word/footer", "word/comments.xml"})
		method = "docx_xml"
	case extension == ".pptx" || strings.Contains(mimeType, "presentationml"):
		text, err = extractZIPXMLText(data, maximum, []string{"ppt/slides/slide", "ppt/notesSlides/notesSlide"})
		method = "pptx_xml"
	case extension == ".xlsx" || strings.Contains(mimeType, "spreadsheetml"):
		text, err = extractZIPXMLText(data, maximum, []string{"xl/sharedStrings.xml", "xl/worksheets/sheet", "xl/comments"})
		method = "xlsx_xml"
	case extension == ".odt" || extension == ".ods" || extension == ".odp" || strings.Contains(mimeType, "opendocument"):
		text, err = extractZIPXMLText(data, maximum, []string{"content.xml", "styles.xml", "meta.xml"})
		method = "odf_xml"
	case extension == ".eml" || mimeType == "message/rfc822":
		text, err = extractEmailText(data, maximum)
		method = "rfc822"
	case extension == ".html" || extension == ".htm" || mimeType == "text/html":
		text = stripAttachmentHTML(decodeAttachmentText(data))
		method = "html_text"
	case extension == ".rtf" || mimeType == "application/rtf" || mimeType == "text/rtf":
		text = attachmentRTFControlPattern.ReplaceAllString(decodeAttachmentText(data), " ")
		method = "rtf_text"
	case material.Kind == attachmentKindText || attachmentLooksTextual(material.Name, mimeType):
		text = decodeAttachmentText(data)
		method = firstNonEmpty(material.ExtractionHint, "plain_text")
	default:
		text = extractPrintableAttachmentStrings(data, maximum)
		method = "binary_strings"
	}
	if err != nil {
		return "", method, false, err
	}
	text = normalizeAttachmentAuditText(text)
	truncated := false
	if len(text) > maximum {
		text = safeUTF8Prefix(text, maximum)
		truncated = true
	}
	if strings.TrimSpace(text) == "" {
		return "", method, truncated, errors.New("attachment did not contain auditable text")
	}
	return text, method, truncated, nil
}

func extractPDFText(data []byte, maximum int) (string, error) {
	temporary, err := os.CreateTemp("", "newapi-risk-attachment-*.pdf")
	if err != nil {
		return "", err
	}
	path := temporary.Name()
	defer os.Remove(path)
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	file, reader, err := pdf.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	plain, err := reader.GetPlainText()
	if err != nil {
		return "", err
	}
	content, err := io.ReadAll(io.LimitReader(plain, int64(maximum+1)))
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func extractZIPXMLText(data []byte, maximum int, prefixes []string) (string, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}
	files := make([]*zip.File, 0, len(reader.File))
	for _, file := range reader.File {
		name := filepath.ToSlash(file.Name)
		for _, prefix := range prefixes {
			if strings.HasPrefix(name, prefix) {
				files = append(files, file)
				break
			}
		}
	}
	sort.Slice(files, func(i int, j int) bool { return naturalAttachmentLess(files[i].Name, files[j].Name) })
	var builder strings.Builder
	for _, file := range files {
		if builder.Len() >= maximum {
			break
		}
		stream, err := file.Open()
		if err != nil {
			return "", err
		}
		decoder := xml.NewDecoder(io.LimitReader(stream, int64(maximum-builder.Len()+1)))
		builder.WriteString("\n[DOCUMENT_PART ")
		builder.WriteString(sanitizeAttachmentName(file.Name))
		builder.WriteString("]\n")
		for builder.Len() < maximum {
			token, err := decoder.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				stream.Close()
				return "", err
			}
			switch typed := token.(type) {
			case xml.CharData:
				value := strings.TrimSpace(string(typed))
				if value != "" {
					builder.WriteString(value)
					builder.WriteByte(' ')
				}
			case xml.EndElement:
				switch typed.Name.Local {
				case "p", "tr", "row", "si", "text:p":
					builder.WriteByte('\n')
				}
			}
		}
		stream.Close()
	}
	if builder.Len() == 0 {
		return "", errors.New("document archive did not contain supported XML text parts")
	}
	return builder.String(), nil
}

func extractEmailText(data []byte, maximum int) (string, error) {
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	var builder strings.Builder
	for _, key := range []string{"From", "To", "Cc", "Subject", "Date"} {
		if value := strings.TrimSpace(message.Header.Get(key)); value != "" {
			builder.WriteString(key)
			builder.WriteString(": ")
			builder.WriteString(value)
			builder.WriteByte('\n')
		}
	}
	body, err := io.ReadAll(io.LimitReader(message.Body, int64(maximum-builder.Len()+1)))
	if err != nil {
		return "", err
	}
	builder.Write(body)
	return builder.String(), nil
}

func stripAttachmentHTML(value string) string {
	value = attachmentHTMLTagPattern.ReplaceAllString(value, " ")
	return html.UnescapeString(value)
}

func decodeAttachmentText(data []byte) string {
	if len(data) >= 2 {
		switch {
		case data[0] == 0xff && data[1] == 0xfe:
			return decodeUTF16Attachment(data[2:], binary.LittleEndian)
		case data[0] == 0xfe && data[1] == 0xff:
			return decodeUTF16Attachment(data[2:], binary.BigEndian)
		}
	}
	if len(data) >= 3 && bytes.Equal(data[:3], []byte{0xef, 0xbb, 0xbf}) {
		data = data[3:]
	}
	return strings.ToValidUTF8(string(data), "�")
}

func decodeUTF16Attachment(data []byte, order binary.ByteOrder) string {
	units := make([]uint16, 0, len(data)/2)
	for index := 0; index+1 < len(data); index += 2 {
		units = append(units, order.Uint16(data[index:index+2]))
	}
	return string(utf16.Decode(units))
}

func extractPrintableAttachmentStrings(data []byte, maximum int) string {
	var builder strings.Builder
	builder.Grow(minInt(maximum, len(data)/2))
	var run []rune
	flush := func() {
		if len(run) >= 4 {
			builder.WriteString(string(run))
			builder.WriteByte('\n')
		}
		run = run[:0]
	}
	for len(data) > 0 && builder.Len() < maximum {
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			flush()
			data = data[1:]
			continue
		}
		data = data[size:]
		if unicode.IsPrint(r) && !unicode.IsControl(r) {
			run = append(run, r)
			if len(run) > 4096 {
				flush()
			}
		} else {
			flush()
		}
	}
	flush()
	return builder.String()
}

func normalizeAttachmentAuditText(value string) string {
	value = strings.ToValidUTF8(value, "")
	for _, expression := range adaptiveSecretPatterns {
		value = expression.ReplaceAllString(value, "[USER_PROVIDED_SECRET]")
	}
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	lines := strings.Split(value, "\n")
	for index := range lines {
		lines[index] = strings.TrimRight(lines[index], " \t\r")
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func sampleAttachmentText(value string, maximum int, segmentBytes int) ([]attachmentTextSegment, []AttachmentSampleRange, bool) {
	if maximum < 4096 {
		maximum = 4096
	}
	if segmentBytes < 4096 {
		segmentBytes = 4096
	}
	if segmentBytes > maximum {
		segmentBytes = maximum
	}
	if len(value) <= maximum {
		segments := splitAttachmentRange(value, 0, "full", segmentBytes)
		return segments, []AttachmentSampleRange{{Start: 0, End: int64(len(value)), Reason: "full"}}, false
	}

	total := len(value)
	baseWindow := maximum / 10
	if baseWindow < 4096 {
		baseWindow = 4096
	}
	ranges := []AttachmentSampleRange{
		{Start: 0, End: int64(minInt(total, maximum/4)), Reason: "head"},
		{Start: int64(maxInt(0, total-maximum/4)), End: int64(total), Reason: "tail"},
	}
	for index := 1; index <= 4; index++ {
		center := total * index / 5
		start := maxInt(0, center-baseWindow/2)
		end := minInt(total, start+baseWindow)
		ranges = append(ranges, AttachmentSampleRange{Start: int64(start), End: int64(end), Reason: "distributed"})
	}
	lower := strings.ToLower(value)
	for _, term := range attachmentSignalTerms {
		searchFrom := 0
		for occurrence := 0; occurrence < 2; occurrence++ {
			relative := strings.Index(lower[searchFrom:], term)
			if relative < 0 {
				break
			}
			position := searchFrom + relative
			start := maxInt(0, position-2048)
			end := minInt(total, position+len(term)+4096)
			ranges = append(ranges, AttachmentSampleRange{Start: int64(start), End: int64(end), Reason: "security_signal"})
			searchFrom = position + len(term)
		}
	}
	ranges = mergeAttachmentRanges(ranges, int64(total))
	ranges = fitAttachmentRanges(ranges, maximum)
	segments := make([]attachmentTextSegment, 0, len(ranges)*2)
	for _, item := range ranges {
		start := safeUTF8Start(value, int(item.Start))
		end := safeUTF8End(value, int(item.End))
		if end <= start {
			continue
		}
		segments = append(segments, splitAttachmentRange(value[start:end], int64(start), item.Reason, segmentBytes)...)
	}
	return segments, ranges, true
}

func splitAttachmentRange(value string, base int64, reason string, segmentBytes int) []attachmentTextSegment {
	if value == "" {
		return nil
	}
	parts := splitAuditTextByBytes(value, segmentBytes, minInt(2048, segmentBytes/8))
	segments := make([]attachmentTextSegment, 0, len(parts))
	search := 0
	for _, part := range parts {
		relative := strings.Index(value[search:], part)
		if relative < 0 {
			relative = 0
		}
		start := search + relative
		end := start + len(part)
		segments = append(segments, attachmentTextSegment{
			Text:   part,
			Start:  base + int64(start),
			End:    base + int64(end),
			Reason: reason,
		})
		search = maxInt(search, end-minInt(2048, len(part)/8))
	}
	return segments
}

func mergeAttachmentRanges(input []AttachmentSampleRange, total int64) []AttachmentSampleRange {
	filtered := make([]AttachmentSampleRange, 0, len(input))
	for _, item := range input {
		item.Start = maxInt64(0, minInt64(total, item.Start))
		item.End = maxInt64(item.Start, minInt64(total, item.End))
		if item.End > item.Start {
			filtered = append(filtered, item)
		}
	}
	sort.Slice(filtered, func(i int, j int) bool {
		if filtered[i].Start == filtered[j].Start {
			return filtered[i].End < filtered[j].End
		}
		return filtered[i].Start < filtered[j].Start
	})
	result := make([]AttachmentSampleRange, 0, len(filtered))
	for _, item := range filtered {
		if len(result) == 0 || item.Start > result[len(result)-1].End {
			result = append(result, item)
			continue
		}
		last := &result[len(result)-1]
		if item.End > last.End {
			last.End = item.End
		}
		if item.Reason == "security_signal" {
			last.Reason = "security_signal"
		}
	}
	return result
}

func fitAttachmentRanges(input []AttachmentSampleRange, maximum int) []AttachmentSampleRange {
	if len(input) == 0 {
		return nil
	}
	total := int64(0)
	for _, item := range input {
		total += item.End - item.Start
	}
	if total <= int64(maximum) {
		return input
	}
	// Preserve head, tail and security-signal windows first, then distributed
	// windows. Each selected range is proportionally reduced when needed.
	sort.SliceStable(input, func(i int, j int) bool {
		priority := func(reason string) int {
			switch reason {
			case "security_signal":
				return 0
			case "head", "tail":
				return 1
			default:
				return 2
			}
		}
		return priority(input[i].Reason) < priority(input[j].Reason)
	})
	remaining := int64(maximum)
	result := make([]AttachmentSampleRange, 0, len(input))
	for _, item := range input {
		if remaining <= 0 {
			break
		}
		length := item.End - item.Start
		allocation := minInt64(length, remaining)
		if allocation < 1024 && len(result) > 0 {
			continue
		}
		if allocation < length {
			middle := (item.Start + item.End) / 2
			item.Start = maxInt64(item.Start, middle-allocation/2)
			item.End = item.Start + allocation
		}
		result = append(result, item)
		remaining -= item.End - item.Start
	}
	sort.Slice(result, func(i int, j int) bool { return result[i].Start < result[j].Start })
	return result
}

func expandArchiveAttachment(material attachmentMaterial, maximumEntries int, maximumBytes int64, maximumDepth int) ([]attachmentCandidate, error) {
	if material.Candidate.Depth >= maximumDepth {
		return nil, fmt.Errorf("archive nesting depth exceeds configured maximum %d", maximumDepth)
	}
	extension := strings.ToLower(filepath.Ext(material.Name))
	mimeType := strings.ToLower(material.MIMEType)
	switch {
	case extension == ".zip" || strings.Contains(mimeType, "zip") || (len(material.Data) >= 4 && string(material.Data[:4]) == "PK\x03\x04"):
		return expandZIPAttachment(material, maximumEntries, maximumBytes)
	case extension == ".tar" || strings.Contains(mimeType, "tar"):
		return expandTARAttachment(material, bytes.NewReader(material.Data), maximumEntries, maximumBytes)
	case extension == ".tgz" || extension == ".gz" || extension == ".gzip" || strings.Contains(mimeType, "gzip") || (len(material.Data) >= 2 && string(material.Data[:2]) == "\x1f\x8b"):
		stream, err := gzip.NewReader(bytes.NewReader(material.Data))
		if err != nil {
			return nil, err
		}
		defer stream.Close()
		if strings.HasSuffix(strings.ToLower(strings.TrimSuffix(material.Name, extension)), ".tar") || extension == ".tgz" {
			return expandTARAttachment(material, stream, maximumEntries, maximumBytes)
		}
		data, err := io.ReadAll(io.LimitReader(stream, maximumBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > maximumBytes {
			return nil, errors.New("gzip entry exceeds configured uncompressed-byte limit")
		}
		name := strings.TrimSuffix(material.Name, extension)
		if name == "" {
			name = "gzip-content"
		}
		return []attachmentCandidate{{
			ParentIndex:  material.Candidate.Index,
			Name:         sanitizeAttachmentName(material.Name + "::" + name),
			DeclaredMIME: "",
			Source:       "archive_entry",
			Data:         data,
			Depth:        material.Candidate.Depth + 1,
		}}, nil
	default:
		return nil, errors.New("unsupported archive type")
	}
}

func expandZIPAttachment(material attachmentMaterial, maximumEntries int, maximumBytes int64) ([]attachmentCandidate, error) {
	reader, err := zip.NewReader(bytes.NewReader(material.Data), int64(len(material.Data)))
	if err != nil {
		return nil, err
	}
	result := make([]attachmentCandidate, 0, minInt(len(reader.File), maximumEntries))
	total := int64(0)
	for _, entry := range reader.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		if len(result) >= maximumEntries {
			return nil, fmt.Errorf("archive contains more than %d files", maximumEntries)
		}
		if entry.UncompressedSize64 > uint64(maximumBytes) {
			return nil, fmt.Errorf("archive entry %q exceeds uncompressed-byte limit", sanitizeAttachmentName(entry.Name))
		}
		if entry.CompressedSize64 > 0 && entry.UncompressedSize64/entry.CompressedSize64 > 200 {
			return nil, fmt.Errorf("archive entry %q exceeds decompression-ratio limit", sanitizeAttachmentName(entry.Name))
		}
		stream, err := entry.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(stream, maximumBytes-total+1))
		stream.Close()
		if err != nil {
			return nil, err
		}
		total += int64(len(data))
		if total > maximumBytes {
			return nil, errors.New("archive exceeds configured total uncompressed-byte limit")
		}
		result = append(result, attachmentCandidate{
			ParentIndex: material.Candidate.Index,
			Name:        sanitizeAttachmentName(material.Name + "::" + entry.Name),
			Source:      "archive_entry",
			Data:        data,
			Depth:       material.Candidate.Depth + 1,
		})
	}
	return result, nil
}

func expandTARAttachment(material attachmentMaterial, source io.Reader, maximumEntries int, maximumBytes int64) ([]attachmentCandidate, error) {
	reader := tar.NewReader(source)
	result := make([]attachmentCandidate, 0, minInt(maximumEntries, 16))
	total := int64(0)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}
		if len(result) >= maximumEntries {
			return nil, fmt.Errorf("archive contains more than %d files", maximumEntries)
		}
		if header.Size < 0 || header.Size > maximumBytes-total {
			return nil, errors.New("archive exceeds configured total uncompressed-byte limit")
		}
		data, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil {
			return nil, err
		}
		total += int64(len(data))
		if total > maximumBytes {
			return nil, errors.New("archive exceeds configured total uncompressed-byte limit")
		}
		result = append(result, attachmentCandidate{
			ParentIndex: material.Candidate.Index,
			Name:        sanitizeAttachmentName(material.Name + "::" + header.Name),
			Source:      "archive_entry",
			Data:        data,
			Depth:       material.Candidate.Depth + 1,
		})
	}
	return result, nil
}

func materializeArchiveEntry(candidate attachmentCandidate) attachmentMaterial {
	mimeType := detectAttachmentMIME(candidate.Name, candidate.DeclaredMIME, candidate.Data)
	return attachmentMaterial{
		Candidate:         candidate,
		Name:              sanitizeAttachmentName(candidate.Name),
		MIMEType:          mimeType,
		Kind:              classifyAttachmentKind(candidate.Name, mimeType, candidate.Data),
		Data:              candidate.Data,
		OriginalBytes:     int64(len(candidate.Data)),
		MaterializedBytes: int64(len(candidate.Data)),
		SHA256:            attachmentSHA256(candidate.Data),
	}
}

func safeUTF8Prefix(value string, maximum int) string {
	if maximum >= len(value) {
		return value
	}
	end := safeUTF8End(value, maximum)
	return value[:end]
}

func safeUTF8Start(value string, index int) int {
	if index <= 0 {
		return 0
	}
	if index >= len(value) {
		return len(value)
	}
	for index < len(value) && !utf8.RuneStart(value[index]) {
		index++
	}
	return index
}

func safeUTF8End(value string, index int) int {
	if index <= 0 {
		return 0
	}
	if index >= len(value) {
		return len(value)
	}
	for index > 0 && !utf8.RuneStart(value[index]) {
		index--
	}
	return index
}

func naturalAttachmentLess(left string, right string) bool {
	leftBase := strings.ToLower(filepath.Base(left))
	rightBase := strings.ToLower(filepath.Base(right))
	leftNumber := trailingAttachmentNumber(leftBase)
	rightNumber := trailingAttachmentNumber(rightBase)
	if leftNumber >= 0 && rightNumber >= 0 && leftNumber != rightNumber {
		return leftNumber < rightNumber
	}
	return leftBase < rightBase
}

func trailingAttachmentNumber(value string) int {
	end := strings.LastIndexByte(value, '.')
	if end < 0 {
		end = len(value)
	}
	start := end
	for start > 0 && value[start-1] >= '0' && value[start-1] <= '9' {
		start--
	}
	if start == end {
		return -1
	}
	parsed, err := strconv.Atoi(value[start:end])
	if err != nil {
		return -1
	}
	return parsed
}

func maxInt(left int, right int) int {
	if left > right {
		return left
	}
	return right
}
''',
)

write(
    "internal/platform/attachment_image.go",
    r'''package platform

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"math"
	"strings"
)

type preparedAttachmentImage struct {
	URL            string
	MIMEType       string
	Bytes          int64
	OriginalWidth  int
	OriginalHeight int
	OutputWidth    int
	OutputHeight   int
	Resized        bool
}

func prepareAttachmentImage(material attachmentMaterial, maximumBytes int, maximumPixels int64) (preparedAttachmentImage, error) {
	if material.RemoteVisionURL != "" {
		return preparedAttachmentImage{
			URL:      material.RemoteVisionURL,
			MIMEType: material.MIMEType,
			Bytes:    material.OriginalBytes,
		}, nil
	}
	if len(material.Data) == 0 {
		return preparedAttachmentImage{}, errors.New("image attachment has no bytes")
	}
	if maximumBytes < 64*1024 {
		maximumBytes = 64 * 1024
	}
	if maximumPixels < 1024*1024 {
		maximumPixels = 1024 * 1024
	}
	mimeType := material.MIMEType
	if !strings.HasPrefix(mimeType, "image/") {
		mimeType = "image/jpeg"
	}
	configuration, format, configErr := image.DecodeConfig(bytes.NewReader(material.Data))
	if configErr == nil {
		pixels := int64(configuration.Width) * int64(configuration.Height)
		if pixels <= maximumPixels && len(material.Data) <= maximumBytes {
			return preparedAttachmentImage{
				URL:            attachmentImageDataURL(mimeType, material.Data),
				MIMEType:       mimeType,
				Bytes:          int64(len(material.Data)),
				OriginalWidth:  configuration.Width,
				OriginalHeight: configuration.Height,
				OutputWidth:    configuration.Width,
				OutputHeight:   configuration.Height,
			}, nil
		}
		if pixels > maximumPixels*8 {
			return preparedAttachmentImage{}, fmt.Errorf("image dimensions %dx%d exceed safe decode ceiling", configuration.Width, configuration.Height)
		}
	} else if len(material.Data) <= maximumBytes {
		// vLLM/OpenAI-compatible multimodal servers can decode formats not in the
		// Go standard library, such as WebP and AVIF. Pass bounded data through.
		return preparedAttachmentImage{
			URL:      attachmentImageDataURL(mimeType, material.Data),
			MIMEType: mimeType,
			Bytes:    int64(len(material.Data)),
		}, nil
	}

	source, decodedFormat, err := image.Decode(bytes.NewReader(material.Data))
	if err != nil {
		return preparedAttachmentImage{}, fmt.Errorf("decode oversized image: %w", err)
	}
	if format == "" {
		format = decodedFormat
	}
	bounds := source.Bounds()
	originalWidth := bounds.Dx()
	originalHeight := bounds.Dy()
	width, height := attachmentImageTargetDimensions(originalWidth, originalHeight, maximumPixels, 2048)
	for attempt := 0; attempt < 5; attempt++ {
		resized := resizeAttachmentImageNearest(source, width, height)
		for _, quality := range []int{82, 70, 58, 45} {
			var output bytes.Buffer
			if err := jpeg.Encode(&output, resized, &jpeg.Options{Quality: quality}); err != nil {
				return preparedAttachmentImage{}, err
			}
			if output.Len() <= maximumBytes {
				return preparedAttachmentImage{
					URL:            attachmentImageDataURL("image/jpeg", output.Bytes()),
					MIMEType:       "image/jpeg",
					Bytes:          int64(output.Len()),
					OriginalWidth:  originalWidth,
					OriginalHeight: originalHeight,
					OutputWidth:    width,
					OutputHeight:   height,
					Resized:        width != originalWidth || height != originalHeight || format != "jpeg",
				}, nil
			}
		}
		width = maxInt(320, width*3/4)
		height = maxInt(320, height*3/4)
	}
	return preparedAttachmentImage{}, fmt.Errorf("image could not be reduced below %d bytes", maximumBytes)
}

func attachmentImageTargetDimensions(width int, height int, maximumPixels int64, maximumSide int) (int, int) {
	if width < 1 || height < 1 {
		return 1, 1
	}
	scale := 1.0
	if width > maximumSide || height > maximumSide {
		scale = math.Min(float64(maximumSide)/float64(width), float64(maximumSide)/float64(height))
	}
	pixels := float64(width) * float64(height) * scale * scale
	if pixels > float64(maximumPixels) {
		scale *= math.Sqrt(float64(maximumPixels) / pixels)
	}
	if scale > 1 {
		scale = 1
	}
	return maxInt(1, int(math.Round(float64(width)*scale))), maxInt(1, int(math.Round(float64(height)*scale)))
}

func resizeAttachmentImageNearest(source image.Image, width int, height int) *image.RGBA {
	output := image.NewRGBA(image.Rect(0, 0, width, height))
	bounds := source.Bounds()
	sourceWidth := bounds.Dx()
	sourceHeight := bounds.Dy()
	for y := 0; y < height; y++ {
		sourceY := bounds.Min.Y + y*sourceHeight/height
		for x := 0; x < width; x++ {
			sourceX := bounds.Min.X + x*sourceWidth/width
			pixel := color.RGBAModel.Convert(source.At(sourceX, sourceY)).(color.RGBA)
			if pixel.A < 255 {
				alpha := uint32(pixel.A)
				pixel.R = uint8((uint32(pixel.R)*alpha + 255*(255-alpha)) / 255)
				pixel.G = uint8((uint32(pixel.G)*alpha + 255*(255-alpha)) / 255)
				pixel.B = uint8((uint32(pixel.B)*alpha + 255*(255-alpha)) / 255)
				pixel.A = 255
			}
			output.SetRGBA(x, y, pixel)
		}
	}
	return output
}

func attachmentImageDataURL(mimeType string, data []byte) string {
	return "data:" + mimeType + ";base64," + base64.StdEncoding.EncodeToString(data)
}
''',
)

write(
    "internal/platform/attachment_foundation_test.go",
    r'''package platform

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"strings"
	"testing"
)

func TestDiscoverAuditAttachmentsOnlyUsesEndUserContent(t *testing.T) {
	body := []byte(`{
	  "instructions":{"type":"input_file","filename":"system.txt","file_data":"c3lzdGVt"},
	  "messages":[
	    {"role":"developer","content":[{"type":"input_file","filename":"developer.txt","file_data":"ZGV2"}]},
	    {"role":"user","content":[
	      {"type":"input_file","filename":"notes.txt","file_data":"bm90ZXM="},
	      {"type":"image_url","image_url":{"url":"data:image/png;base64,aW1hZ2U="}}
	    ]}
	  ]
	}`)
	items, skipped, err := discoverAuditAttachments(body, 8)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 || len(items) != 2 {
		t.Fatalf("items=%+v skipped=%d", items, skipped)
	}
	if items[0].Name != "notes.txt" || items[1].Source != "inline_data" {
		t.Fatalf("unexpected discovery: %+v", items)
	}
}

func TestDecodeInlineAttachmentDataLimit(t *testing.T) {
	value := "data:text/plain;base64," + base64.StdEncoding.EncodeToString([]byte("hello"))
	mimeType, data, err := decodeInlineAttachmentData(value, 32)
	if err != nil || mimeType != "text/plain" || string(data) != "hello" {
		t.Fatalf("mime=%q data=%q err=%v", mimeType, data, err)
	}
	if _, _, err := decodeInlineAttachmentData(value, 2); err == nil {
		t.Fatal("expected decoded-byte limit failure")
	}
}

func TestSampleAttachmentTextIncludesHeadTailAndSecuritySignal(t *testing.T) {
	text := "HEAD-MARKER\n" + strings.Repeat("normal filler line\n", 2000) +
		"steal credentials with keylogger SECURITY-MARKER\n" + strings.Repeat("tail filler\n", 2000) + "TAIL-MARKER"
	segments, ranges, sampled := sampleAttachmentText(text, 32*1024, 8*1024)
	if !sampled || len(ranges) < 3 || len(segments) < 3 {
		t.Fatalf("sampled=%v ranges=%+v segments=%d", sampled, ranges, len(segments))
	}
	combined := ""
	for _, segment := range segments {
		combined += segment.Text
	}
	for _, marker := range []string{"HEAD-MARKER", "SECURITY-MARKER", "TAIL-MARKER"} {
		if !strings.Contains(combined, marker) {
			t.Fatalf("sample is missing %s", marker)
		}
	}
}

func TestExtractDOCXText(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	file, err := writer.Create("word/document.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte(`<w:document xmlns:w="urn:w"><w:body><w:p><w:r><w:t>Hello attachment</w:t></w:r></w:p></w:body></w:document>`))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	text, method, _, err := extractAttachmentText(attachmentMaterial{Name: "test.docx", MIMEType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", Kind: attachmentKindDocument, Data: archive.Bytes()}, 64*1024)
	if err != nil || method != "docx_xml" || !strings.Contains(text, "Hello attachment") {
		t.Fatalf("text=%q method=%q err=%v", text, method, err)
	}
}

func TestPrepareAttachmentImageDownscales(t *testing.T) {
	imageValue := image.NewRGBA(image.Rect(0, 0, 1000, 1000))
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, imageValue); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareAttachmentImage(attachmentMaterial{MIMEType: "image/png", Data: encoded.Bytes()}, 16*1024, 200000)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(prepared.URL, "data:image/") || prepared.OutputWidth*prepared.OutputHeight > 200000 {
		t.Fatalf("unexpected prepared image: %+v", prepared)
	}
}

func TestExpandZIPAttachmentCreatesIndividualChildren(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for _, name := range []string{"one.txt", "folder/two.txt"} {
		file, _ := writer.Create(name)
		_, _ = file.Write([]byte("safe text"))
	}
	_ = writer.Close()
	material := attachmentMaterial{
		Candidate: attachmentCandidate{Index: 1, Depth: 0},
		Name:      "bundle.zip",
		MIMEType: "application/zip",
		Kind:      attachmentKindArchive,
		Data:      archive.Bytes(),
	}
	children, err := expandArchiveAttachment(material, 8, 1024*1024, 2)
	if err != nil || len(children) != 2 {
		t.Fatalf("children=%+v err=%v", children, err)
	}
	if children[0].ParentIndex != 1 || !strings.Contains(children[1].Name, "bundle.zip::") {
		t.Fatalf("unexpected children: %+v", children)
	}
}
''',
)

# Config surface.
replace_once(
    "internal/platform/config.go",
    '''\tAuditMaxChunks                 int
\tSSELineMaxBytes                int
''',
    '''\tAuditMaxChunks                 int
\tAttachmentAuditEnabled         bool
\tAttachmentMaxCount             int
\tAttachmentFetchMaxBytes        int64
\tAttachmentTotalMaxBytes        int64
\tAttachmentExtractMaxBytes      int
\tAttachmentSampleMaxBytes       int
\tAttachmentSegmentBytes         int
\tAttachmentImageMaxBytes        int
\tAttachmentImageMaxPixels       int64
\tAttachmentPerRequestConcurrency int
\tAttachmentGlobalConcurrency    int
\tAttachmentFetchTimeout         time.Duration
\tAttachmentArchiveMaxEntries    int
\tAttachmentArchiveMaxDepth      int
\tAttachmentArchiveMaxBytes      int64
\tAttachmentAllowRemoteURLs      bool
\tAttachmentAllowPrivateURLs     bool
\tSSELineMaxBytes                int
''',
    "config attachment fields",
)
replace_once(
    "internal/platform/config.go",
    '''\t\tAuditMaxChunks:                 envInt("AUDIT_MAX_CHUNKS", 256),
\t\tSSELineMaxBytes:                envInt("SSE_LINE_MAX_BYTES", 1024*1024),
''',
    '''\t\tAuditMaxChunks:                  envInt("AUDIT_MAX_CHUNKS", 256),
\t\tAttachmentAuditEnabled:          envBool("ATTACHMENT_AUDIT_ENABLED", true),
\t\tAttachmentMaxCount:              envInt("ATTACHMENT_MAX_COUNT", 16),
\t\tAttachmentFetchMaxBytes:         int64(envInt("ATTACHMENT_FETCH_MAX_BYTES", 64*1024*1024)),
\t\tAttachmentTotalMaxBytes:         int64(envInt("ATTACHMENT_TOTAL_MAX_BYTES", 128*1024*1024)),
\t\tAttachmentExtractMaxBytes:       envInt("ATTACHMENT_EXTRACT_MAX_BYTES", 32*1024*1024),
\t\tAttachmentSampleMaxBytes:        envInt("ATTACHMENT_SAMPLE_MAX_BYTES", 1024*1024),
\t\tAttachmentSegmentBytes:          envInt("ATTACHMENT_SEGMENT_BYTES", 192*1024),
\t\tAttachmentImageMaxBytes:         envInt("ATTACHMENT_IMAGE_MAX_BYTES", 8*1024*1024),
\t\tAttachmentImageMaxPixels:        int64(envInt("ATTACHMENT_IMAGE_MAX_PIXELS", 20*1000*1000)),
\t\tAttachmentPerRequestConcurrency: envInt("ATTACHMENT_PER_REQUEST_CONCURRENCY", 2),
\t\tAttachmentGlobalConcurrency:     envInt("ATTACHMENT_GLOBAL_CONCURRENCY", 16),
\t\tAttachmentFetchTimeout:          envDuration("ATTACHMENT_FETCH_TIMEOUT", 15*time.Second),
\t\tAttachmentArchiveMaxEntries:     envInt("ATTACHMENT_ARCHIVE_MAX_ENTRIES", 128),
\t\tAttachmentArchiveMaxDepth:       envInt("ATTACHMENT_ARCHIVE_MAX_DEPTH", 2),
\t\tAttachmentArchiveMaxBytes:       int64(envInt("ATTACHMENT_ARCHIVE_MAX_BYTES", 128*1024*1024)),
\t\tAttachmentAllowRemoteURLs:       envBool("ATTACHMENT_ALLOW_REMOTE_URLS", true),
\t\tAttachmentAllowPrivateURLs:      envBool("ATTACHMENT_ALLOW_PRIVATE_URLS", false),
\t\tSSELineMaxBytes:                 envInt("SSE_LINE_MAX_BYTES", 1024*1024),
''',
    "config attachment defaults",
)
replace_once(
    "internal/platform/config.go",
    '''\tif c.AuditMaxChunks < 2 || c.AuditMaxChunks > 256 {
\t\tproblems = append(problems, "AUDIT_MAX_CHUNKS must be between 2 and 256")
\t}
\tif c.SSELineMaxBytes < 64*1024 || c.SSELineMaxBytes > 8*1024*1024 {
''',
    '''\tif c.AuditMaxChunks < 2 || c.AuditMaxChunks > 256 {
\t\tproblems = append(problems, "AUDIT_MAX_CHUNKS must be between 2 and 256")
\t}
\tif c.AttachmentMaxCount < 1 || c.AttachmentMaxCount > 128 {
\t\tproblems = append(problems, "ATTACHMENT_MAX_COUNT must be between 1 and 128")
\t}
\tif c.AttachmentFetchMaxBytes < 64*1024 || c.AttachmentFetchMaxBytes > 256*1024*1024 {
\t\tproblems = append(problems, "ATTACHMENT_FETCH_MAX_BYTES must be between 64 KiB and 256 MiB")
\t}
\tif c.AttachmentTotalMaxBytes < c.AttachmentFetchMaxBytes || c.AttachmentTotalMaxBytes > 1024*1024*1024 {
\t\tproblems = append(problems, "ATTACHMENT_TOTAL_MAX_BYTES must be at least ATTACHMENT_FETCH_MAX_BYTES and at most 1 GiB")
\t}
\tif c.AttachmentExtractMaxBytes < 64*1024 || int64(c.AttachmentExtractMaxBytes) > c.AttachmentFetchMaxBytes {
\t\tproblems = append(problems, "ATTACHMENT_EXTRACT_MAX_BYTES must be between 64 KiB and ATTACHMENT_FETCH_MAX_BYTES")
\t}
\tif c.AttachmentSampleMaxBytes < 16*1024 || c.AttachmentSampleMaxBytes > c.AttachmentExtractMaxBytes {
\t\tproblems = append(problems, "ATTACHMENT_SAMPLE_MAX_BYTES must be between 16 KiB and ATTACHMENT_EXTRACT_MAX_BYTES")
\t}
\tif c.AttachmentSegmentBytes < 4096 || c.AttachmentSegmentBytes > c.AttachmentSampleMaxBytes {
\t\tproblems = append(problems, "ATTACHMENT_SEGMENT_BYTES must be between 4 KiB and ATTACHMENT_SAMPLE_MAX_BYTES")
\t}
\tif c.AttachmentImageMaxBytes < 64*1024 || int64(c.AttachmentImageMaxBytes) > c.AttachmentFetchMaxBytes {
\t\tproblems = append(problems, "ATTACHMENT_IMAGE_MAX_BYTES must be between 64 KiB and ATTACHMENT_FETCH_MAX_BYTES")
\t}
\tif c.AttachmentImageMaxPixels < 1024*1024 || c.AttachmentImageMaxPixels > 100*1000*1000 {
\t\tproblems = append(problems, "ATTACHMENT_IMAGE_MAX_PIXELS must be between 1,048,576 and 100,000,000")
\t}
\tif c.AttachmentPerRequestConcurrency < 1 || c.AttachmentPerRequestConcurrency > 16 {
\t\tproblems = append(problems, "ATTACHMENT_PER_REQUEST_CONCURRENCY must be between 1 and 16")
\t}
\tif c.AttachmentGlobalConcurrency < c.AttachmentPerRequestConcurrency || c.AttachmentGlobalConcurrency > 256 {
\t\tproblems = append(problems, "ATTACHMENT_GLOBAL_CONCURRENCY must be at least ATTACHMENT_PER_REQUEST_CONCURRENCY and at most 256")
\t}
\tif c.AttachmentFetchTimeout < time.Second || c.AttachmentFetchTimeout > 2*time.Minute {
\t\tproblems = append(problems, "ATTACHMENT_FETCH_TIMEOUT must be between 1s and 2m")
\t}
\tif c.AttachmentArchiveMaxEntries < 1 || c.AttachmentArchiveMaxEntries > 2000 {
\t\tproblems = append(problems, "ATTACHMENT_ARCHIVE_MAX_ENTRIES must be between 1 and 2000")
\t}
\tif c.AttachmentArchiveMaxDepth < 0 || c.AttachmentArchiveMaxDepth > 5 {
\t\tproblems = append(problems, "ATTACHMENT_ARCHIVE_MAX_DEPTH must be between 0 and 5")
\t}
\tif c.AttachmentArchiveMaxBytes < 1024*1024 || c.AttachmentArchiveMaxBytes > 1024*1024*1024 {
\t\tproblems = append(problems, "ATTACHMENT_ARCHIVE_MAX_BYTES must be between 1 MiB and 1 GiB")
\t}
\tif strings.EqualFold(c.Environment, "production") && c.AttachmentAllowPrivateURLs && !envBool("ACK_ATTACHMENT_PRIVATE_URL_SSRF_RISK", false) {
\t\tproblems = append(problems, "ACK_ATTACHMENT_PRIVATE_URL_SSRF_RISK=true is required with private attachment URLs in production")
\t}
\tif c.SSELineMaxBytes < 64*1024 || c.SSELineMaxBytes > 8*1024*1024 {
''',
    "config attachment validation",
)

# Environment/deployment defaults.
env_block = '''\n# Image and file audit. Each discovered end-user attachment is processed independently.\nATTACHMENT_AUDIT_ENABLED=true\nATTACHMENT_MAX_COUNT=16\nATTACHMENT_FETCH_MAX_BYTES=67108864\nATTACHMENT_TOTAL_MAX_BYTES=134217728\nATTACHMENT_EXTRACT_MAX_BYTES=33554432\nATTACHMENT_SAMPLE_MAX_BYTES=1048576\nATTACHMENT_SEGMENT_BYTES=196608\nATTACHMENT_IMAGE_MAX_BYTES=8388608\nATTACHMENT_IMAGE_MAX_PIXELS=20000000\nATTACHMENT_PER_REQUEST_CONCURRENCY=2\nATTACHMENT_GLOBAL_CONCURRENCY=16\nATTACHMENT_FETCH_TIMEOUT=15s\nATTACHMENT_ARCHIVE_MAX_ENTRIES=128\nATTACHMENT_ARCHIVE_MAX_DEPTH=2\nATTACHMENT_ARCHIVE_MAX_BYTES=134217728\nATTACHMENT_ALLOW_REMOTE_URLS=true\nATTACHMENT_ALLOW_PRIVATE_URLS=false\nACK_ATTACHMENT_PRIVATE_URL_SSRF_RISK=false\n'''
replace_once(
    ".env.example",
    "AUDIT_MAX_CHUNKS=256\n",
    "AUDIT_MAX_CHUNKS=256\n" + env_block,
    "env attachment defaults",
)

compose_lines = '''      ATTACHMENT_AUDIT_ENABLED: ${ATTACHMENT_AUDIT_ENABLED:-true}\n      ATTACHMENT_MAX_COUNT: ${ATTACHMENT_MAX_COUNT:-16}\n      ATTACHMENT_FETCH_MAX_BYTES: ${ATTACHMENT_FETCH_MAX_BYTES:-67108864}\n      ATTACHMENT_TOTAL_MAX_BYTES: ${ATTACHMENT_TOTAL_MAX_BYTES:-134217728}\n      ATTACHMENT_EXTRACT_MAX_BYTES: ${ATTACHMENT_EXTRACT_MAX_BYTES:-33554432}\n      ATTACHMENT_SAMPLE_MAX_BYTES: ${ATTACHMENT_SAMPLE_MAX_BYTES:-1048576}\n      ATTACHMENT_SEGMENT_BYTES: ${ATTACHMENT_SEGMENT_BYTES:-196608}\n      ATTACHMENT_IMAGE_MAX_BYTES: ${ATTACHMENT_IMAGE_MAX_BYTES:-8388608}\n      ATTACHMENT_IMAGE_MAX_PIXELS: ${ATTACHMENT_IMAGE_MAX_PIXELS:-20000000}\n      ATTACHMENT_PER_REQUEST_CONCURRENCY: ${ATTACHMENT_PER_REQUEST_CONCURRENCY:-2}\n      ATTACHMENT_GLOBAL_CONCURRENCY: ${ATTACHMENT_GLOBAL_CONCURRENCY:-16}\n      ATTACHMENT_FETCH_TIMEOUT: ${ATTACHMENT_FETCH_TIMEOUT:-15s}\n      ATTACHMENT_ARCHIVE_MAX_ENTRIES: ${ATTACHMENT_ARCHIVE_MAX_ENTRIES:-128}\n      ATTACHMENT_ARCHIVE_MAX_DEPTH: ${ATTACHMENT_ARCHIVE_MAX_DEPTH:-2}\n      ATTACHMENT_ARCHIVE_MAX_BYTES: ${ATTACHMENT_ARCHIVE_MAX_BYTES:-134217728}\n      ATTACHMENT_ALLOW_REMOTE_URLS: ${ATTACHMENT_ALLOW_REMOTE_URLS:-true}\n      ATTACHMENT_ALLOW_PRIVATE_URLS: ${ATTACHMENT_ALLOW_PRIVATE_URLS:-false}\n      ACK_ATTACHMENT_PRIVATE_URL_SSRF_RISK: ${ACK_ATTACHMENT_PRIVATE_URL_SSRF_RISK:-false}\n'''
replace_once(
    "docker-compose.yml",
    "      AUDIT_MAX_CHUNKS: ${AUDIT_MAX_CHUNKS:-256}\n",
    "      AUDIT_MAX_CHUNKS: ${AUDIT_MAX_CHUNKS:-256}\n" + compose_lines,
    "compose attachment defaults",
)

k8s_lines = '''  ATTACHMENT_AUDIT_ENABLED: "true"\n  ATTACHMENT_MAX_COUNT: "16"\n  ATTACHMENT_FETCH_MAX_BYTES: "67108864"\n  ATTACHMENT_TOTAL_MAX_BYTES: "134217728"\n  ATTACHMENT_EXTRACT_MAX_BYTES: "33554432"\n  ATTACHMENT_SAMPLE_MAX_BYTES: "1048576"\n  ATTACHMENT_SEGMENT_BYTES: "196608"\n  ATTACHMENT_IMAGE_MAX_BYTES: "8388608"\n  ATTACHMENT_IMAGE_MAX_PIXELS: "20000000"\n  ATTACHMENT_PER_REQUEST_CONCURRENCY: "2"\n  ATTACHMENT_GLOBAL_CONCURRENCY: "16"\n  ATTACHMENT_FETCH_TIMEOUT: 15s\n  ATTACHMENT_ARCHIVE_MAX_ENTRIES: "128"\n  ATTACHMENT_ARCHIVE_MAX_DEPTH: "2"\n  ATTACHMENT_ARCHIVE_MAX_BYTES: "134217728"\n  ATTACHMENT_ALLOW_REMOTE_URLS: "true"\n  ATTACHMENT_ALLOW_PRIVATE_URLS: "false"\n  ACK_ATTACHMENT_PRIVATE_URL_SSRF_RISK: "false"\n'''
replace_once(
    "deploy/kubernetes.yaml",
    '  AUDIT_MAX_CHUNKS: "256"\n',
    '  AUDIT_MAX_CHUNKS: "256"\n' + k8s_lines,
    "k8s attachment defaults",
)

replace_once(
    "scripts/init-env.sh",
    '''    "AUDIT_MAX_CHUNKS": "256",
}
''',
    '''    "AUDIT_MAX_CHUNKS": "256",
    "ATTACHMENT_AUDIT_ENABLED": "true",
    "ATTACHMENT_MAX_COUNT": "16",
    "ATTACHMENT_FETCH_MAX_BYTES": "67108864",
    "ATTACHMENT_TOTAL_MAX_BYTES": "134217728",
    "ATTACHMENT_EXTRACT_MAX_BYTES": "33554432",
    "ATTACHMENT_SAMPLE_MAX_BYTES": "1048576",
    "ATTACHMENT_SEGMENT_BYTES": "196608",
    "ATTACHMENT_IMAGE_MAX_BYTES": "8388608",
    "ATTACHMENT_IMAGE_MAX_PIXELS": "20000000",
    "ATTACHMENT_PER_REQUEST_CONCURRENCY": "2",
    "ATTACHMENT_GLOBAL_CONCURRENCY": "16",
    "ATTACHMENT_FETCH_TIMEOUT": "15s",
    "ATTACHMENT_ARCHIVE_MAX_ENTRIES": "128",
    "ATTACHMENT_ARCHIVE_MAX_DEPTH": "2",
    "ATTACHMENT_ARCHIVE_MAX_BYTES": "134217728",
    "ATTACHMENT_ALLOW_REMOTE_URLS": "true",
    "ATTACHMENT_ALLOW_PRIVATE_URLS": "false",
    "ACK_ATTACHMENT_PRIVATE_URL_SSRF_RISK": "false",
}
''',
    "init env attachment defaults",
)

print("attachment audit foundation applied")
