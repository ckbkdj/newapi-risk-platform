package platform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Unwrap only COMPLETE JSON at known tool arguments/output boundaries. This is
// an untrusted textual projection, not a second message parser: role/system/type
// keys inside tool data are retained as data, never honored as control fields.
// Strings get their own lines so JSON escape letters cannot form new words with
// the following text. All keys, scalars and sibling values are retained.
//
// Standard MCP image payloads are the one exception: raw base64 pixels are not
// natural-language evidence and can dominate long-context audits. Preserve the
// image MIME/type, encoded size and digest while compacting only fields that are
// structurally identified as media. Arbitrary opaque/base64 tool strings remain
// unchanged and auditable.
func auditToolJSONView(ctx context.Context, text string, maxBytes int) (string, int, error) {
	var out strings.Builder
	decoded := 0
	write := func(s string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(s) > maxBytes-out.Len() {
			return newAuditModelCallError("audit_capacity_exceeded", 0, "decoded tool data exceeds complete-audit capacity", nil)
		}
		out.WriteString(s)
		return nil
	}
	var render func(any, int, int, string, map[string]any) error
	render = func(v any, depth, wrappers int, key string, parent map[string]any) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > 32 {
			return newAuditModelCallError("serialized_tool_depth", 0, "tool JSON projection depth exceeded", nil)
		}
		switch x := v.(type) {
		case string:
			if compacted, ok := compactToolMediaString(key, parent, x); ok {
				return write(compacted)
			}
			if child, ok := completeToolJSON(ctx, x); ok {
				if wrappers >= 4 {
					return newAuditModelCallError("serialized_tool_depth", 0, "too many nested serialized tool documents", nil)
				}
				decoded++
				return render(child, depth+1, wrappers+1, "", nil)
			}
			if err := write("\""); err != nil {
				return err
			}
			if err := write(x); err != nil {
				return err
			}
			return write("\"")
		case map[string]any:
			if err := write("{\n"); err != nil {
				return err
			}
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if err := write(k + ":\n"); err != nil {
					return err
				}
				if err := render(x[k], depth+1, wrappers, k, x); err != nil {
					return err
				}
				if err := write("\n"); err != nil {
					return err
				}
			}
			return write("}")
		case []any:
			if err := write("[\n"); err != nil {
				return err
			}
			for _, item := range x {
				if err := render(item, depth+1, wrappers, "", nil); err != nil {
					return err
				}
				if err := write("\n"); err != nil {
					return err
				}
			}
			return write("]")
		default:
			b, err := json.Marshal(v)
			if err != nil {
				return newAuditModelCallError("serialized_tool_value", 0, "unsupported tool JSON value", nil)
			}
			return write(string(b))
		}
	}
	value, ok := completeToolJSON(ctx, text)
	if !ok {
		return text, 0, ctx.Err()
	}
	decoded++
	if err := render(value, 0, 1, "", nil); err != nil {
		return "", decoded, err
	}
	return out.String(), decoded, nil
}

func compactToolMediaString(key string, parent map[string]any, value string) (string, bool) {
	if mime, payload, ok := imageDataURI(value); ok {
		return mcpMediaPlaceholder(mime, payload), true
	}
	if parent == nil || len(value) < 256 || !likelyBase64MediaPayload(value) {
		return "", false
	}

	keyClass := normalizeToolMediaKey(key)
	mime := toolMediaMIME(parent)
	kind := strings.ToLower(strings.TrimSpace(toolMapString(parent, "type")))
	explicitImageKey := keyClass == "imagebase64" || keyClass == "base64image" || keyClass == "imagedata" || keyClass == "imagebytes"
	standardMCPData := (keyClass == "data" || keyClass == "base64") && (kind == "image" || strings.HasPrefix(strings.ToLower(mime), "image/"))
	if !explicitImageKey && !standardMCPData {
		return "", false
	}
	if mime == "" {
		mime = "image/unknown"
	}
	return mcpMediaPlaceholder(mime, value), true
}

func imageDataURI(value string) (string, string, bool) {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "data:image/") {
		return "", "", false
	}
	comma := strings.IndexByte(trimmed, ',')
	if comma <= len("data:image/") {
		return "", "", false
	}
	meta := trimmed[:comma]
	metaLower := strings.ToLower(meta)
	if !strings.Contains(metaLower, ";base64") {
		return "", "", false
	}
	semi := strings.IndexByte(meta, ';')
	if semi <= len("data:") {
		return "", "", false
	}
	mime := strings.TrimSpace(meta[len("data:"):semi])
	payload := trimmed[comma+1:]
	if !strings.HasPrefix(strings.ToLower(mime), "image/") || !likelyBase64MediaPayload(payload) {
		return "", "", false
	}
	return mime, payload, true
}

func toolMediaMIME(parent map[string]any) string {
	for _, key := range []string{"mimeType", "mime_type", "mime", "contentType", "content_type"} {
		if value := toolMapString(parent, key); strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "image/") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func toolMapString(values map[string]any, name string) string {
	for key, value := range values {
		if !strings.EqualFold(key, name) {
			continue
		}
		text, _ := value.(string)
		return text
	}
	return ""
}

func normalizeToolMediaKey(key string) string {
	var out strings.Builder
	out.Grow(len(key))
	for _, r := range strings.ToLower(key) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			out.WriteRune(r)
		}
	}
	return out.String()
}

func likelyBase64MediaPayload(value string) bool {
	count := 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/', c == '=', c == '-', c == '_':
			count++
		case c == ' ', c == '\n', c == '\r', c == '\t':
			continue
		default:
			return false
		}
	}
	return count >= 256
}

func mcpMediaPlaceholder(mime, encoded string) string {
	digest := sha256.Sum256([]byte(encoded))
	return fmt.Sprintf("[MCP_MEDIA %s base64_encoded_bytes=%d sha256=%x]", strings.TrimSpace(mime), len(encoded), digest[:8])
}

func completeToolJSON(ctx context.Context, s string) (any, bool) {
	t := strings.TrimSpace(s)
	if len(t) < 2 || (t[0] != '{' && t[0] != '[' && t[0] != '"') {
		return nil, false
	}
	d := json.NewDecoder(auditContextReader{ctx: ctx, reader: bytes.NewReader([]byte(t))})
	d.UseNumber()
	v, err := readAuditJSONValue(d, 0)
	if err != nil {
		return nil, false
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, false
	}
	return v, true
}
