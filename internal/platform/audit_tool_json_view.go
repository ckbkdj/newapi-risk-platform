package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sort"
	"strings"
)

// Unwrap only COMPLETE JSON at known tool arguments/output boundaries. This is
// an untrusted textual projection, not a second message parser: role/system/type
// keys inside tool data are retained as data, never honored as control fields.
// Strings get their own lines so JSON escape letters cannot form new words with
// the following text. All keys, scalars and sibling values are retained.
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
	var render func(any, int, int) error
	render = func(v any, depth, wrappers int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > 32 {
			return newAuditModelCallError("serialized_tool_depth", 0, "tool JSON projection depth exceeded", nil)
		}
		switch x := v.(type) {
		case string:
			if child, ok := completeToolJSON(ctx, x); ok {
				if wrappers >= 4 {
					return newAuditModelCallError("serialized_tool_depth", 0, "too many nested serialized tool documents", nil)
				}
				decoded++
				return render(child, depth+1, wrappers+1)
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
				if err := render(x[k], depth+1, wrappers); err != nil {
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
				if err := render(item, depth+1, wrappers); err != nil {
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
	if err := render(value, 0, 1); err != nil {
		return "", decoded, err
	}
	return out.String(), decoded, nil
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
