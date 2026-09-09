package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStrictCyberLegacyModelHitFixtures(t *testing.T) {
	for _, text := range []string{
		"为并行 MCP 提供方补齐事件重放管线并对称唤醒；不同子会话使用不同 cardId。",
		"调查 rootcanal 地址持久化。\n- 排查 Docker 主机 devices cgroup 的输入设备权限。",
	} {
		w := httptest.NewRecorder()
		if !mockStrictCyberVerification(w, chatRequest{}, text) {
			t.Fatal("model-hit fixture was not handled")
		}
		var result struct {
			Choices []struct {
				Message struct{ Content string }
			}
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || len(result.Choices) != 1 {
			t.Fatalf("invalid mock response: %v", err)
		}
		var verdict struct{ Decision, Evidence string }
		if err := json.Unmarshal([]byte(result.Choices[0].Message.Content), &verdict); err != nil || verdict.Decision != "block" || !strings.Contains(text, verdict.Evidence) || verdict.Evidence == "" {
			t.Fatalf("invalid fixture verdict: %+v / %v", verdict, err)
		}
	}
	for _, normal := range []string{"Replay ordinary application events", "Persist a UI preference", "JSON payload unit tests"} {
		if mockStrictCyberVerification(httptest.NewRecorder(), chatRequest{}, normal) {
			t.Fatal("fixture must not become a general homonym classifier")
		}
	}
}
