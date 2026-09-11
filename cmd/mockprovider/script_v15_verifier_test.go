package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestV15VerifierFaultSurvivesChunkChanges(t *testing.T) {
	for _, mode := range []string{"invalid", "unavailable", "context"} {
		for _, text := range []string{"normal request", "x", strings.Repeat("ordinary line\n", 400)} {
			for _, second := range []bool{false, true} {
				r := chatRequest{Model: "qwen-v15-verifier-" + mode, MaxTokens: 256,
					ChatTemplateKwargs: map[string]any{"enable_thinking": false, "preserve_thinking": false}}
				control := "Classify the complete text."
				if second {
					control += " CYBER DENY SECOND PASS"
				}
				r.Messages = []struct {
					Role    string `json:"role"`
					Content any    `json:"content"`
				}{{Role: "system", Content: control}, {Role: "user", Content: text}}
				w := httptest.NewRecorder()
				if !mockScriptV15(w, r) {
					t.Fatal("dedicated fixture not handled")
				}
				wantStatus := 200
				if second && mode == "unavailable" {
					wantStatus = 503
				} else if second && mode == "context" {
					wantStatus = 400
				}
				if w.Code != wantStatus {
					t.Fatalf("%s second=%v: status %d: %s", mode, second, w.Code, w.Body.String())
				}
				var response struct {
					Choices []struct {
						Message struct{ Content string } `json:"message"`
					} `json:"choices"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if !second {
					if len(response.Choices) != 1 || !strings.Contains(response.Choices[0].Message.Content, `"decision":"allow"`) {
						t.Fatal("primary must still allow ordinary text")
					}
				} else if mode == "invalid" && (len(response.Choices) != 1 || response.Choices[0].Message.Content != "not-json") {
					t.Fatal("invalid verifier became valid after re-chunking")
				}
			}
		}
	}
	w := httptest.NewRecorder()
	if mockScriptV15Verifier(w, chatRequest{Model: "qwen-v15-verifier-unrecognized"}) || w.Body.Len() != 0 {
		t.Fatal("fixture captured another model")
	}
}
