package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
)

func TestV15MockCorpusMatchesGatewayRegression(t *testing.T) {
	b, err := os.ReadFile("../../internal/platform/testdata/script-development-v15.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID       string `json:"id"`
		Quote    string `json:"quote"`
		Code     string `json:"risk_code"`
		Category string `json:"category"`
	}
	if err = json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != len(v15ScriptQuotes) {
		t.Fatal("mock/corpus drift")
	}
	for _, c := range cases {
		got, ok := v15ScriptQuotes[c.ID]
		if !ok || got.Quote != c.Quote || got.Code != c.Code || got.Category != c.Category {
			t.Fatalf("mock/corpus drift: %s", c.ID)
		}
	}
	rec := httptest.NewRecorder()
	if mockScriptV15(rec, chatRequest{Model: "a-real-model"}) || rec.Body.Len() != 0 {
		t.Fatal("fixture intercepted an unrelated model")
	}
	rec = httptest.NewRecorder()
	if !mockScriptV15(rec, chatRequest{Model: "qwen-v15-script"}) || rec.Code != 400 {
		t.Fatal("fixture omitted Qwen parameter check")
	}
}
