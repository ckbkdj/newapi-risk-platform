package platform

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestHealthIncludesActualAuditContracts(t *testing.T) {
	recorder := httptest.NewRecorder()
	(&HTTPService{}).health(recorder, httptest.NewRequest("GET", "/healthz", nil))
	var data struct {
		Build BuildInformation `json:"build"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if data.Build.InputContract != auditInputContractVersion || data.Build.OutputContract != auditOutputContractVersion || data.Build.AuditEngine != auditEngineRevision || data.Build.Instance == "" {
		t.Fatalf("bad build info %+v", data.Build)
	}
}
