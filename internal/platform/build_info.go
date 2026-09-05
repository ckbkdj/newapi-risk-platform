package platform

import (
	"crypto/rand"
	"encoding/hex"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
)

const auditEngineRevision = "output-resilience-fusion.v1"

type BuildInformation struct {
	Version        string `json:"version"`
	Commit         string `json:"commit"`
	Instance       string `json:"instance"`
	GoVersion      string `json:"go_version"`
	AuditEngine    string `json:"audit_engine"`
	InputContract  string `json:"input_contract"`
	OutputContract string `json:"output_contract"`
}

var processBuild atomic.Value
var processInstance = func() string {
	var value [12]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(value[:])
}()

func SetBuildInformation(version, commit string) {
	if commit == "" || commit == "unknown" {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, setting := range info.Settings {
				if setting.Key == "vcs.revision" {
					commit = setting.Value
				}
			}
		}
	}
	processBuild.Store(BuildInformation{Version: boundedBuildValue(version), Commit: boundedBuildValue(commit), Instance: processInstance, GoVersion: runtime.Version(), AuditEngine: auditEngineRevision, InputContract: auditInputContractVersion, OutputContract: auditOutputContractVersion})
}
func boundedBuildValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 100 {
		return "unknown"
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._+-", c)) {
			return "unknown"
		}
	}
	return value
}
func CurrentBuildInformation() BuildInformation {
	if value := processBuild.Load(); value != nil {
		return value.(BuildInformation)
	}
	return BuildInformation{Version: "dev", Commit: "unknown", Instance: processInstance, GoVersion: runtime.Version(), AuditEngine: auditEngineRevision, InputContract: auditInputContractVersion, OutputContract: auditOutputContractVersion}
}
