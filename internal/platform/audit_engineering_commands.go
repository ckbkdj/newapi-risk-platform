package platform

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Grammar gates for a fresh evidence check, NEVER authorization to execute or
// forward. Every command in a compound must qualify; unknown options,
// substitutions, remote CIM sessions, writes and executable pipelines do not.
var engineeringPSHead = regexp.MustCompile(`(?i)^(?:Get-NetTCPConnection(?:[ \t]+-(?:State[ \t]+(?:Listen|Established|Bound|TimeWait|CloseWait)|(?:LocalPort|OwningProcess)[ \t]+[0-9]+(?:,[0-9]+)*|ErrorAction[ \t]+SilentlyContinue))*|Get-NetUDPEndpoint(?:[ \t]+-(?:(?:LocalPort|OwningProcess)[ \t]+[0-9]+(?:,[0-9]+)*|ErrorAction[ \t]+SilentlyContinue))*|Get-Process(?:[ \t]+-(?:Id[ \t]+[0-9]+(?:,[0-9]+)*|Name[ \t]+[A-Za-z0-9_.-]+|ErrorAction[ \t]+SilentlyContinue))*|Get-Date(?:[ \t]+-Format[ \t]+"[A-Za-z0-9 :/._-]+")?)$`)
var engineeringPSFilter = regexp.MustCompile(`(?i)^Where-Object[ \t]+\{[ \t]*\$_\.(?:LocalPort|OwningProcess|State|ProcessName)[ \t]+(?:-in[ \t]+@\([ \t]*[0-9]+(?:[ \t]*,[ \t]*[0-9]+)*[ \t]*\)|-eq[ \t]+(?:[0-9]+|"[A-Za-z0-9_.-]+"|'[A-Za-z0-9_.-]+'))[ \t]*\}$`)
var engineeringPSDisplay = regexp.MustCompile(`(?i)^(?:(?:Select-Object|Sort-Object|Format-List)[ \t]+(?:-Property[ \t]+)?[A-Za-z][A-Za-z0-9]*(?:[ \t]*,[ \t]*[A-Za-z][A-Za-z0-9]*)*|Format-Table(?:[ \t]+-AutoSize)?|Out-String)$`)
var engineeringUnixStatus = regexp.MustCompile(`^(?:df(?:[ \t]+-[hHikPTa]+)*|mount|uname(?:[ \t]+-[armnsv]+)*|free(?:[ \t]+-[hmgk]+)*|cat[ \t]+/proc/(?:mounts|meminfo|version)|getenforce|id|ps[ \t]+(?:-[A-Za-z]+|aux|[0-9]+)(?:[ \t]+(?:-[A-Za-z]+|[0-9]+))*)$`)
var engineeringADBPrefix = regexp.MustCompile(`^adb(?:[ \t]+-s[ \t]+[A-Za-z0-9_.:-]+)?[ \t]+`)
var engineeringAndroidStatus = regexp.MustCompile(`^(?:getprop(?:[ \t]+[A-Za-z0-9_.-]+)?|getenforce|id|dumpsys(?:[ \t]+(?:-l|(?:meminfo|cpuinfo|input|window|activity|package|connectivity|telephony\.registry|display|SurfaceFlinger|gfxinfo|battery)(?:[ \t]+(?:[A-Za-z][A-Za-z0-9_.:]*|-h|--help|--proto))?))|pm[ \t]+(?:list[ \t]+packages(?:[ \t]+-[fs3duie]+)*|path[ \t]+[A-Za-z][A-Za-z0-9_.]+)|settings[ \t]+get[ \t]+(?:global|system|secure)[ \t]+[A-Za-z0-9_.]+|logcat[ \t]+-d(?:[ \t]+(?:-b[ \t]+(?:main|system|crash|radio|events|all)|-v[ \t]+(?:threadtime|time|brief|long|raw)|-s[ \t]+[A-Za-z0-9_.*:-]+))*)$`)
var androidMutationArgument = regexp.MustCompile(`(?i)\b(?:set|reset|unplug|write|put|delete|disable|enable|clear|stop|start|force-stop|kill|call)\b`)
var engineeringBuild = regexp.MustCompile(`^(?:(?:source|\.)[ \t]+build/envsetup\.sh|lunch[ \t]+[A-Za-z0-9_.-]+|(?:m|mm|mmm)(?:[ \t]+(?:-j[0-9]+|[A-Za-z0-9_./:-]+))*|(?:\./)?gradlew(?:[ \t]+(?::?[A-Za-z0-9_.:-]*(?:assembleDebug|assembleRelease|compileDebugJavaWithJavac|testDebugUnitTest|lintDebug)|--stacktrace|--info|-q))+|repo[ \t]+(?:status|diff)|git[ \t]+status(?:[ \t]+--short)?)$`)

func engineeringCommandShape(cmd string) bool {
	if len(cmd) == 0 || len(cmd) > 8192 || strings.ContainsAny(cmd, "\r\n`<>\\") {
		return false
	}
	// A text search has its own quoted-regex grammar and can legitimately contain
	// backslashes or pipes INSIDE its pattern. Never promote shell suffixes.
	return engineeringCompoundShape(cmd)
}
func engineeringCompoundShape(cmd string) bool {
	pieces := strings.Split(cmd, ";")
	if len(pieces) > 16 {
		return false
	}
	for _, p := range pieces {
		p = strings.TrimSpace(p)
		if p == "" {
			return false
		}
		pipeline := strings.Split(p, "|")
		if len(pipeline) > 8 {
			return false
		}
		head := strings.TrimSpace(pipeline[0])
		if engineeringPSHead.MatchString(head) {
			for _, part := range pipeline[1:] {
				s := strings.TrimSpace(part)
				if !engineeringPSFilter.MatchString(s) && !engineeringPSDisplay.MatchString(s) {
					return false
				}
			}
			continue
		}
		if len(pipeline) != 1 || strings.ContainsAny(p, "$&{}()") {
			return false
		}
		if engineeringUnixStatus.MatchString(p) || (engineeringBuild.MatchString(p) && !engineeringUnsafeBuildTarget.MatchString(p)) {
			continue
		}
		if engineeringADBPrefix.MatchString(p) {
			tail := engineeringADBPrefix.ReplaceAllString(p, "")
			if tail == "devices" || tail == "devices -l" || tail == "version" {
				continue
			}
			tail = strings.TrimPrefix(tail, "shell ")
			if !sensitiveSearchEvidence.MatchString(tail) && !androidMutationArgument.MatchString(tail) && engineeringAndroidStatus.MatchString(tail) {
				continue
			}
		}
		return false
	}
	return true
}

func ordinaryEngineeringCommand(cmd string) bool {
	return localStatusCommand.MatchString(strings.TrimSpace(cmd)) || readOnlySearchEvidence(strings.TrimSpace(cmd)) || engineeringCommandShape(strings.TrimSpace(cmd))
}

// Locate the complete containing literal, not just the model's short prefix.
// All occurrences are checked by observationalAuditEvidence; a safe occurrence
// cannot bless a dangerous occurrence later in the source.
func engineeringEvidenceAt(source string, start, end int) bool {
	if start < 0 || end <= start || end > len(source) {
		return false
	}
	a := strings.LastIndex(source[:start], "\n") + 1
	b := len(source)
	if n := strings.IndexByte(source[end:], '\n'); n >= 0 {
		b = end + n
	}
	if b-a > 8192 {
		return false
	}
	line := source[a:b]
	trimmed := strings.TrimSpace(line)
	if ordinaryEngineeringCommand(trimmed) {
		return true
	}
	// The tool projection prints string scalars with literal decoded newlines.
	// A complete one-line scalar retains its outer quotes and its complete body.
	if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' && ordinaryEngineeringCommand(trimmed[1:len(trimmed)-1]) {
		return true
	}
	for _, m := range localCommandLiteral.FindAllStringSubmatchIndex(line, 32) {
		if a+m[2]+1 > start || a+m[3]-1 < end {
			continue
		}
		suffix := strings.TrimSpace(line[m[3]:])
		if suffix != "" && suffix[0] != ',' && suffix[0] != '}' {
			continue
		}
		var cmd string
		if json.Unmarshal([]byte(line[m[2]:m[3]]), &cmd) == nil && ordinaryEngineeringCommand(cmd) {
			return true
		}
	}
	return false
}

// A narrow unstructured-output fallback: the n belongs to an escaped newline,
// followed by an entire numeric filesystem row. This only rejects a spurious
// rule candidate; it does not decode arbitrary scripts or allow the request.
var escapedMountMapRow = regexp.MustCompile(`^nmap[ \t]+auto_home[ \t]+[0-9.]+[A-Za-z]*[ \t]+[0-9.]+[A-Za-z]*[ \t]+[0-9.]+[A-Za-z]*[ \t]+[0-9]+%[ \t]+[0-9.]+[A-Za-z]*[ \t]+[0-9.]+[A-Za-z]*[ \t]+(?:[0-9]+%|-)[ \t]+/[A-Za-z0-9_./ -]+$`)

func escapedMountMapCandidate(source string, ev cyberRuleEvidence) bool {
	if ev.matchedRaw != "nmap" || ev.start < 1 || source[ev.start-1] != '\\' {
		return false
	}
	end := ev.start
	for end < len(source) && end-ev.start <= 2048 && source[end] != '\\' && source[end] != '\n' && source[end] != '\r' && source[end] != '"' {
		end++
	}
	return end-ev.start <= 2048 && escapedMountMapRow.MatchString(strings.TrimSpace(source[ev.start:end]))
}

// Small artifact forms: these demonstrate declarations/status, not a security
// operation. Only the quoted fragment is admitted for one recheck; code around
// it and all task anchors remain audited. No source-file/path allowlist.
var androidBuildDeclaration = regexp.MustCompile(`^[ \t]*(?:(?:TARGET_ARCH|TARGET_ARCH_VARIANT|TARGET_CPU_VARIANT|PRODUCT_PACKAGES|LOCAL_MODULE|LOCAL_SRC_FILES)[ \t]*(?::=|\+=|=)[ \t]*[A-Za-z0-9_./ :+-]+|(?:buildConfig|viewBinding)[ \t]*(?:=[ \t]*)?(?:true|false)|android\.buildFeatures\.buildConfig[ \t]+true)[ \t]*$`)
var androidPropertyRecord = regexp.MustCompile(`^\[(?:ro\.build\.(?:type|version\.release|version\.sdk)|ro\.product\.(?:model|device)|ro\.hardware)\]:[ \t]*\[[A-Za-z0-9_ .-]+\]$`)
var androidDiagnosticQuote = regexp.MustCompile(`^(?:avc:[ \t]+denied|cannot find symbol|NDK version mismatch|defaultConfig contains custom BuildConfig fields)$`)
var engineeringUnsafeBuildTarget = regexp.MustCompile(`(?i)\b(?:nmap|masscan|sqlmap|frida|xposed|lsposed|magisk|exploit|bypass|rootkit)\b`)

func androidArtifactEvidenceAt(source string, start, end int) bool {
	if start < 0 || end <= start || end > len(source) {
		return false
	}
	a := strings.LastIndex(source[:start], "\n") + 1
	b := len(source)
	if n := strings.IndexByte(source[end:], '\n'); n >= 0 {
		b = end + n
	}
	if b-a > 2048 {
		return false
	}
	line := strings.TrimSpace(source[a:b])
	quote := source[start:end]
	if engineeringUnsafeBuildTarget.MatchString(line) || devExplicitOperation.MatchString(line) {
		return false
	}
	return androidBuildDeclaration.MatchString(line) || androidPropertyRecord.MatchString(line) || androidDiagnosticQuote.MatchString(quote)
}
