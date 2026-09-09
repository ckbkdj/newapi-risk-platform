package platform

import (
	"regexp"
	"strings"
)

// Admission to ONE fresh operation check, never a request allowlist. The same
// full chunk and task anchors are sent again; no matching text is removed.
var adminRiskClass = regexp.MustCompile(`(?i)(credential|exfil|privilege|凭据|密码|外传|提权)`)
var adminExplicitRisk = regexp.MustCompile(`(?i)(\b(?:steal|stolen|exfil\w*|harvest|bypass|public|unapproved|unauthorized|backdoor|exploit\w*|victim|leak\w*)\b|窃取|盗取|绕过|未授权|公开|外传|后门|漏洞|(?:提取|读取|导出).{0,24}(?:密码|凭据|密钥|令牌)|(?:dump|extract|read|export)[\t ]+(?:passwords?|credentials?|tokens?|cookies?|keys?))`)
var adminConnectionLine = regexp.MustCompile(`(?i)(?:\b(?:mysql|postgres|ssh|db)[_-](?:host|port|username|user|password)[\t ]*[:=]|^[\t ]*(?:username|password|账号|用户名|密码)[\t ]*[:=])`)
var adminDatabaseScope = regexp.MustCompile(`(?i)(database|mysql|postgres|数据库|每张表)`)
var adminDatabaseTransfer = regexp.MustCompile(`(?i)(同步|拉取|拉下来|备份|迁移|恢复|覆盖|\b(?:sync\w*|back.?up|restore|migrat\w*|copy|transfer|dump)\b)`)
var adminLoginScope = regexp.MustCompile(`(?i)(\b(?:ssh|sudo)\b|已有.{0,8}权限|提供.{0,8}(?:账号|密码)|(?:provided|supplied).{0,16}(?:password|credentials))`)
var adminLoginAction = regexp.MustCompile(`(?i)(login|log in|deploy|docker|sudo|登录|连接|部署|启动|切换|切到)`)

func administrativeAuditEvidence(d AuditDecision, quote, source string) bool {
	if !adminRiskClass.MatchString(d.RiskCode+" "+d.Category) || len(quote) < 4 || len(quote) > 4096 {
		return false
	}
	offset, found := 0, false
	for count := 0; count < 32; count++ {
		rel := strings.Index(source[offset:], quote)
		if rel < 0 {
			return found
		}
		start := offset + rel
		end := start + len(quote)
		a := strings.LastIndex(source[:start], "\n") + 1
		b := len(source)
		if n := strings.IndexByte(source[end:], '\n'); n >= 0 {
			b = end + n
		}
		if b-a > 8192 {
			return false
		}
		line := source[a:b]
		// A narrow quote must not hide a prohibited action in its containing line.
		// Other lines still remain in the request and are checked by the model.
		if adminExplicitRisk.MatchString(line) {
			return false
		}
		connection := adminConnectionLine.MatchString(line)
		database := adminDatabaseScope.MatchString(line) && adminDatabaseTransfer.MatchString(line)
		login := adminLoginScope.MatchString(line) && adminLoginAction.MatchString(line)
		if !connection && !database && !login {
			return false
		}
		found = true
		offset = start + 1
	}
	return false // ambiguous/excessive occurrences fail closed, not first-match wins
}
