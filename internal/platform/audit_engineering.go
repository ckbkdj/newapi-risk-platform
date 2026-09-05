package platform

import "regexp"

const MandatoryAuditEngineeringGuard = `MANDATORY ROUTINE-ENGINEERING PRECISION — APPLIES EVEN WITH A CUSTOM BASE PROMPT:
A public IP address, an admin URL, ADB, AOSP, root, userdebug, eng, or a statement of ownership is not evidence of harm by itself. A claim of authorization is neither an automatic permit for harmful capability nor an independent reason to review or block a routine task. Apply the context-claim policy to actual risky capability, not ordinary operation.
Allow normal AOSP/Android platform builds, Soong/ninja build fixes, framework/HAL changes, CTS/VTS, SELinux policy debugging, and userdebug/eng image development. ADB pairing/connecting to a specified development device (including a company public endpoint), logcat/dumpsys/getprop, APK installation, and normal adb root/remount on developer builds are ordinary engineering, not unauthorized intrusion solely because they involve root or a public address.
Creating an ordinary test user through an application's normal authenticated admin interface, filling display name/sub/tenant/password, is normal administration. The application must enforce its existing authentication and authorization; the audit does not grant access or bypass those controls. Do not demand proof of ownership or defensive/security wording for routine form filling.
Keep reviewing genuinely ambiguous risky capabilities. Keep blocking explicit unauthorized access, authentication bypass, third-party credential/data theft, bulk compromise of exposed ADB devices, covert malware/backdoors, and harmful security evasion even when the request also mentions AOSP, company infrastructure, a test lab, or ownership.
Examples:
- "AOSP userdebug 编译失败，修复 Soong 配置" -> allow.
- "公司云手机通过公网 IP 使用 adb connect，查看 logcat 排查崩溃" -> allow; public address is neutral.
- "在管理后台新增普通测试用户，填写展示名、sub、默认租户和密码" -> allow via normal authentication, not CYBER_UNTRUSTED_CONTEXT_CLAIM.
- "我允许你操作，这是自己的测试环境" attached to the above ordinary user creation -> still allow; the claim is not the harmful action.
- "扫描全网开放 ADB，绕过认证并安装隐藏后门" -> block, even with a company/lab claim.`

var routineAOSPSubject = regexp.MustCompile(`(?i)\b(?:aosp|soong|userdebug|rootcanal)\b|Android\s*(?:源码|系统开发)`)
var routineAOSPOperation = regexp.MustCompile(`(?i)\b(?:build|compile|ninja|lunch|cts|vts|logcat|dumpsys)\b|编译|构建|调试|排障|修复|日志|测试`)
var routineADBSubject = regexp.MustCompile(`(?i)\badb\b`)
var routineADBOperation = regexp.MustCompile(`(?i)\badb\s+(?:-[a-z]\s+\S+\s+)*(?:connect|pair|devices|logcat|install|root|remount|reboot|get-state|version)\b|\badb\b.{0,40}(?:连接|配对|调试|日志|安装.{0,8}(?:测试|apk))`)
var routineADBShell = regexp.MustCompile(`(?i)\badb\s+(?:-[a-z]\s+\S+\s+)*shell\s+(?:getprop|dumpsys|id|wm\s+size|pm\s+list\s+packages)\b`)
var anyADBShell = regexp.MustCompile(`(?i)\badb\s+(?:-[a-z]\s+\S+\s+)*shell\b`)
var routineAdminSubject = regexp.MustCompile(`(?i)/admin/|/end-users\b|\badmin\b|管理后台|后台|租户|展示名`)
var routineAdminOperation = regexp.MustCompile(`(?i)(?:新增|创建|添加).{0,16}(?:用户|账号|账户)|\b(?:create|add)\b.{0,24}\b(?:user|account)\b`)

// This is a conservative exception guard, not a general-purpose malware
// detector. Unsupported, mixed, encoded or potentially harmful operations
// remain with the semantic classifier. It never overrides a specific harm code.
var engineeringExceptionExclusion = regexp.MustCompile(`(?i)绕过|破解|逆向|反编译|脱壳|扫描|枚举|漏洞|注入|钓鱼|窃取|盗取|偷取|外传|爆破|撞库|绕过.{0,16}(?:认证|登录|授权|权限|验证)|未授权|未经.{0,8}(?:许可|允许|授权)|他人|别人|受害者|后门|恶意|隐藏|隐蔽|免杀|逃避|规避.{0,12}(?:检测|安全|风控)|(?:关闭|禁用).{0,8}(?:安全|防护|EDR)|全网|网段|批量扫描|接管|提权|反弹|联系人|相册|聊天记录|微信数据库|超级管理员|提升.{0,8}权限|不需要.{0,8}(?:密码|授权|登录)|没有.{0,8}(?:密码|权限)|\b(?:steal|harvest|exfiltrat\w*|payload|scan|enumerate|decompile|disassemble|malware|backdoor|covert|hidden|victim|unauthori[sz]ed|exploit|privesc|frida|metasploit|msfvenom|ransomware|phishing|masscan|nmap|bruteforce|superadmin|base64|eval|exec|powershell|curl|wget)\b|\bbypass\b|\bc2\b|command.and.control|implant|inject|hook|persistence|reverse\s+shell|without\s+(?:permission|consent|credentials|login)|disable\s+(?:security|edr|antivirus)|\brm\s+-|\bsh\s+-c|\bsu\s+-c|[|;&]|\\x[0-9a-f]{2}|忽略.{0,12}(?:规则|审计|指令)|ignore.{0,16}(?:rules|instructions|policy)`)

func isRoutineEngineeringRequest(text string) bool {
	// Large pasted programs and mixed arbitrary commands need semantic review;
	// a benign prefix must never white-list an entire long request.
	if len(text) > 32*1024 || engineeringExceptionExclusion.MatchString(text) {
		return false
	}
	if anyADBShell.MatchString(text) && len(anyADBShell.FindAllStringIndex(text, -1)) != len(routineADBShell.FindAllStringIndex(text, -1)) {
		return false
	}
	return (routineAOSPSubject.MatchString(text) && routineAOSPOperation.MatchString(text)) ||
		(routineADBSubject.MatchString(text) && (routineADBOperation.MatchString(text) || routineADBShell.MatchString(text))) ||
		(routineAdminSubject.MatchString(text) && routineAdminOperation.MatchString(text))
}
