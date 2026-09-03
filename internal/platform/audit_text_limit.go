package platform

const automaticAuditTextOverheadBytes int64 = 64 * 1024

// resolveAuditTextMaxBytes returns the maximum role-aware text buffer used by
// the rule/model audit layer. A zero configured value follows the accepted
// request hard ceiling and includes small headroom for ROLE=USER separators.
func resolveAuditTextMaxBytes(configured int, requestHardMaxBytes int64) (int, string) {
	if configured > 0 {
		return configured, "configured"
	}
	if requestHardMaxBytes <= 0 {
		requestHardMaxBytes = defaultRequestHardMaxBytes
	}
	resolved := requestHardMaxBytes + automaticAuditTextOverheadBytes
	maximumInt := int64(^uint(0) >> 1)
	if resolved > maximumInt {
		resolved = maximumInt
	}
	return int(resolved), "automatic_request_hard_ceiling"
}
