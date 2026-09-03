package platform

const (
	defaultRequestHardMaxBytes             int64 = 64 * 1024 * 1024
	maximumConfigurableRequestHardMaxBytes int64 = 256 * 1024 * 1024
)

type requestBodyLimitPolicy struct {
	Mode                 string
	EffectiveLimitBytes  int64
	HardLimitBytes       int64
	ConfiguredLimitBytes int64
}

// resolveRequestBodyLimit implements automatic actual-size admission. When
// REQUEST_MAX_BYTES=0 and Content-Length is known, the gateway accepts that
// exact size as long as it is within REQUEST_HARD_MAX_BYTES. Unknown-length
// bodies are allowed up to the hard ceiling. A positive REQUEST_MAX_BYTES keeps
// the old explicit soft-limit behavior for operators who require it.
func resolveRequestBodyLimit(configuredLimit int64, hardLimit int64, contentLength int64) requestBodyLimitPolicy {
	if hardLimit <= 0 {
		hardLimit = defaultRequestHardMaxBytes
	}
	if configuredLimit > 0 {
		if configuredLimit > hardLimit {
			configuredLimit = hardLimit
		}
		return requestBodyLimitPolicy{
			Mode:                 "configured",
			EffectiveLimitBytes:  configuredLimit,
			HardLimitBytes:       hardLimit,
			ConfiguredLimitBytes: configuredLimit,
		}
	}
	if contentLength >= 0 && contentLength <= hardLimit {
		effective := contentLength
		if effective < 1 {
			effective = 1
		}
		return requestBodyLimitPolicy{
			Mode:                "auto_actual_size",
			EffectiveLimitBytes: effective,
			HardLimitBytes:      hardLimit,
		}
	}
	return requestBodyLimitPolicy{
		Mode:                "auto_hard_ceiling",
		EffectiveLimitBytes: hardLimit,
		HardLimitBytes:      hardLimit,
	}
}

func (policy requestBodyLimitPolicy) ExceedsKnownLength(contentLength int64) bool {
	return contentLength >= 0 && contentLength > policy.EffectiveLimitBytes
}

func requestBodyNeedsLargeSlot(contentLength int64, threshold int64) bool {
	return contentLength < 0 || contentLength > threshold
}

func recommendedRequestMaxBytes(requestBytes int64, hardLimit int64) int64 {
	if hardLimit <= 0 {
		hardLimit = defaultRequestHardMaxBytes
	}
	if requestBytes <= 0 || requestBytes > hardLimit {
		return 0
	}
	return requestBytes
}
