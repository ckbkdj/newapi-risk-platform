package platform

const (
	minimumRecommendedRequestMaxBytes int64 = 8 * 1024 * 1024
	maximumSupportedRequestMaxBytes   int64 = 64 * 1024 * 1024
)

// recommendedRequestMaxBytes returns a power-of-two limit that can contain the
// observed request without silently exceeding the platform's supported 64 MiB
// ceiling. A zero result means the caller must reduce or externalize payloads.
func recommendedRequestMaxBytes(requestBytes int64) int64 {
	if requestBytes <= 0 || requestBytes > maximumSupportedRequestMaxBytes {
		return 0
	}
	limit := minimumRecommendedRequestMaxBytes
	for limit < requestBytes && limit < maximumSupportedRequestMaxBytes {
		limit *= 2
	}
	if limit > maximumSupportedRequestMaxBytes {
		return 0
	}
	return limit
}
