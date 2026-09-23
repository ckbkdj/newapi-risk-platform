package platform

import (
	"testing"
	"time"
)

func TestDefaultRouteRequestTimeoutSupportsLongTasks(t *testing.T) {
	if defaultRouteRequestTimeoutMS != 2700000 {
		t.Fatalf("unexpected route timeout ms: %d", defaultRouteRequestTimeoutMS)
	}
	if defaultRouteRequestTimeout != 45*time.Minute {
		t.Fatalf("unexpected route timeout duration: %s", defaultRouteRequestTimeout)
	}
}
