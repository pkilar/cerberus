package vsockwatch

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// defaultHeartbeatClient POSTs an empty body to url with a short per-request
// timeout, independent of the caller's Heartbeat.Interval — a single slow
// request should not delay the next tick indefinitely.
type defaultHeartbeatClient struct{}

const heartbeatRequestTimeout = 10 * time.Second

func (defaultHeartbeatClient) Do(ctx context.Context, url string) error {
	if url == "" {
		return fmt.Errorf("vsockwatch: heartbeat URL is not configured")
	}
	reqCtx, cancel := context.WithTimeout(ctx, heartbeatRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, nil)
	if err != nil {
		return fmt.Errorf("vsockwatch: build heartbeat request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("vsockwatch: heartbeat delivery failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("vsockwatch: heartbeat endpoint returned status %d", resp.StatusCode)
	}
	return nil
}
