package platform

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// BootstrapViewer creates the deployment read-only account exactly once. It is
// intentionally insert-only: restarts and upgrades never rotate or overwrite an
// existing viewer password or role. The existing HTTP RBAC already grants the
// viewer role GET access while all mutation routes require operator/admin.
func (s *Store) BootstrapViewer(ctx context.Context, username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		username = "viewer"
	}
	if strings.TrimSpace(password) == "" {
		return nil
	}
	if len(password) < 14 {
		return errors.New("bootstrap viewer password must contain at least 14 characters")
	}
	passwordHash, err := HashPassword(password)
	if err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO admin_users(username,password_hash,role,enabled)
		VALUES($1,$2,'viewer',TRUE) ON CONFLICT(username) DO NOTHING`, username, passwordHash); err != nil {
		return fmt.Errorf("bootstrap viewer: %w", err)
	}
	return nil
}
