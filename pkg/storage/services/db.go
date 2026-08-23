package services

import (
	"errors"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/obot-platform/kinm/pkg/db"
)

const (
	dbConnectMaxAttempts = 15
	dbConnectRetryDelay  = 2 * time.Second
)

// connectDB dials the storage database factory, retrying transient connection
// failures — a DNS resolution race while the container network is being
// recreated, for example — for a bounded number of attempts. Permanent
// configuration errors (e.g. an unsupported DSN) fail immediately.
func connectDB(
	dial func() (*db.Factory, error),
	maxAttempts int,
	delay time.Duration,
) (*db.Factory, error) {
	var lastErr error
	for attempt := range maxAttempts {
		factory, err := dial()
		if err == nil {
			return factory, nil
		}
		if !isTransientConnectError(err) {
			return nil, err
		}
		lastErr = err
		log.Warnf(
			"Database connection attempt %d/%d failed, retrying in %s: %v",
			attempt+1,
			maxAttempts,
			delay,
			err,
		)
		time.Sleep(delay)
	}
	return nil, lastErr
}

// isTransientConnectError reports whether err is the kind of network failure
// that resolves on its own (DNS lookup failure, connection refused) as opposed
// to a permanent configuration error (e.g. an unsupported DSN scheme).
func isTransientConnectError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var connectErr *pgconn.ConnectError
	return errors.As(err, &connectErr)
}
