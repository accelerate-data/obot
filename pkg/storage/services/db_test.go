package services

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/obot-platform/kinm/pkg/db"
)

func TestConnectDBRetriesTransientErrorsUntilSuccess(t *testing.T) {
	attempts := 0
	factory := &db.Factory{}
	dial := func() (*db.Factory, error) {
		attempts++
		if attempts < 3 {
			return nil, &net.DNSError{
				Err:        "no such host",
				Name:       "postgres",
				IsNotFound: true,
			}
		}
		return factory, nil
	}

	got, err := connectDB(dial, 5, time.Millisecond)
	if err != nil {
		t.Fatalf("connectDB returned error: %v", err)
	}
	if got != factory {
		t.Fatal("connectDB returned the wrong factory")
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestConnectDBRetriesConnectionRefused(t *testing.T) {
	attempts := 0
	factory := &db.Factory{}
	dial := func() (*db.Factory, error) {
		attempts++
		if attempts < 2 {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
		}
		return factory, nil
	}

	got, err := connectDB(dial, 4, time.Millisecond)
	if err != nil {
		t.Fatalf("connectDB returned error: %v", err)
	}
	if got != factory {
		t.Fatal("connectDB returned the wrong factory")
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
}

func TestConnectDBFailsFastOnPermanentError(t *testing.T) {
	attempts := 0
	dial := func() (*db.Factory, error) {
		attempts++
		return nil, errors.New("unsupported database: foo")
	}

	_, err := connectDB(dial, 5, time.Millisecond)
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 1 {
		t.Fatalf("expected a single fail-fast attempt, got %d", attempts)
	}
}

func TestConnectDBReturnsLastErrorAfterMaxAttempts(t *testing.T) {
	attempts := 0
	dial := func() (*db.Factory, error) {
		attempts++
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	}

	_, err := connectDB(dial, 3, time.Millisecond)
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}
