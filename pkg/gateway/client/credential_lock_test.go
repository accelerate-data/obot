package client

import (
	"context"
	"errors"
	"testing"
	"time"

	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	storageservices "github.com/obot-platform/obot/pkg/storage/services"
)

func TestAcquireCredentialLockSQLiteHonorsCancellation(t *testing.T) {
	services, err := storageservices.New(storageservices.Config{DSN: "sqlite://:memory:"})
	if err != nil {
		t.Fatalf("opening SQLite database: %v", err)
	}
	database, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	if err != nil {
		t.Fatalf("opening gateway database: %v", err)
	}
	client := &Client{db: database}

	release, err := client.AcquireCredentialLock(t.Context(), "shared-key")
	if err != nil {
		t.Fatalf("acquiring credential lock: %v", err)
	}
	waitCtx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	if _, err := client.AcquireCredentialLock(waitCtx, "shared-key"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting for credential lock returned %v, want context deadline exceeded", err)
	}

	release()
	secondRelease, err := client.AcquireCredentialLock(t.Context(), "shared-key")
	if err != nil {
		t.Fatalf("acquiring released credential lock: %v", err)
	}
	secondRelease()
}
