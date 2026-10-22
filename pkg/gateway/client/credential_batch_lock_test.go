package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAcquireCredentialLocksReleasesPartialSetAfterCancellation(t *testing.T) {
	client := newTestClient(t)
	release, err := client.AcquireCredentialLock(t.Context(), "blocked")
	require.NoError(t, err)
	defer release()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	_, err = client.AcquireCredentialLocks(ctx, "first", "blocked")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	ctx2, cancel2 := context.WithTimeout(t.Context(), time.Second)
	defer cancel2()
	unlock, err := client.AcquireCredentialLocks(ctx2, "first", "first", "another")
	require.NoError(t, err)
	unlock()
	unlock()
}

func TestAcquireCredentialLocksPostgresUsesOneConnectionForManyKeys(t *testing.T) {
	dsn, _ := newCredentialLockPostgresTest(t)
	database := newPostgresUserLimitTestDB(t, dsn)
	holder := newCredentialLockTestClient(t, database)
	waiter := newCredentialLockTestClient(t, database)
	keys := []string{"catalog", "entry-a", "entry-b", "entry-c", "entry-d", "entry-e", "entry-f"}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	release, err := holder.AcquireCredentialLocks(ctx, keys...)
	require.NoError(t, err)
	defer release()
	require.Equal(t, 1, holder.credentialLockPool.Stats().InUse)
	for _, key := range keys {
		ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
		unlock, err := waiter.AcquireCredentialLock(ctx, key)
		cancel()
		if err == nil {
			unlock()
			t.Fatalf("batch did not hold key %q", key)
		}
		require.True(t, errors.Is(err, context.DeadlineExceeded), "key %s: %v", key, err)
	}
	// A failed batch must release a key it acquired before reaching a held
	// singleton lock, so another operation can still use that key.
	partialCtx, cancelPartial := context.WithTimeout(t.Context(), 40*time.Millisecond)
	_, err = waiter.AcquireCredentialLocks(partialCtx, "free-first", keys[2])
	cancelPartial()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	freeCtx, cancelFree := context.WithTimeout(t.Context(), time.Second)
	unlockFree, err := holder.AcquireCredentialLock(freeCtx, "free-first")
	cancelFree()
	require.NoError(t, err)
	unlockFree()
	release()
	for _, key := range keys {
		unlock, err := waiter.AcquireCredentialLock(t.Context(), key)
		require.NoError(t, err)
		unlock()
	}
}
