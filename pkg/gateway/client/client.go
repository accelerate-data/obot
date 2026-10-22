package client

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	nahbackend "github.com/obot-platform/nah/pkg/backend"
	types2 "github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/gateway/db"
	"github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/mcptrigger"
	"golang.org/x/sync/singleflight"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	defaultAuditLogCleanupInterval = 24 * time.Hour
	defaultAuditLogDeleteBatchSize = 1000

	defaultDeviceScanCleanupInterval = 24 * time.Hour
	defaultDeviceScanDeleteBatchSize = 100

	// DefaultUserLimit is the maximum number of users allowed when no
	// license-derived user-limit provider is configured.
	DefaultUserLimit = 100

	// DefaultDeviceLimit is the maximum number of devices allowed when no
	// license-derived device-limit provider is configured.
	DefaultDeviceLimit = 100
)

type Client struct {
	egressAuditLock           sync.Mutex
	egressAuditPersistLock    sync.Mutex
	egressAuditBuffer         []types.EgressAuditLog
	egressAuditPending        int
	egressAuditBytes          int
	egressAuditDropped        uint64
	egressAuditOverflowLogged time.Time
	kickEgressAuditPersist    chan struct{}
	egressAuditCancel         context.CancelFunc
	egressAuditDone           chan struct{}

	db                        *db.DB
	encryptionConfig          *encryptionconfig.EncryptionConfiguration
	emailsWithExplicitRoles   map[string]types2.Role
	auditLock                 sync.Mutex
	auditBuffer               []types.MCPAuditLog
	kickAuditPersist          chan struct{}
	enforcementLock           sync.Mutex
	enforcementBuffer         []types.EnforcementDecisionLog
	kickEnforcementPersist    chan struct{}
	credentialLocks           sync.Map
	credentialLockPoolOnce    sync.Once
	credentialLockPool        *sql.DB
	credentialLockPoolErr     error
	llmAuditEntries           chan llmAuditEntry
	llmAuditBatchSize         int
	llmAuditEnabled           bool
	storageClient             kclient.Client
	apiKeyCacheLock           sync.RWMutex
	apiKeyCache               map[[32]byte]apiKeyValidationCacheEntry
	apiKeyCacheTTL            time.Duration
	serviceAccountCacheLock   sync.RWMutex
	serviceAccountCache       map[[32]byte]serviceAccountValidationCacheEntry
	serviceAccountCacheTTL    time.Duration
	deviceCreationLock        sync.Mutex
	auditLogCleanupInterval   time.Duration
	auditLogDeleteBatchSize   int
	deviceScanCleanupInterval time.Duration
	deviceScanDeleteBatchSize int
	mcpOAuthTokenTrigger      func(context.Context, string) error
	groupRefresh              singleflight.Group
	groupCooldown             groupRefreshCooldown
	kickLifecycleDelivery     chan struct{}
}

func New(ctx context.Context, db *db.DB, storageClient kclient.Client, encryptionConfig *encryptionconfig.EncryptionConfiguration, controllerBackend nahbackend.Trigger, ownerEmails, adminEmails []string, auditLogPersistenceInterval time.Duration, auditLogBatchSize, auditLogRetentionDays, llmAuditLogRetentionDays, deviceScanRetentionDays int, llmAuditEnabled bool) *Client {
	explicitRoleEmailsSet := make(map[string]types2.Role, len(ownerEmails)+len(adminEmails))
	for _, email := range adminEmails {
		explicitRoleEmailsSet[strings.ToLower(email)] = types2.RoleAdmin
	}
	// If a user is explicitly both an admin and owner, they are an owner.
	for _, email := range ownerEmails {
		explicitRoleEmailsSet[strings.ToLower(email)] = types2.RoleOwner
	}
	egressCtx, egressCancel := context.WithCancel(ctx)
	c := &Client{
		egressAuditBuffer:         make([]types.EgressAuditLog, 0, min(2*auditLogBatchSize, egressAuditMaxEntries)),
		kickEgressAuditPersist:    make(chan struct{}, 1),
		egressAuditCancel:         egressCancel,
		egressAuditDone:           make(chan struct{}),
		db:                        db,
		encryptionConfig:          encryptionConfig,
		emailsWithExplicitRoles:   explicitRoleEmailsSet,
		auditBuffer:               make([]types.MCPAuditLog, 0, 2*auditLogBatchSize),
		kickAuditPersist:          make(chan struct{}),
		enforcementBuffer:         make([]types.EnforcementDecisionLog, 0, 2*auditLogBatchSize),
		kickEnforcementPersist:    make(chan struct{}),
		storageClient:             storageClient,
		apiKeyCache:               make(map[[32]byte]apiKeyValidationCacheEntry),
		apiKeyCacheTTL:            apiKeyValidationCacheTTL,
		serviceAccountCache:       make(map[[32]byte]serviceAccountValidationCacheEntry),
		serviceAccountCacheTTL:    serviceAccountValidationCacheTTL,
		llmAuditEntries:           make(chan llmAuditEntry, defaultLLMAuditLogBufferSize),
		llmAuditBatchSize:         defaultLLMAuditLogBatchSize,
		llmAuditEnabled:           llmAuditEnabled,
		auditLogCleanupInterval:   defaultAuditLogCleanupInterval,
		auditLogDeleteBatchSize:   defaultAuditLogDeleteBatchSize,
		deviceScanCleanupInterval: defaultDeviceScanCleanupInterval,
		deviceScanDeleteBatchSize: defaultDeviceScanDeleteBatchSize,
		kickLifecycleDelivery:     make(chan struct{}, 1),
	}

	go c.runEgressAuditPersistenceLoop(egressCtx, auditLogPersistenceInterval)
	if controllerBackend != nil {
		// Callers without a controller backend (tests, and any caller that does
		// not run controllers) have nothing to notify. Building the trigger here
		// rather than accepting a callback leaves no call site that can enqueue
		// a bare key or an MCPServerInstance name (VD-4889).
		c.mcpOAuthTokenTrigger = mcptrigger.OwningServerTrigger(storageClient, controllerBackend)
	}

	go c.runMCPAuditLogPersistenceLoop(ctx, auditLogPersistenceInterval)
	go c.runEnforcementDecisionPersistenceLoop(ctx, auditLogPersistenceInterval)
	go c.runLLMAuditPersistenceLoop(ctx, c.llmAuditBatchSize, auditLogPersistenceInterval)
	go c.runPendingStateCleanup(ctx)
	go c.runTokenCleanup(ctx)
	go c.runAPIKeyCacheCleanup(ctx)
	go c.runRetentionCleanup(ctx, auditLogRetentionDays, llmAuditLogRetentionDays)
	go c.runDeviceScanCleanup(ctx, deviceScanRetentionDays)
	go c.runUserLifecycleEventDelivery(ctx)
	go c.runSCIMGroupDeletionMarkExpiry(ctx)
	return c
}

func (c *Client) Close() error {
	var errs []error
	if c.egressAuditCancel != nil {
		c.egressAuditCancel()
		<-c.egressAuditDone
	}
	if err := c.FlushEgressAuditLogs(); err != nil {
		errs = append(errs, fmt.Errorf("failed to persist egress audit logs: %w", err))
	}
	if c.credentialLockPool != nil {
		if err := c.credentialLockPool.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close credential lock database: %w", err))
		}
	}
	if err := c.persistMCPAuditLogs(); err != nil {
		errs = append(errs, fmt.Errorf("failed to persist audit logs: %w", err))
	}
	if err := c.persistEnforcementDecisions(); err != nil {
		errs = append(errs, fmt.Errorf("failed to persist enforcement decisions: %w", err))
	}
	if err := c.persistQueuedLLMAuditLogs(); err != nil {
		errs = append(errs, fmt.Errorf("failed to persist LLM audit logs: %w", err))
	}

	return errors.Join(append(errs, c.db.Close())...)
}

func (c *Client) HasExplicitRole(email string) types2.Role {
	return c.emailsWithExplicitRoles[strings.ToLower(email)]
}

// GetExplicitRoleEmails returns a copy of all emails with explicit roles.
// Used by setup endpoints to list Owner and Admin emails.
func (c *Client) GetExplicitRoleEmails() map[string]types2.Role {
	// No lock needed - map is immutable after construction
	return maps.Clone(c.emailsWithExplicitRoles)
}
