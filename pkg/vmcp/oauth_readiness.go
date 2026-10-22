package vmcp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/obot-platform/obot/apiclient/types"
	gateway "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	kuser "k8s.io/apiserver/pkg/authentication/user"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type OAuthCredentialReader interface {
	RevealCredential(context.Context, []string, string) (gatewaytypes.Credential, error)
}

// OAuthCredentialReady checks the provider-bound, proved credential rather than
// its asynchronously reconciled status flag. Missing credentials are not ready.
func OAuthCredentialReady(ctx context.Context, credentials OAuthCredentialReader, reference, fixedURL string) (bool, error) {
	if credentials == nil || fixedURL == "" {
		return false, nil
	}
	credential, err := credentials.RevealCredential(ctx, []string{reference}, system.StaticOAuthCredentialName)
	if errors.As(err, &gateway.CredentialNotFoundError{}) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return gateway.MCPStaticOAuthCredentialReady(credential.Secrets, fixedURL), nil
}

// LockOAuthCredentials holds the same catalog-then-credential fences used by
// Save/Clear until the caller persists its vMCP definition or connection. This
// prevents a stale status or concurrent Clear/provider edit admitting a new
// connection. Locks are sorted so multi-component definitions cannot deadlock.
func LockOAuthCredentials(ctx context.Context, credentials *gateway.Client, reader kclient.Reader, namespace string, components []types.VMCPComponent, requireSource bool) (func(), error) {
	return lockOAuthCredentials(ctx, credentials, reader, namespace, components, requireSource, false)
}

func lockOAuthCredentials(ctx context.Context, credentials *gateway.Client, reader kclient.Reader, namespace string, components []types.VMCPComponent, requireSource, catalogHeld bool) (func(), error) {
	var required []types.VMCPComponent
	for _, component := range components {
		if StaticOAuthCredentialReference(component.CatalogEntry.Manifest, component.MCPServerCatalogEntryID) != "" {
			required = append(required, component)
		}
	}
	if credentials == nil {
		if len(required) == 0 {
			return func() {}, nil
		}
		return func() {}, types.NewErrBadRequest("%s requires administrator static OAuth configuration", required[0].Name)
	}
	refs := make([]string, 0, len(required))
	for _, component := range required {
		refs = append(refs, ComponentOAuthCredentialReference(component))
	}
	slices.Sort(refs)
	keys := slices.Compact(refs)
	if !catalogHeld {
		keys = append([]string{system.MCPStaticOAuthCatalogMutationLock}, keys...)
	}
	if len(keys) == 0 {
		return func() {}, nil
	}
	unlock, err := credentials.AcquireCredentialLocks(ctx, keys...)
	if err != nil {
		return func() {}, err
	}
	var once sync.Once
	release := func() { once.Do(unlock) }
	for _, component := range required {
		fixedURL := component.CatalogEntry.Manifest.RemoteConfig.FixedURL
		var entry v1.MCPServerCatalogEntry
		err := reader.Get(ctx, kclient.ObjectKey{Namespace: namespace, Name: component.MCPServerCatalogEntryID}, &entry)
		if err != nil && (requireSource || !apierrors.IsNotFound(err)) {
			release()
			return func() {}, err
		}
		// Deleted source entries may still back retained snapshots. Existing sources
		// must still identify the provider the connection is about to use.
		if err == nil && (entry.Spec.Manifest.RemoteConfig == nil || entry.Spec.Manifest.RemoteConfig.FixedURL != fixedURL) {
			release()
			return func() {}, types.NewErrBadRequest("%s requires administrator static OAuth configuration", component.Name)
		}
		ready, err := OAuthCredentialReady(ctx, credentials, ComponentOAuthCredentialReference(component), fixedURL)
		if err != nil {
			release()
			return func() {}, fmt.Errorf("check static OAuth for %s: %w", component.Name, err)
		}
		if !ready {
			release()
			return func() {}, types.NewErrBadRequest("%s requires administrator static OAuth configuration", component.Name)
		}
	}
	return release, nil
}

// LockOAuthConnection re-reads the definition inside the catalog fence before
// checking credentials, so a concurrent definition edit cannot add a static
// component after the connection checked an older component list. The catalog
// lock and batched credential locks use at most two PostgreSQL connections.
func LockOAuthConnection(ctx context.Context, credentials *gateway.Client, reader kclient.Reader, vmcp *v1.VMCP, instance *v1.VMCPInstance, user kuser.Info) (func(), error) {
	releaseCatalog := func() {}
	if credentials != nil {
		var err error
		releaseCatalog, err = credentials.AcquireCredentialLock(ctx, system.MCPStaticOAuthCatalogMutationLock)
		if err != nil {
			return func() {}, err
		}
	}
	if err := reader.Get(ctx, kclient.ObjectKeyFromObject(vmcp), vmcp); err != nil {
		releaseCatalog()
		return func() {}, err
	}
	var currentInstance v1.VMCPInstance
	if instance != nil && instance.Name != "" {
		if err := reader.Get(ctx, kclient.ObjectKeyFromObject(instance), instance); err != nil {
			releaseCatalog()
			return func() {}, err
		}
		currentInstance = *instance
	} else if instance != nil {
		currentInstance = *instance
	}
	components := EnabledComponents(user, *vmcp, ComponentsForInstance(*vmcp, currentInstance))
	releaseCredentials, err := lockOAuthCredentials(ctx, credentials, reader, vmcp.Namespace, components, false, true)
	if err != nil {
		releaseCatalog()
		return func() {}, err
	}
	var once sync.Once
	return func() { once.Do(func() { releaseCredentials(); releaseCatalog() }) }, nil
}
