package handlers

import (
	"context"
	"errors"

	"github.com/obot-platform/obot/apiclient/types"
	gateway "github.com/obot-platform/obot/pkg/gateway/client"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// lockStaticOAuthCredentialForCreate takes the catalog mutation fence shared
// with static OAuth Save/Clear and catalog entry updates, re-reads the entry
// inside it, and reports whether the entry's static OAuth credential is ready
// for the entry's current provider. The entry's cached status is not consulted:
// it lags a Clear or a provider change, and a stale "configured" would let a
// server bind to a credential that no longer exists or was issued for another
// provider. Entries without static OAuth take only the catalog fence so they
// never wait on an unrelated credential mutation.
//
// The returned release must be called once the server is created and before
// the response is written, so a stalled client cannot hold the fence.
func lockStaticOAuthCredentialForCreate(ctx context.Context, gatewayClient *gateway.Client, reader kclient.Reader, entryKey kclient.ObjectKey) (func(), v1.MCPServerCatalogEntry, bool, error) {
	var entry v1.MCPServerCatalogEntry
	releaseCatalogMutation, err := gatewayClient.AcquireCredentialLock(ctx, system.MCPStaticOAuthCatalogMutationLock)
	if err != nil {
		return func() {}, entry, false, err
	}
	if err := reader.Get(ctx, entryKey, &entry); err != nil {
		releaseCatalogMutation()
		return func() {}, entry, false, err
	}
	if entry.Spec.Manifest.Runtime != types.RuntimeRemote ||
		entry.Spec.Manifest.RemoteConfig == nil ||
		!entry.Spec.Manifest.RemoteConfig.StaticOAuthRequired {
		return releaseCatalogMutation, entry, true, nil
	}
	credentialName := system.MCPOAuthCredentialName(entryKey.Name)
	releaseCredential, err := gatewayClient.AcquireCredentialLock(ctx, credentialName)
	if err != nil {
		releaseCatalogMutation()
		return func() {}, entry, false, err
	}
	release := func() {
		releaseCredential()
		releaseCatalogMutation()
	}
	credential, err := gatewayClient.RevealCredential(ctx, []string{credentialName}, system.StaticOAuthCredentialName)
	if err != nil {
		if errors.As(err, &gateway.CredentialNotFoundError{}) {
			return release, entry, false, nil
		}
		release()
		return func() {}, entry, false, err
	}
	return release, entry, gateway.MCPStaticOAuthCredentialReady(credential.Secrets, entry.Spec.Manifest.RemoteConfig.FixedURL), nil
}
