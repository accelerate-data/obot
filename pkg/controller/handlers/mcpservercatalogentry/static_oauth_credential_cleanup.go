package mcpservercatalogentry

// Fork-only guarantee (fork #37, restored by VD-6903): static OAuth cleanup is
// serialized with catalog mutation and re-reads the entry before deleting, and
// removing an application also removes the grants and pending proofs it issued.
// Kept in its own file so an upstream sync cannot drop it by merging over the
// shared controller file.

import (
	"fmt"

	"github.com/obot-platform/nah/pkg/router"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// deleteStaticOAuthCredential removes the entry's static OAuth application and
// everything it issued. It deletes nothing and reports restored when the stored
// entry has been changed back to require static OAuth.
//
// The request that triggered cleanup can be stale: an admin can restore static
// OAuth and write a new credential while this pass is queued. The API writes
// credentials under the catalog mutation lock and then the credential lock, so
// taking the same locks in the same order and re-reading the entry under them
// keeps a stale pass from deleting the restored application.
//
// Removing the application from a live entry deletes only the grants it issued,
// so users' own dynamic grants on its deployments survive. Deleting the entry
// itself (entryDeleted) also revokes every grant on its deployments, since they
// cannot outlive the entry they were made for.
func deleteStaticOAuthCredential(req router.Request, creds credentialClient, entry *v1.MCPServerCatalogEntry, entryDeleted bool) (deleted, restored bool, err error) {
	releaseCatalogMutationLock, err := creds.AcquireCredentialLock(req.Ctx, system.MCPStaticOAuthCatalogMutationLock)
	if err != nil {
		return false, false, fmt.Errorf("failed to coordinate static OAuth cleanup with catalog mutation: %w", err)
	}
	defer releaseCatalogMutationLock()

	var current v1.MCPServerCatalogEntry
	if err := req.Client.Get(req.Ctx, router.Key(entry.Namespace, entry.Name), &current); err != nil {
		if !apierrors.IsNotFound(err) {
			return false, false, fmt.Errorf("failed to confirm static OAuth cleanup is still required: %w", err)
		}
	} else if current.DeletionTimestamp.IsZero() && requiresStaticOAuth(&current) {
		return false, true, nil
	}

	releaseCredentialLock, err := creds.AcquireCredentialLock(req.Ctx, system.MCPOAuthCredentialName(entry.Name))
	if err != nil {
		return false, false, fmt.Errorf("failed to coordinate static OAuth cleanup with credential mutation: %w", err)
	}
	defer releaseCredentialLock()

	// Deployments are passed so they re-evaluate their OAuth state. The delete is not
	// fenced on a generation and does not decrypt the application, so a credential
	// without a generation, or one this server can no longer decrypt, is still removed
	// together with what it issued.
	deploymentIDs, err := staticOAuthDeploymentIDs(req, entry.Name)
	if err != nil {
		return false, false, err
	}
	if entryDeleted {
		deleted, err = creds.DeleteMCPStaticOAuthStateForDeletedCatalogEntry(req.Ctx, entry.Name, deploymentIDs...)
	} else {
		deleted, err = creds.DeleteMCPStaticOAuthCredential(req.Ctx, entry.Name, deploymentIDs...)
	}
	if err != nil {
		return false, false, fmt.Errorf("failed to clean up static OAuth state: %w", err)
	}
	return deleted, false, nil
}

func staticOAuthDeploymentIDs(req router.Request, entryName string) ([]string, error) {
	var servers v1.MCPServerList
	if err := req.List(&servers, &kclient.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.mcpServerCatalogEntryName", entryName),
		Namespace:     system.DefaultNamespace,
	}); err != nil {
		return nil, fmt.Errorf("failed to list MCP servers for static OAuth cleanup: %w", err)
	}
	var instances v1.MCPServerInstanceList
	if err := req.List(&instances, &kclient.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.mcpServerCatalogEntryName", entryName),
		Namespace:     system.DefaultNamespace,
	}); err != nil {
		return nil, fmt.Errorf("failed to list MCP server instances for static OAuth cleanup: %w", err)
	}

	ids := make([]string, 0, len(servers.Items)+len(instances.Items))
	for _, server := range servers.Items {
		ids = append(ids, server.Name)
	}
	for _, instance := range instances.Items {
		ids = append(ids, instance.Name)
	}
	return ids, nil
}
