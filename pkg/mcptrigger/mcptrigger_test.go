package mcptrigger

import (
	"context"
	"testing"
	"time"

	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	storagescheme "github.com/obot-platform/obot/pkg/storage/scheme"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type recordedTrigger struct {
	gvk   schema.GroupVersionKind
	key   string
	delay time.Duration
}

type recordingBackend struct {
	triggers []recordedTrigger
}

func (r *recordingBackend) Trigger(_ context.Context, gvk schema.GroupVersionKind, key string, delay time.Duration) error {
	r.triggers = append(r.triggers, recordedTrigger{gvk: gvk, key: key, delay: delay})
	return nil
}

func newStorageClient(t *testing.T, objs ...kclient.Object) kclient.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(storagescheme.Scheme).
		WithObjects(objs...).
		Build()
}

func mcpServerInstance(name, serverName string) *v1.MCPServerInstance {
	return &v1.MCPServerInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: system.DefaultNamespace,
		},
		Spec: v1.MCPServerInstanceSpec{
			UserID:        "user-1",
			MCPServerName: serverName,
		},
	}
}

// The router resolves a trigger key as "<namespace>/<name>". MCPServer is
// namespace-scoped, so a bare name resolves to no object and every handler is
// skipped.
func TestServerTriggersMCPServerWithNamespaceQualifiedKey(t *testing.T) {
	backend := &recordingBackend{}

	require.NoError(t, Server(context.Background(), backend, system.MCPServerPrefix+"abc"))

	require.Len(t, backend.triggers, 1)
	require.Equal(t, v1.SchemeGroupVersion.WithKind("MCPServer"), backend.triggers[0].gvk)
	require.Equal(t, system.DefaultNamespace+"/"+system.MCPServerPrefix+"abc", backend.triggers[0].key)
	require.Zero(t, backend.triggers[0].delay)
}

func TestServerRejectsMissingBackend(t *testing.T) {
	err := Server(context.Background(), nil, system.MCPServerPrefix+"abc")
	require.ErrorContains(t, err, "controller backend is not configured")
}

func TestServerIgnoresEmptyName(t *testing.T) {
	backend := &recordingBackend{}
	require.NoError(t, Server(context.Background(), backend, ""))
	require.Empty(t, backend.triggers)
}

// A multi-user MCP identifier names an MCPServerInstance, which has no status
// and no OAuth handlers. The reconcile has to land on the owning MCPServer.
func TestOwningServerResolvesInstanceToItsOwningServer(t *testing.T) {
	const (
		instanceName = system.MCPServerInstancePrefix + "abc"
		serverName   = system.MCPServerPrefix + "def"
	)

	backend := &recordingBackend{}
	c := newStorageClient(t, mcpServerInstance(instanceName, serverName))

	require.NoError(t, OwningServer(context.Background(), c, backend, instanceName))

	require.Len(t, backend.triggers, 1)
	require.Equal(t, v1.SchemeGroupVersion.WithKind("MCPServer"), backend.triggers[0].gvk)
	require.Equal(t, system.DefaultNamespace+"/"+serverName, backend.triggers[0].key)
}

func TestOwningServerTriggersServerIDDirectly(t *testing.T) {
	const serverName = system.MCPServerPrefix + "abc"

	backend := &recordingBackend{}
	c := newStorageClient(t)

	require.NoError(t, OwningServer(context.Background(), c, backend, serverName))

	require.Len(t, backend.triggers, 1)
	require.Equal(t, v1.SchemeGroupVersion.WithKind("MCPServer"), backend.triggers[0].gvk)
	require.Equal(t, system.DefaultNamespace+"/"+serverName, backend.triggers[0].key)
}

// Credential rows outlive the instance they were created for, so a delete that
// notifies a stale identifier must not fail.
func TestOwningServerIgnoresDeletedInstance(t *testing.T) {
	backend := &recordingBackend{}
	c := newStorageClient(t)

	require.NoError(t, OwningServer(context.Background(), c, backend, system.MCPServerInstancePrefix+"gone"))
	require.Empty(t, backend.triggers)
}

func TestOwningServerIgnoresInstanceWithoutOwner(t *testing.T) {
	const instanceName = system.MCPServerInstancePrefix + "abc"

	backend := &recordingBackend{}
	c := newStorageClient(t, mcpServerInstance(instanceName, ""))

	require.NoError(t, OwningServer(context.Background(), c, backend, instanceName))
	require.Empty(t, backend.triggers)
}

func TestOwningServerReportsStorageFailure(t *testing.T) {
	backend := &recordingBackend{}

	err := OwningServer(context.Background(), nil, backend, system.MCPServerInstancePrefix+"abc")
	require.ErrorContains(t, err, "no storage client is configured")
	require.Empty(t, backend.triggers)
}

func TestOwningServerIgnoresEmptyID(t *testing.T) {
	backend := &recordingBackend{}
	require.NoError(t, OwningServer(context.Background(), newStorageClient(t), backend, ""))
	require.Empty(t, backend.triggers)
}
