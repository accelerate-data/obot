package wait

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type watchListClient struct {
	kclient.WithWatch
	watcher  *watch.RaceFreeFakeWatcher
	once     sync.Once
	watching chan struct{}
	options  kclient.ListOptions
}

func TestForListEvaluatesExistingMatchingObjects(t *testing.T) {
	matching := &corev1.ConfigMap{
		Name:      "matching",
		Namespace: "default",
		Labels:    map[string]string{"instance": "target"},
	}
	client := newForListTestClient(t, matching)

	var visited []string
	err := ForList(t.Context(), client, &corev1.ConfigMap{}, "default", func(configMap *corev1.ConfigMap) (bool, error) {
		visited = append(visited, configMap.Name)
		return true, nil
	}, ListOption{
		Timeout: time.Second,
		ListOptions: []kclient.ListOption{
			kclient.MatchingLabels{"instance": "target"},
		},
	})
	if err != nil {
		t.Fatalf("ForList() error = %v", err)
	}
	if len(visited) != 1 || visited[0] != matching.Name {
		t.Fatalf("visited objects = %v, want only %q", visited, matching.Name)
	}
	if client.options.Namespace != "default" {
		t.Fatalf("watch namespace = %q, want default", client.options.Namespace)
	}
	if got := client.options.LabelSelector.String(); got != "instance=target" {
		t.Fatalf("watch label selector = %q, want instance=target", got)
	}
	if client.options.Raw == nil {
		t.Fatal("watch raw options are nil")
	}
	if client.options.Raw.SendInitialEvents == nil || !*client.options.Raw.SendInitialEvents {
		t.Fatal("watch does not request initial events")
	}
	if client.options.Raw.ResourceVersionMatch != metav1.ResourceVersionMatchNotOlderThan {
		t.Fatalf("watch resource version match = %q, want %q", client.options.Raw.ResourceVersionMatch, metav1.ResourceVersionMatchNotOlderThan)
	}
	if !client.options.Raw.AllowWatchBookmarks {
		t.Fatal("watch does not allow bookmarks")
	}
}

func TestForListWaitsForMatchingObject(t *testing.T) {
	client := newForListTestClient(t)
	watching := make(chan struct{})
	client.watching = watching
	go func() {
		<-watching
		client.watcher.Add(&corev1.ConfigMap{
			Name:      "created-later",
			Namespace: "default",
			Labels:    map[string]string{"instance": "target"},
		})
	}()

	err := ForList(t.Context(), client, &corev1.ConfigMap{}, "default", func(configMap *corev1.ConfigMap) (bool, error) {
		return configMap.Name == "created-later", nil
	}, ListOption{
		Timeout: time.Second,
		ListOptions: []kclient.ListOption{
			kclient.MatchingLabels{"instance": "target"},
		},
	})
	if err != nil {
		t.Fatalf("ForList() error = %v", err)
	}
}

func TestForListPropagatesConditionError(t *testing.T) {
	wantErr := errors.New("condition failed")
	client := newForListTestClient(t, &corev1.ConfigMap{
		Name:      "existing",
		Namespace: "default",
	})

	err := ForList(t.Context(), client, &corev1.ConfigMap{}, "default", func(*corev1.ConfigMap) (bool, error) {
		return false, wantErr
	}, ListOption{Timeout: time.Second})
	if !errors.Is(err, wantErr) {
		t.Fatalf("ForList() error = %v, want %v", err, wantErr)
	}
	if errors.Is(err, ErrTimeout) {
		t.Fatalf("ForList() error = %v, must not be %v", err, ErrTimeout)
	}
}

func TestForListTimeoutIsErrTimeout(t *testing.T) {
	client := newForListTestClient(t)

	err := ForList(t.Context(), client, &corev1.ConfigMap{}, "default", func(*corev1.ConfigMap) (bool, error) {
		return false, nil
	}, ListOption{Timeout: 60 * time.Millisecond})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("ForList() error = %v, want %v", err, ErrTimeout)
	}
	if errors.Is(err, ErrWatchClosed) {
		t.Fatalf("ForList() error = %v, must not be reported as a closed watch", err)
	}
}

func TestForTimeoutIsErrTimeout(t *testing.T) {
	client := newForListTestClient(t)

	pending := &corev1.ConfigMap{}
	pending.Name = "pending"
	pending.Namespace = "default"
	pending.UID = "pending-uid"

	_, err := For(t.Context(), client, pending, func(*corev1.ConfigMap) (bool, error) {
		return false, nil
	}, Option{Timeout: 60 * time.Millisecond})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("For() error = %v, want %v", err, ErrTimeout)
	}
}

// A watch that ends before the timeout is a transport fault, not readiness.
func TestForListWatchClosedIsErrWatchClosed(t *testing.T) {
	client := newForListTestClient(t)
	watching := make(chan struct{})
	client.watching = watching
	go func() {
		<-watching
		client.watcher.Stop()
	}()

	err := ForList(t.Context(), client, &corev1.ConfigMap{}, "default", func(*corev1.ConfigMap) (bool, error) {
		return false, nil
	}, ListOption{Timeout: time.Second})
	if !errors.Is(err, ErrWatchClosed) {
		t.Fatalf("ForList() error = %v, want %v", err, ErrWatchClosed)
	}
	if errors.Is(err, ErrTimeout) {
		t.Fatalf("ForList() error = %v, must not be reported as a timeout", err)
	}
}

// A caller's own deadline is the caller's, not the wait's: reporting it as
// ErrTimeout would let a caller degrade on a request that has already expired.
func TestForListCallerDeadlineIsNotATimeout(t *testing.T) {
	client := newForListTestClient(t)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()

	err := ForList(ctx, client, &corev1.ConfigMap{}, "default", func(*corev1.ConfigMap) (bool, error) {
		return false, nil
	}, ListOption{Timeout: time.Minute})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ForList() error = %v, want the caller's deadline", err)
	}
	if errors.Is(err, ErrTimeout) {
		t.Fatalf("ForList() error = %v, must not be reported as the wait's timeout", err)
	}
}

func (c *watchListClient) Watch(_ context.Context, _ kclient.ObjectList, opts ...kclient.ListOption) (watch.Interface, error) {
	c.options = kclient.ListOptions{}
	c.options.ApplyOptions(opts)
	if c.watching != nil {
		c.once.Do(func() {
			close(c.watching)
		})
	}
	return c.watcher, nil
}

func newForListTestClient(t *testing.T, objects ...kclient.Object) *watchListClient {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	watcher := watch.NewRaceFreeFake()
	for _, object := range objects {
		watcher.Add(object)
	}
	return &watchListClient{
		WithWatch: fake.NewClientBuilder().WithScheme(scheme).Build(),
		watcher:   watcher,
	}
}
