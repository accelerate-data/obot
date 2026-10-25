package wait

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrTimeout marks the wait's own elapsed timeout. Callers may degrade on it.
	// An early watch close is ErrWatchClosed, and a caller whose context ends gets
	// that context's error, so a transport fault never looks like a timeout.
	ErrTimeout = errors.New("timeout")
	// ErrWatchClosed marks a watch that ended before the wait's timeout elapsed.
	ErrWatchClosed = errors.New("watch closed")
)

type Option struct {
	Timeout       time.Duration
	Create        bool
	WaitForExists bool
}

type ListOption struct {
	Timeout     time.Duration
	ListOptions []kclient.ListOption
}

func completeOptions(opts ...Option) (result Option) {
	for _, opt := range opts {
		result.Timeout = cmp.Or(result.Timeout, opt.Timeout)
		result.Create = cmp.Or(result.Create, opt.Create)
		result.WaitForExists = cmp.Or(result.WaitForExists, opt.WaitForExists)
	}
	if result.Timeout == 0 {
		result.Timeout = 2 * time.Minute
	}
	return
}

func completeListOptions(opts ...ListOption) (result ListOption) {
	for _, opt := range opts {
		result.Timeout = cmp.Or(result.Timeout, opt.Timeout)
		result.ListOptions = append(result.ListOptions, opt.ListOptions...)
	}
	if result.Timeout == 0 {
		result.Timeout = 2 * time.Minute
	}
	return
}

func load(ctx context.Context, c kclient.Client, obj kclient.Object, create bool) error {
	if obj.GetUID() != "" {
		return nil
	}

	if obj.GetName() != "" {
		err := c.Get(ctx, kclient.ObjectKeyFromObject(obj), obj)
		if !apierrors.IsNotFound(err) {
			return err
		}

		if !create {
			return err
		}
	}

	err := c.Create(ctx, obj)
	if !apierrors.IsAlreadyExists(err) {
		// If the object already exists, we can retrieve it
		return err
	}

	return c.Get(ctx, kclient.ObjectKeyFromObject(obj), obj)
}

func For[T kclient.Object](ctx context.Context, c kclient.WithWatch, obj T, condition func(T) (bool, error), opts ...Option) (def T, _ error) {
	opt := completeOptions(opts...)
	// The local deadline is authoritative. A server-side watch timeout of the same
	// duration would race it, and a watch the server closed would look like a fault.
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	obj = obj.DeepCopyObject().(T)

	gvk, err := c.GroupVersionKindFor(obj)
	if err != nil {
		return def, err
	}

	list, err := c.Scheme().New(schema.GroupVersionKind{
		Group:   gvk.Group,
		Version: gvk.Version,
		Kind:    gvk.Kind + "List",
	})
	if err != nil {
		return def, err
	}

	if err = load(ctx, c, obj, opt.Create); err != nil {
		if !apierrors.IsNotFound(err) || !opt.WaitForExists {
			return def, err
		}
	}

	if obj.GetName() != "" {
		if ok, err := condition(obj); ok || err != nil {
			return obj, err
		}
	}

	w, err := c.Watch(ctx, list.(kclient.ObjectList),
		kclient.InNamespace(obj.GetNamespace()),
		kclient.MatchingFields{"metadata.name": obj.GetName()},
		&kclient.ListOptions{
			Raw: &metav1.ListOptions{
				ResourceVersion: obj.GetResourceVersion(),
			},
		})
	if err != nil {
		return def, err
	}
	defer func() {
		w.Stop()
		//nolint:revive
		for range w.ResultChan() {
		}
	}()

	for {
		select {
		case <-ctx.Done():
			if err := parent.Err(); err != nil {
				return def, err
			}
			return def, fmt.Errorf("%w waiting for %s %s to meet condition", ErrTimeout, gvk.Kind, obj.GetName())
		case event, ok := <-w.ResultChan():
			if !ok {
				return def, fmt.Errorf("%w waiting for %s %s to meet condition", ErrWatchClosed, gvk.Kind, obj.GetName())
			}
			if event.Type == watch.Deleted {
				gvk, _ := c.GroupVersionKindFor(obj)
				return def, apierrors.NewNotFound(schema.GroupResource{
					Group:    gvk.Group,
					Resource: gvk.Kind,
				}, obj.GetName())
			}
			switch event.Type {
			case watch.Added, watch.Modified:
				if ok, err := condition(event.Object.(T)); err != nil {
					return def, err
				} else if ok {
					return event.Object.(T), nil
				}
			case watch.Error:
				return def, apierrors.FromObject(event.Object)
			}
		}
	}
}

func ForList[T kclient.Object](ctx context.Context, c kclient.WithWatch, obj T, namespace string, condition func(T) (bool, error), opts ...ListOption) error {
	opt := completeListOptions(opts...)
	// The local deadline is authoritative. A server-side watch timeout of the same
	// duration would race it, and a watch the server closed would look like a fault.
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	gvk, err := c.GroupVersionKindFor(obj)
	if err != nil {
		return err
	}

	list, err := c.Scheme().New(schema.GroupVersionKind{
		Group:   gvk.Group,
		Version: gvk.Version,
		Kind:    gvk.Kind + "List",
	})
	if err != nil {
		return err
	}
	watchOptions := append([]kclient.ListOption{kclient.InNamespace(namespace)}, opt.ListOptions...)
	watchOptions = append(watchOptions,
		&kclient.ListOptions{
			Raw: &metav1.ListOptions{
				AllowWatchBookmarks:  true,
				ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
				SendInitialEvents:    new(true),
			},
		})
	w, err := c.Watch(ctx, list.(kclient.ObjectList), watchOptions...)
	if err != nil {
		return err
	}
	defer func() {
		w.Stop()
		//nolint:revive
		for range w.ResultChan() {
		}
	}()

	for {
		select {
		case <-ctx.Done():
			if err := parent.Err(); err != nil {
				return err
			}
			return fmt.Errorf("%w waiting for %s list", ErrTimeout, gvk.Kind)
		case event, ok := <-w.ResultChan():
			if !ok {
				return fmt.Errorf("%w waiting for %s list", ErrWatchClosed, gvk.Kind)
			}
			switch event.Type {
			case watch.Added, watch.Modified:
				typedObject, ok := event.Object.(T)
				if !ok {
					return fmt.Errorf("unexpected %T in %s watch", event.Object, gvk.Kind)
				}
				if ok, err := condition(typedObject); err != nil {
					return err
				} else if ok {
					return nil
				}
			case watch.Error:
				return apierrors.FromObject(event.Object)
			}
		}
	}
}
