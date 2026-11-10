package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

type staticAuthenticator struct {
	response *authenticator.Response
	err      error
}

func TestUserDecoratorNoopsWithoutAuthProviderMetadata(t *testing.T) {
	c := newTestClient(t)
	decorator := NewUserDecorator(staticAuthenticator{
		response: &authenticator.Response{
			User: &user.DefaultInfo{
				Name:  "api-key-user",
				UID:   "api-key-user",
				Extra: map[string][]string{},
			},
		},
	}, c, unlimitedUserLimitProvider())

	resp, ok, err := decorator.AuthenticateRequest(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected decorator to skip users without auth provider metadata")
	}
	if resp != nil {
		t.Fatalf("expected nil response, got %#v", resp)
	}
}

func (s staticAuthenticator) AuthenticateRequest(*http.Request) (*authenticator.Response, bool, error) {
	if s.err != nil {
		return nil, false, s.err
	}
	if s.response == nil {
		return nil, false, nil
	}
	return s.response, true, nil
}

func unlimitedUserLimitProvider() UserLimitProvider {
	return userLimitProviderFunc(func(context.Context) (UserLimit, error) {
		return UserLimit{Unlimited: true}, nil
	})
}
