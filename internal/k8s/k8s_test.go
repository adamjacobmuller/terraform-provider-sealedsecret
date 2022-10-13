package k8s

import (
	"context"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestGet(t *testing.T) {
	tests := []struct {
		Name                    string
		Mock                    roundTripFunc
		ExpectedResponse        string
		ExpectedErr             string
		ExpectedNumberOfRetries int
	}{
		{
			Name: "happy day",
			Mock: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(strings.NewReader("this_should_work")),
				}, nil
			}),
			ExpectedResponse: "this_should_work",
			ExpectedErr:      "",
		},
		{
			Name: "retries logic is working",
			Mock: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return nil, nil
			}),
			ExpectedResponse:        "",
			ExpectedErr:             "request to k8s cluster failed: Get \"http://localhost/api/v1/namespaces/controllerNs_aaa/services/http:controllerName_aaa:/proxy/path_aaa?timeout=10s\": http: RoundTripper implementation (*transport.userAgentRoundTripper) returned a nil *Response with a nil error",
			ExpectedNumberOfRetries: 5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.ExpectedNumberOfRetries == 0 {
				// min number of calls is one
				tc.ExpectedNumberOfRetries = 1
			}
			var gotNumberOfRetries int

			c, err := NewClient(&Config{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				gotNumberOfRetries++
				return tc.Mock(req)
			})})
			if err != nil {
				t.Fatal(err)
			}

			resp, err := c.Get(context.Background(), "controllerName_aaa", "controllerNs_aaa", "path_aaa")
			if tc.ExpectedErr == "" && err != nil {
				t.Errorf("expected error to be nil, got %v", err)
			}

			if tc.ExpectedErr != "" && tc.ExpectedErr != err.Error() {
				t.Errorf("expected error '%s', got '%s'", tc.ExpectedErr, err.Error())
			}

			assert.Equal(t, tc.ExpectedResponse, string(resp))
			assert.Equal(t, tc.ExpectedNumberOfRetries, gotNumberOfRetries)
		})
	}
}
