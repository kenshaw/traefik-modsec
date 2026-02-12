package modsec

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestModsec(t *testing.T) {
	req, err := http.NewRequest("GET", "http://proxy.com/test", strings.NewReader("Request"))
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	type resp struct {
		Body       string
		StatusCode int
	}
	svcResp := resp{
		StatusCode: http.StatusOK,
		Body:       "Response from service",
	}
	tests := []struct {
		name   string
		req    *http.Request
		waf    resp
		svc    resp
		exp    string
		status int
		jailed bool
		cfg    *Config
	}{
		{
			name: "Forward request when WAF found no threats",
			req:  req.Clone(t.Context()),
			waf: resp{
				StatusCode: http.StatusOK,
				Body:       "Response from waf",
			},
			svc:    svcResp,
			exp:    "Response from service",
			status: http.StatusOK,
			jailed: false,
		},
		{
			name: "Intercepts request when WAF found threats",
			req:  req.Clone(t.Context()),
			waf: resp{
				StatusCode: http.StatusForbidden,
				Body:       "Response from waf",
			},
			svc:    svcResp,
			exp:    "Response from waf",
			status: http.StatusForbidden,
			jailed: false,
		},
		{
			name: "Does not forward Websockets",
			req: &http.Request{
				Body: http.NoBody,
				Header: http.Header{
					"Upgrade": []string{"websocket"},
				},
				Method: http.MethodGet,
				URL:    req.URL,
			},
			waf: resp{
				StatusCode: http.StatusOK,
				Body:       "Response from waf",
			},
			svc:    svcResp,
			exp:    "Response from service",
			status: http.StatusOK,
			jailed: false,
		},
		{
			name: "Jail client after multiple bad requests",
			req:  req.Clone(t.Context()),
			waf: resp{
				StatusCode: http.StatusForbidden,
				Body:       "Response from waf",
			},
			svc:    svcResp,
			exp:    "Forbidden\n",
			status: http.StatusForbidden,
			jailed: true,
			cfg: &Config{
				Jail: &JailConfig{
					Enabled:          true,
					BadRequestLimit:  3,
					BadRequestPeriod: 10 * time.Millisecond,
					Duration:         10 * time.Millisecond,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := http.Response{
					Body:       io.NopCloser(strings.NewReader(test.waf.Body)),
					StatusCode: test.waf.StatusCode,
					Header:     http.Header{},
				}
				t.Logf("WAF Mock: status code: %d, body: %s", resp.StatusCode, test.waf.Body)
				forward(w, &resp)
			}))
			defer srv.Close()
			svc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := http.Response{
					Body:       io.NopCloser(strings.NewReader(test.svc.Body)),
					StatusCode: test.svc.StatusCode,
					Header:     http.Header{},
				}
				t.Logf("Service Handler: status code: %d, body: %s", resp.StatusCode, test.svc.Body)
				forward(w, &resp)
			})
			cfg := &Config{
				Timeout:    2 * time.Second,
				ServiceURL: srv.URL,
				Jail: &JailConfig{
					Enabled:          test.jailed,
					BadRequestLimit:  25,
					BadRequestPeriod: 600 * time.Millisecond,
					Duration:         600 * time.Millisecond,
				},
			}
			if test.jailed && test.cfg != nil {
				cfg = test.cfg
				cfg.ServiceURL = srv.URL
			}
			mw, err := New(context.Background(), svc, cfg, "modsecurity-middleware")
			if err != nil {
				t.Fatalf("Failed to create middleware: %v", err)
			}
			if z, ok := mw.(*Modsec); ok {
				z.l = log.New(logWriter{t}, "", 0)
			}
			w := httptest.NewRecorder()
			for i := 0; i < cfg.Jail.BadRequestLimit; i++ {
				mw.ServeHTTP(w, test.req.Clone(test.req.Context()))
				if test.jailed && i < cfg.Jail.BadRequestLimit-1 {
					if code, exp := w.Result().StatusCode, test.waf.StatusCode; code != exp {
						t.Errorf("expected %d, got: %d", exp, code)
					}
				}
			}
			w = httptest.NewRecorder()
			mw.ServeHTTP(w, test.req.Clone(test.req.Context()))
			resp := w.Result()
			body, _ := io.ReadAll(resp.Body)
			if s, exp := string(body), test.exp; s != exp {
				t.Errorf("expected %q, got: %q", exp, s)
			}
			if code, exp := resp.StatusCode, test.status; code != exp {
				t.Errorf("expected %d, got: %d", exp, code)
			}
		})
	}
}

type logWriter struct {
	t *testing.T
}

func (w logWriter) Write(buf []byte) (int, error) {
	for b := range bytes.SplitSeq(bytes.TrimRight(buf, "\n"), []byte{'\n'}) {
		w.t.Logf("%s", string(b))
	}
	return len(buf), nil
}
