// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/falcosecurity/falcosidekick-ui/configuration"
	"github.com/falcosecurity/falcosidekick-ui/internal/testpki"
	echo "github.com/labstack/echo/v4"
)

const (
	uiName      = "ui.test"
	allowedSAN  = "sidekick.test"
	otherSAN    = "other.test"
	cnOnlyName  = "cn-only.test"
	ingestOK    = http.StatusCreated
	healthzPath = "/api/v1/healthz"
)

var ingestPaths = []string{"/", "/api/v1/", "/api/v1/events/add"}

type pki struct {
	ca                *x509.CertPool
	caFile            string
	certFile, keyFile string
	dir               string
	authority         *testpki.CA
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	ca := testpki.NewCA(t)
	dir := t.TempDir()
	p := &pki{ca: ca.Pool(), authority: ca, dir: dir,
		caFile:   filepath.Join(dir, "ca.crt"),
		certFile: filepath.Join(dir, "site.crt"),
		keyFile:  filepath.Join(dir, "site.key")}
	testpki.WriteFile(t, p.caFile, ca.PEM)
	c, k := ca.Issue(t, uiName, []string{uiName}, 1)
	testpki.WriteFile(t, p.certFile, c)
	testpki.WriteFile(t, p.keyFile, k)
	return p
}

// startServer builds the HTTPS server through NewHTTPSServer (the function main
// uses), serves it on a real listener and returns its address.
func startServer(t *testing.T, e *echo.Echo, p *pki) string {
	t.Helper()
	cfg := configuration.GetConfiguration()
	cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSClientCAFile = p.certFile, p.keyFile, p.caFile
	srv, err := NewHTTPSServer(e, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func setupConfig(t *testing.T, sans string) {
	t.Helper()
	cfg := configuration.CreateConfiguration()
	cfg.LogLevel = "info"
	cfg.DisableAuth = true
	cfg.IngestMTLSAllowedSANs = sans
	old := ReloadInterval
	t.Cleanup(func() { ReloadInterval = old })
}

func newClient(p *pki, clientCert *tls.Certificate) *http.Client {
	cfg := &tls.Config{RootCAs: p.ca, ServerName: uiName, MinVersion: tls.VersionTLS12}
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true},
	}
}

func issueClient(t *testing.T, ca *testpki.CA, cn string, dns []string, serial int64) *tls.Certificate {
	t.Helper()
	c, k := ca.Issue(t, cn, dns, serial)
	pair, err := tls.X509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	return &pair
}

func do(t *testing.T, c *http.Client, method, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestIngestMTLSRealRouterStack(t *testing.T) {
	setupConfig(t, " "+allowedSAN+" , ,")
	p := newPKI(t)

	var reached atomic.Int32
	e := echo.New()
	e.HideBanner = true
	RegisterRoutes(e, func(c echo.Context) error {
		reached.Add(1)
		return c.String(ingestOK, "stored")
	})
	addr := startServer(t, e, p)
	base := "https://" + addr

	allowed := issueClient(t, p.authority, "whatever", []string{allowedSAN}, 10)
	other := issueClient(t, p.authority, "whatever", []string{otherSAN}, 11)
	cnOnly := issueClient(t, p.authority, allowedSAN, nil, 12)

	for _, path := range ingestPaths {
		t.Run("allowed SAN "+path, func(t *testing.T) {
			before := reached.Load()
			code, _ := do(t, newClient(p, allowed), http.MethodPost, base+path)
			if code != ingestOK || reached.Load() != before+1 {
				t.Fatalf("code=%d handlerCalls=%d, want %d and handler reached", code, reached.Load()-before, ingestOK)
			}
		})
		t.Run("CN match "+path, func(t *testing.T) {
			code, _ := do(t, newClient(p, cnOnly), http.MethodPost, base+path)
			if code != ingestOK {
				t.Fatalf("code=%d, want %d", code, ingestOK)
			}
		})
		t.Run("other SAN "+path, func(t *testing.T) {
			before := reached.Load()
			code, body := do(t, newClient(p, other), http.MethodPost, base+path)
			if code != http.StatusForbidden || reached.Load() != before {
				t.Fatalf("code=%d reached=%v body=%s, want 403 and handler not reached", code, reached.Load() != before, body)
			}
		})
		t.Run("no cert "+path, func(t *testing.T) {
			before := reached.Load()
			code, _ := do(t, newClient(p, nil), http.MethodPost, base+path)
			if code != http.StatusForbidden || reached.Load() != before {
				t.Fatalf("code=%d reached=%v, want 403 and handler not reached", code, reached.Load() != before)
			}
		})
	}

	t.Run("non-ingest route without cert is not blocked", func(t *testing.T) {
		code, _ := do(t, newClient(p, nil), http.MethodGet, base+"/api/v1/version")
		if code != http.StatusOK {
			t.Fatalf("code=%d, want 200", code)
		}
	})

	t.Run("client cert from untrusted CA is rejected at handshake", func(t *testing.T) {
		rogue := testpki.NewCA(t)
		cert := issueClient(t, rogue, "x", []string{allowedSAN}, 99)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/", strings.NewReader("{}"))
		resp, err := newClient(p, cert).Do(req)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("expected handshake failure, got %d", resp.StatusCode)
		}
	})
}

func TestIngestMTLSDisabledWhenNoSANs(t *testing.T) {
	setupConfig(t, "")
	p := newPKI(t)
	e := echo.New()
	e.HideBanner = true
	RegisterRoutes(e, func(c echo.Context) error { return c.String(ingestOK, "stored") })
	addr := startServer(t, e, p)
	code, _ := do(t, newClient(p, nil), http.MethodPost, "https://"+addr+"/api/v1/")
	if code != ingestOK {
		t.Fatalf("code=%d, want %d (no mTLS configured)", code, ingestOK)
	}
}

func servedSerial(t *testing.T, addr string, p *pki) int64 {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: p.ca, ServerName: uiName, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

func TestHTTPSServerServesHealthzAndReloadsCert(t *testing.T) {
	setupConfig(t, "")
	ReloadInterval = time.Nanosecond // test hook: check files on every handshake
	p := newPKI(t)
	e := echo.New()
	e.HideBanner = true
	RegisterRoutes(e, func(c echo.Context) error { return c.NoContent(ingestOK) })
	addr := startServer(t, e, p)

	if code, _ := do(t, newClient(p, nil), http.MethodGet, "https://"+addr+healthzPath); code != http.StatusOK {
		t.Fatalf("healthz without client cert: %d, want 200", code)
	}
	if s := servedSerial(t, addr, p); s != 1 {
		t.Fatalf("initial serial %d, want 1", s)
	}

	c2, k2 := p.authority.Issue(t, uiName, []string{uiName}, 2)
	testpki.WriteFile(t, p.certFile, c2)
	testpki.WriteFile(t, p.keyFile, k2)

	if s := servedSerial(t, addr, p); s != 2 {
		t.Fatalf("serial after rotation %d, want 2", s)
	}
	if code, _ := do(t, newClient(p, nil), http.MethodGet, "https://"+addr+healthzPath); code != http.StatusOK {
		t.Fatalf("healthz after rotation: %d, want 200", code)
	}
}

func TestNewHTTPSServerErrors(t *testing.T) {
	setupConfig(t, "")
	p := newPKI(t)
	cfg := configuration.GetConfiguration()
	cfg.TLSCertFile, cfg.TLSKeyFile = p.certFile, p.keyFile
	cfg.TLSClientCAFile = filepath.Join(p.dir, "missing-ca.crt")
	if _, err := NewHTTPSServer(echo.New(), ":0"); err == nil {
		t.Fatal("expected error for missing client CA file")
	}
	cfg.TLSClientCAFile = ""
	cfg.TLSCertFile = filepath.Join(p.dir, "missing.crt")
	if _, err := NewHTTPSServer(echo.New(), ":0"); err == nil {
		t.Fatal("expected error for missing cert file")
	}
}

func TestParseAllowedSANs(t *testing.T) {
	got := ParseAllowedSANs(" a , ,b,,")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("got %q", got)
	}
}
