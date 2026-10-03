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

package redis

import (
	"bufio"
	"crypto/tls"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/falcosecurity/falcosidekick-ui/configuration"
	"github.com/falcosecurity/falcosidekick-ui/internal/testpki"
	"github.com/gomodule/redigo/redis"
)

const redisName = "redis.test"

// fakeRedis is a TLS listener (client certs required and verified) that answers PING with +PONG.
type fakeRedis struct {
	addr string
	mu   sync.Mutex
	seen []int64 // serials of client certs presented, one per connection
}

func (f *fakeRedis) serials() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int64(nil), f.seen...)
}

func startFakeRedis(t *testing.T, ca *testpki.CA) *fakeRedis {
	t.Helper()
	c, k := ca.Issue(t, redisName, []string{redisName}, 100)
	pair, err := tls.X509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.Pool(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRedis{addr: ln.Addr().String()}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				tc := conn.(*tls.Conn)
				if tc.Handshake() != nil {
					return
				}
				f.mu.Lock()
				f.seen = append(f.seen, tc.ConnectionState().PeerCertificates[0].SerialNumber.Int64())
				f.mu.Unlock()
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if strings.EqualFold(strings.TrimSpace(line), "PING") {
						_, _ = conn.Write([]byte("+PONG\r\n"))
					}
				}
			}(conn)
		}
	}()
	return f
}

type env struct {
	ca                *testpki.CA
	dir               string
	caFile            string
	certFile, keyFile string
	srv               *fakeRedis
}

func setup(t *testing.T) *env {
	t.Helper()
	ca := testpki.NewCA(t)
	dir := t.TempDir()
	e := &env{ca: ca, dir: dir,
		caFile:   filepath.Join(dir, "ca.crt"),
		certFile: filepath.Join(dir, "client.crt"),
		keyFile:  filepath.Join(dir, "client.key"),
		srv:      startFakeRedis(t, ca)}
	testpki.WriteFile(t, e.caFile, ca.PEM)
	e.writeClient(t, 1)

	tlsReloader = nil // the helper keeps a process-wide reloader; start clean
	oldInterval := clientCertReloadInterval
	clientCertReloadInterval = time.Nanosecond // test hook: re-check files on every handshake
	t.Cleanup(func() { tlsReloader = nil; clientCertReloadInterval = oldInterval })

	cfg := configuration.CreateConfiguration()
	cfg.LogLevel = "info"
	cfg.RedisServer = e.srv.addr
	cfg.RedisTLS = true
	cfg.RedisTLSCAFile = e.caFile
	cfg.RedisTLSCertFile = e.certFile
	cfg.RedisTLSKeyFile = e.keyFile
	cfg.RedisTLSServerName = redisName
	return e
}

func (e *env) writeClient(t *testing.T, serial int64) {
	t.Helper()
	c, k := e.ca.Issue(t, "ui", []string{"ui.test"}, serial)
	testpki.WriteFile(t, e.certFile, c)
	testpki.WriteFile(t, e.keyFile, k)
}

func dialPing(t *testing.T, addr string) (string, error) {
	t.Helper()
	opts, err := DialOptions()
	if err != nil {
		t.Fatal(err)
	}
	opts = append(opts, redis.DialConnectTimeout(3*time.Second), redis.DialReadTimeout(3*time.Second))
	c, err := redis.Dial("tcp", addr, opts...)
	if err != nil {
		return "", err
	}
	defer c.Close()
	return redis.String(c.Do("PING"))
}

func TestDialOptionsTLSPingPresentsClientCert(t *testing.T) {
	e := setup(t)
	got, err := dialPing(t, e.srv.addr)
	if err != nil || got != "PONG" {
		t.Fatalf("PING = %q, %v; want PONG", got, err)
	}
	if s := e.srv.serials(); len(s) != 1 || s[0] != 1 {
		t.Fatalf("server saw client cert serials %v, want [1]", s)
	}
}

func TestDialOptionsTLSWrongServerNameFails(t *testing.T) {
	e := setup(t)
	configuration.GetConfiguration().RedisTLSServerName = "not-redis.test"
	if got, err := dialPing(t, e.srv.addr); err == nil {
		t.Fatalf("expected verification error, got %q", got)
	}
}

func TestDialOptionsTLSServerNameDefaultsToAddressHost(t *testing.T) {
	e := setup(t)
	configuration.GetConfiguration().RedisTLSServerName = ""
	// address host is 127.0.0.1, which is not in the server cert SANs
	if got, err := dialPing(t, e.srv.addr); err == nil {
		t.Fatalf("expected verification error for IP host, got %q", got)
	}
}

func TestDialOptionsMissingCAFileFails(t *testing.T) {
	e := setup(t)
	configuration.GetConfiguration().RedisTLSCAFile = filepath.Join(e.dir, "nope.crt")
	if _, err := DialOptions(); err == nil {
		t.Fatal("expected error for nonexistent CA file")
	}
}

func TestDialOptionsTLSRejectsServerFromOtherCA(t *testing.T) {
	e := setup(t)
	other := testpki.NewCA(t)
	testpki.WriteFile(t, e.caFile, other.PEM)
	if got, err := dialPing(t, e.srv.addr); err == nil {
		t.Fatalf("expected error when CA does not match, got %q", got)
	}
}

func TestDialOptionsTLSClientCertRotation(t *testing.T) {
	e := setup(t)
	if _, err := dialPing(t, e.srv.addr); err != nil {
		t.Fatal(err)
	}
	e.writeClient(t, 2)
	if _, err := dialPing(t, e.srv.addr); err != nil {
		t.Fatal(err)
	}
	s := e.srv.serials()
	if len(s) != 2 || s[0] != 1 || s[1] != 2 {
		t.Fatalf("server saw client cert serials %v, want [1 2]", s)
	}
}

func TestDialOptionsTLSOffIsPlain(t *testing.T) {
	setup(t)
	configuration.GetConfiguration().RedisTLS = false
	opts, err := DialOptions()
	if err != nil || len(opts) != 0 {
		t.Fatalf("opts=%d err=%v, want no options", len(opts), err)
	}
}
