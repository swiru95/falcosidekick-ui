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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/falcosecurity/falcosidekick-ui/configuration"
	"github.com/falcosecurity/falcosidekick-ui/internal/tlsreload"
	"github.com/gomodule/redigo/redis"
)

var (
	tlsReloader   *tlsreload.Reloader
	tlsReloaderMu sync.Mutex
)

// DialOptions returns dial options configured for TLS if enabled, with username/password
// and a singleton mutex-guarded client-cert reloader.
func DialOptions() ([]redis.DialOption, error) {
	config := configuration.GetConfiguration()
	var dialOpts []redis.DialOption

	if config.RedisUsername != "" {
		dialOpts = append(dialOpts, redis.DialUsername(config.RedisUsername))
	}

	if config.RedisPassword != "" {
		dialOpts = append(dialOpts, redis.DialPassword(config.RedisPassword))
	}

	if config.RedisTLS {
		// Build TLS config
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		// Load CA certificate if provided
		if config.RedisTLSCAFile != "" {
			caCert, err := os.ReadFile(config.RedisTLSCAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read Redis TLS CA file: %w", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse Redis TLS CA file")
			}
			tlsConfig.RootCAs = caCertPool
		}

		// Set server name for verification (defaults to host part of Redis address)
		if config.RedisTLSServerName != "" {
			tlsConfig.ServerName = config.RedisTLSServerName
		} else {
			host, _, err := net.SplitHostPort(resolveRedisAddr(config.RedisServer))
			if err != nil {
				host = config.RedisServer
			}
			tlsConfig.ServerName = host
		}

		// Load client certificate if provided
		if config.RedisTLSCertFile != "" && config.RedisTLSKeyFile != "" {
			tlsReloaderMu.Lock()
			if tlsReloader == nil {
				reloader, err := tlsreload.New(config.RedisTLSCertFile, config.RedisTLSKeyFile, 30*time.Second)
				if err != nil {
					tlsReloaderMu.Unlock()
					return nil, fmt.Errorf("failed to create Redis TLS client cert reloader: %w", err)
				}
				tlsReloader = reloader
			}
			tlsReloaderMu.Unlock()
			tlsConfig.GetClientCertificate = tlsReloader.GetClientCertificate
		}

		dialOpts = append(dialOpts, redis.DialUseTLS(true))
		dialOpts = append(dialOpts, redis.DialTLSConfig(tlsConfig))
	}

	return dialOpts, nil
}
