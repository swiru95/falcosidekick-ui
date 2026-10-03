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

package oidc

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
	connPoolMutex     sync.Mutex
	connPool          *redis.Pool
	oidcTLSReloader   *tlsreload.Reloader
	oidcTLSReloaderMu sync.Mutex
)

// resolveRedisAddr normalizes a Redis address string to host:port format.
// Examples:
// - "redis-master" → "redis-master:6379"
// - ":6380" → "localhost:6380"
// - "h:1" → "h:1"
// - "" → "localhost:6379"
func resolveRedisAddr(s string) string {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		// If SplitHostPort fails, the input has no port; use the input as host
		host = s
		port = "6379"
	}
	if host == "" {
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}

// getRedisTLSDialOptions returns TLS-specific dial options for Redis
func getRedisTLSDialOptions(config *configuration.Configuration) ([]redis.DialOption, error) {
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
		oidcTLSReloaderMu.Lock()
		if oidcTLSReloader == nil {
			reloader, err := tlsreload.New(config.RedisTLSCertFile, config.RedisTLSKeyFile, 30*time.Second)
			if err != nil {
				oidcTLSReloaderMu.Unlock()
				return nil, fmt.Errorf("failed to create Redis TLS client cert reloader: %w", err)
			}
			oidcTLSReloader = reloader
		}
		oidcTLSReloaderMu.Unlock()
		tlsConfig.GetClientCertificate = oidcTLSReloader.GetClientCertificate
	}

	dialOpts := make([]redis.DialOption, 0, 2)
	dialOpts = append(dialOpts, redis.DialUseTLS(true))
	dialOpts = append(dialOpts, redis.DialTLSConfig(tlsConfig))
	return dialOpts, nil
}

// GetRedisConn returns a redis connection from the pool.
// Uses the same Redis server as configured in the application.
func GetRedisConn() (redis.Conn, error) {
	pool, err := getConnPool()
	if err != nil {
		return nil, err
	}
	return pool.Get(), nil
}

// getConnPool returns or creates the Redis connection pool.
func getConnPool() (*redis.Pool, error) {
	connPoolMutex.Lock()
	defer connPoolMutex.Unlock()

	if connPool != nil {
		return connPool, nil
	}

	// Import the helper from the redis package - but we're in oidc package
	// We'll duplicate the logic here since we're in a different package
	// and need to maintain separation of concerns
	config := configuration.GetConfiguration()
	var dialOpts []redis.DialOption

	if config.RedisUsername != "" {
		dialOpts = append(dialOpts, redis.DialUsername(config.RedisUsername))
	}

	if config.RedisPassword != "" {
		dialOpts = append(dialOpts, redis.DialPassword(config.RedisPassword))
	}

	// Add timeout options
	dialOpts = append(dialOpts,
		redis.DialConnectTimeout(5*time.Second),
		redis.DialReadTimeout(5*time.Second),
		redis.DialWriteTimeout(5*time.Second),
	)

	// Add TLS options if Redis TLS is enabled
	if config.RedisTLS {
		var tlsDialOpts []redis.DialOption
		tlsDialOpts, err := getRedisTLSDialOptions(config)
		if err != nil {
			return nil, fmt.Errorf("failed to configure Redis TLS: %w", err)
		}
		dialOpts = append(dialOpts, tlsDialOpts...)
	}

	// Resolve the Redis address using the helper
	serverAddress := resolveRedisAddr(config.RedisServer)

	connPool = &redis.Pool{
		MaxIdle:     16,
		MaxActive:   32,
		Wait:        true,
		IdleTimeout: 300 * time.Second,
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", serverAddress, dialOpts...)
			if err != nil {
				return nil, fmt.Errorf("failed to dial redis: %w", err)
			}
			return c, nil
		},
	}

	return connPool, nil
}
