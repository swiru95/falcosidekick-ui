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

// Package server holds the HTTP wiring of falcosidekick-ui (routes, ingestion
// mTLS middleware, HTTPS server construction) so main and tests share it.
package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/falcosecurity/falcosidekick-ui/configuration"
	"github.com/falcosecurity/falcosidekick-ui/internal/api"
	"github.com/falcosecurity/falcosidekick-ui/internal/auth"
	"github.com/falcosecurity/falcosidekick-ui/internal/oidc"
	"github.com/falcosecurity/falcosidekick-ui/internal/tlsreload"
	"github.com/falcosecurity/falcosidekick-ui/internal/utils"
	echo "github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	echoSwagger "github.com/swaggo/echo-swagger"
)

// AddEvent is the route name of the ingestion endpoints.
const AddEvent = "add-event"

const (
	routeNameAuthMe       = "auth-me"
	routeNameAuthenticate = "authenticate"
)

// ReloadInterval is how often the HTTPS server certificate files are checked
// for changes. Tests lower it.
var ReloadInterval = 30 * time.Second

// ParseAllowedSANs splits a comma list, trimming blanks and dropping empties.
func ParseAllowedSANs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// RegisterRoutes registers every route on e based on the current configuration.
// ingest is the handler serving the ingestion endpoints.
func RegisterRoutes(e *echo.Echo, ingest echo.HandlerFunc) {
	config := configuration.GetConfiguration()

	e.GET("/docs/*", echoSwagger.WrapHandler)
	e.GET("/docs", func(c echo.Context) error {
		return c.Redirect(http.StatusPermanentRedirect, "docs/")
	})
	e.Static("/*", "frontend/dist").Name = "webui-home"

	apiRoute := e.Group("/api/v1")

	switch config.AuthMode {
	case configuration.AuthModeOIDC:
		oidc.RegisterRoutes(apiRoute)

	case configuration.AuthModeNone:
		apiRoute.GET("/auth/me", oidc.Me).Name = routeNameAuthMe
		apiRoute.POST("/auth", api.Authenticate).Name = routeNameAuthenticate
		apiRoute.POST("/authenticate", api.Authenticate).Name = routeNameAuthenticate

	default: // basic mode
		apiRoute.Use(middleware.BasicAuthWithConfig(middleware.BasicAuthConfig{
			Skipper: func(c echo.Context) bool {
				if configuration.GetConfiguration().DisableAuth {
					return true
				}
				if c.Request().Method == "POST" {
					return true
				}
				if c.Path() == "/api/v1/healthz" {
					return true
				}
				if c.Path() == "/api/v1/auth/me" {
					return true
				}
				return false
			},
			Validator: auth.ValidateCredentials,
		}))

		apiRoute.GET("/auth/me", oidc.Me).Name = routeNameAuthMe
		apiRoute.POST("/auth", api.Authenticate).Name = routeNameAuthenticate
		apiRoute.POST("/authenticate", api.Authenticate).Name = routeNameAuthenticate
	}

	// Ingest middleware slice (empty when no ingest protection is configured)
	var ingestMW []echo.MiddlewareFunc
	if config.IngestAuth == configuration.AuthModeOIDC {
		ingestMW = append(ingestMW, oidc.IngestBearerMiddleware())
	}
	if sans := ParseAllowedSANs(config.IngestMTLSAllowedSANs); len(sans) > 0 {
		ingestMW = append(ingestMW, IngestMTLSMiddleware(sans))
	}

	e.POST("/", ingest, ingestMW...).Name = AddEvent
	apiRoute.POST("/", ingest, ingestMW...).Name = AddEvent

	apiRoute.GET("/config", api.GetConfiguration).Name = "get-configuration"
	apiRoute.GET("/configuration", api.GetConfiguration).Name = "get-configuration"
	apiRoute.GET("/version", api.GetVersionInfo).Name = "get-version"
	apiRoute.GET("/healthz", api.Healthz).Name = "healthz"
	apiRoute.GET("/outputs", api.GetOutputs).Name = "list-outputs"

	eventsRoute := apiRoute.Group("/events")
	eventsRoute.POST("/add", ingest, ingestMW...).Name = AddEvent
	eventsRoute.GET("/count", api.CountEvent).Name = "count-events"
	eventsRoute.GET("/count/:groupby", api.CountByEvent).Name = "count-events-by"
	eventsRoute.GET("/search", api.Search).Name = "search-keys"
}

// IngestMTLSMiddleware requires a verified client certificate whose DNS SAN,
// URI SAN or CN exactly matches one of the allowed entries.
func IngestMTLSMiddleware(allowed []string) echo.MiddlewareFunc {
	loggedSANSets := make(map[string]bool)
	var mu sync.Mutex

	isAllowed := func(name string) bool {
		for _, a := range allowed {
			if name == a {
				return true
			}
		}
		return false
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			st := c.Request().TLS
			if st == nil || len(st.VerifiedChains) == 0 || len(st.PeerCertificates) == 0 {
				return c.JSON(http.StatusForbidden, map[string]string{"error": "client certificate required"})
			}
			leaf := st.PeerCertificates[0]

			var presented []string
			for _, n := range leaf.DNSNames {
				if isAllowed(n) {
					return next(c)
				}
				presented = append(presented, n)
			}
			for _, u := range leaf.URIs {
				if isAllowed(u.String()) {
					return next(c)
				}
				presented = append(presented, u.String())
			}
			if cn := leaf.Subject.CommonName; cn != "" {
				if isAllowed(cn) {
					return next(c)
				}
				presented = append(presented, cn)
			}

			key := fmt.Sprintf("%v", presented)
			mu.Lock()
			first := !loggedSANSets[key]
			loggedSANSets[key] = true
			mu.Unlock()
			if first {
				utils.WriteLog("warning", fmt.Sprintf("ingestion mTLS verification failed; presented SANs: %v", presented))
			}
			return c.JSON(http.StatusForbidden, map[string]string{"error": "client certificate SAN not allowed"})
		}
	}
}

// NewHTTPSServer builds the HTTPS server for handler h from the TLS settings
// in the configuration. Serve it with ListenAndServeTLS("", "") or
// ServeTLS(listener, "", "").
func NewHTTPSServer(h http.Handler, addr string) (*http.Server, error) {
	config := configuration.GetConfiguration()

	reloader, err := tlsreload.New(config.TLSCertFile, config.TLSKeyFile, ReloadInterval)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS cert reloader: %w", err)
	}
	tlsConfig := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: reloader.GetCertificate,
	}

	if config.TLSClientCAFile != "" {
		caPEM, err := os.ReadFile(config.TLSClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse client CA file")
		}
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		tlsConfig.ClientCAs = pool
	}

	return &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 30 * time.Second,
	}, nil
}
