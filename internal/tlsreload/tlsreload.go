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

package tlsreload

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/falcosecurity/falcosidekick-ui/internal/utils"
)

// Reloader holds certificate file paths and cached certificate for hot-reloading.
type Reloader struct {
	certFile        string
	keyFile         string
	interval        time.Duration
	cachedCert      *tls.Certificate
	lastContentHash [sha256.Size]byte
	lastCheckTime   time.Time
	mu              sync.Mutex
}

// New creates a new certificate reloader and loads the initial certificate.
// It returns an error if the initial load fails.
func New(certFile, keyFile string, interval time.Duration) (*Reloader, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load initial certificate: %w", err)
	}

	r := &Reloader{
		certFile:   certFile,
		keyFile:    keyFile,
		interval:   interval,
		cachedCert: &cert,
	}

	// Compute initial content hash
	if err := r.updateContentHash(); err != nil {
		return nil, fmt.Errorf("failed to compute initial certificate hash: %w", err)
	}
	r.lastCheckTime = time.Now()

	return r, nil
}

// updateContentHash reads both cert and key files and computes their SHA-256 hash.
func (r *Reloader) updateContentHash() error {
	certData, err := os.ReadFile(r.certFile)
	if err != nil {
		return err
	}
	keyData, err := os.ReadFile(r.keyFile)
	if err != nil {
		return err
	}
	h := sha256.New()
	h.Write(certData)
	h.Write(keyData)
	copy(r.lastContentHash[:], h.Sum(nil))
	return nil
}

// GetCertificate implements the tls.Config.GetCertificate callback.
// It checks if certificate files have changed by content hash (at most once per interval) and reloads if needed.
func (r *Reloader) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if enough time has passed since last check
	if time.Since(r.lastCheckTime) < r.interval {
		return r.cachedCert, nil
	}

	r.lastCheckTime = time.Now()

	// Read both files and compute hash
	certData, err := os.ReadFile(r.certFile)
	if err != nil {
		// Keep previous cert and log error
		utils.WriteLog("error", fmt.Sprintf("failed to read certificate file: %v", err))
		return r.cachedCert, nil
	}
	keyData, err := os.ReadFile(r.keyFile)
	if err != nil {
		// Keep previous cert and log error
		utils.WriteLog("error", fmt.Sprintf("failed to read key file: %v", err))
		return r.cachedCert, nil
	}

	h := sha256.New()
	h.Write(certData)
	h.Write(keyData)
	var currentHash [sha256.Size]byte
	copy(currentHash[:], h.Sum(nil))

	// If content hasn't changed, return cached cert
	if currentHash == r.lastContentHash {
		return r.cachedCert, nil
	}

	// Try to load new certificate from the bytes just read
	newCert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		// Keep previous cert and log error
		utils.WriteLog("error", fmt.Sprintf("failed to reload TLS certificate: %v", err))
		return r.cachedCert, nil
	}

	// Chain-shrink guard: check if new chain has fewer certificates
	if len(newCert.Certificate) < len(r.cachedCert.Certificate) {
		utils.WriteLog("warning", fmt.Sprintf("TLS certificate reload skipped: new chain has %d certs, current has %d (partial write?)", len(newCert.Certificate), len(r.cachedCert.Certificate)))
		return r.cachedCert, nil
	}

	// Update cached cert and content hash
	r.cachedCert = &newCert
	copy(r.lastContentHash[:], currentHash[:])

	utils.WriteLog("info", "TLS certificate reloaded")

	return r.cachedCert, nil
}

// GetClientCertificate implements the tls.Config.GetClientCertificate callback.
// It checks if certificate files have changed by content hash (at most once per interval) and reloads if needed.
func (r *Reloader) GetClientCertificate(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if enough time has passed since last check
	if time.Since(r.lastCheckTime) < r.interval {
		return r.cachedCert, nil
	}

	r.lastCheckTime = time.Now()

	// Read both files and compute hash
	certData, err := os.ReadFile(r.certFile)
	if err != nil {
		// Keep previous cert and log error
		utils.WriteLog("error", fmt.Sprintf("failed to read certificate file: %v", err))
		return r.cachedCert, nil
	}
	keyData, err := os.ReadFile(r.keyFile)
	if err != nil {
		// Keep previous cert and log error
		utils.WriteLog("error", fmt.Sprintf("failed to read key file: %v", err))
		return r.cachedCert, nil
	}

	h := sha256.New()
	h.Write(certData)
	h.Write(keyData)
	var currentHash [sha256.Size]byte
	copy(currentHash[:], h.Sum(nil))

	// If content hasn't changed, return cached cert
	if currentHash == r.lastContentHash {
		return r.cachedCert, nil
	}

	// Try to load new certificate from the bytes just read
	newCert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		// Keep previous cert and log error
		utils.WriteLog("error", fmt.Sprintf("failed to reload TLS client certificate: %v", err))
		return r.cachedCert, nil
	}

	// Chain-shrink guard: check if new chain has fewer certificates
	if len(newCert.Certificate) < len(r.cachedCert.Certificate) {
		utils.WriteLog("warning", fmt.Sprintf("TLS client certificate reload skipped: new chain has %d certs, current has %d (partial write?)", len(newCert.Certificate), len(r.cachedCert.Certificate)))
		return r.cachedCert, nil
	}

	// Update cached cert and content hash
	r.cachedCert = &newCert
	copy(r.lastContentHash[:], currentHash[:])

	utils.WriteLog("info", "TLS client certificate reloaded")

	return r.cachedCert, nil
}
