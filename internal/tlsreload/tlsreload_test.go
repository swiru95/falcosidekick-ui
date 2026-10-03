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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/falcosecurity/falcosidekick-ui/configuration"
)

const (
	certBlockType       = "CERTIFICATE"
	privateKeyBlockType = "PRIVATE KEY"
	testLocalName       = "test.local"
	testLocalName2      = "test2.local"
)

func init() {
	// Initialize configuration for tests
	configuration.CreateConfiguration()
	config := configuration.GetConfiguration()
	config.LogLevel = "info"
}

// generateTestCertificate generates a self-signed certificate for testing.
func generateTestCertificate(commonName string, dnsNames []string) (certPEM, keyPEM []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:              dnsNames,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: certBlockType, Bytes: certDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{Type: privateKeyBlockType, Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// TestReloaderLoadsInitialCert tests that reloader loads the initial certificate.
func TestReloaderLoadsInitialCert(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	// Generate initial certificate
	certPEM, keyPEM, err := generateTestCertificate(testLocalName, []string{testLocalName})
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Create reloader
	reloader, err := New(certFile, keyFile, 1*time.Second)
	if err != nil {
		t.Fatalf("failed to create reloader: %v", err)
	}

	// Get certificate
	cert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get certificate: %v", err)
	}

	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
}

// TestReloaderDetectsChanges tests that reloader detects certificate changes.
func TestReloaderDetectsChanges(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	// Generate initial certificate
	certPEM, keyPEM, err := generateTestCertificate(testLocalName, []string{testLocalName})
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Create reloader with 0 interval for testing
	reloader, err := New(certFile, keyFile, 0)
	if err != nil {
		t.Fatalf("failed to create reloader: %v", err)
	}

	// Get initial certificate
	initialCert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get initial certificate: %v", err)
	}

	// Wait to ensure time has passed
	time.Sleep(100 * time.Millisecond)

	// Generate new certificate
	newCertPEM, newKeyPEM, err := generateTestCertificate(testLocalName2, []string{testLocalName2})
	if err != nil {
		t.Fatalf("failed to generate new certificate: %v", err)
	}

	if err := os.WriteFile(certFile, newCertPEM, 0600); err != nil {
		t.Fatalf("failed to write new cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, newKeyPEM, 0600); err != nil {
		t.Fatalf("failed to write new key file: %v", err)
	}

	// Get certificate again - should get the new one
	newCert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get new certificate: %v", err)
	}

	// Verify certificates are different (by comparing raw certificate data)
	if len(initialCert.Certificate) == 0 || len(newCert.Certificate) == 0 {
		t.Fatal("expected non-empty certificate chains")
	}

	if string(initialCert.Certificate[0]) == string(newCert.Certificate[0]) {
		t.Error("expected different certificates after reload")
	}
}

// TestReloaderKeepsPreviousOnError tests that reloader keeps serving old cert on errors.
func TestReloaderKeepsPreviousOnError(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	// Generate initial certificate
	certPEM, keyPEM, err := generateTestCertificate(testLocalName, []string{testLocalName})
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Create reloader with 0 interval for testing
	reloader, err := New(certFile, keyFile, 0)
	if err != nil {
		t.Fatalf("failed to create reloader: %v", err)
	}

	// Get initial certificate
	initialCert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get initial certificate: %v", err)
	}

	// Wait
	time.Sleep(100 * time.Millisecond)

	// Write corrupt data to cert file
	if err := os.WriteFile(certFile, []byte("corrupt"), 0600); err != nil {
		t.Fatalf("failed to write corrupt cert file: %v", err)
	}

	// Get certificate again - should still get the old one
	cert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get certificate: %v", err)
	}

	// Should return the original cert (same pointer)
	if cert != initialCert {
		t.Error("expected same certificate after failed reload")
	}
}

// TestGetClientCertificate tests the GetClientCertificate method
func TestGetClientCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	// Generate initial certificate
	certPEM, keyPEM, err := generateTestCertificate(testLocalName, []string{testLocalName})
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Create reloader
	reloader, err := New(certFile, keyFile, 1*time.Second)
	if err != nil {
		t.Fatalf("failed to create reloader: %v", err)
	}

	// Get client certificate
	cert, err := reloader.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get client certificate: %v", err)
	}

	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
}
