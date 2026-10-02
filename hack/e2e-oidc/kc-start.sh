#!/bin/bash
export KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin
export JAVA_TOOL_OPTIONS=""
cd /tmp/e2e/keycloak-26.6.0
exec bin/kc.sh start-dev --https-port=8444 --http-enabled=false --hostname=https://kc.test:8444 \
  --https-certificate-file=/tmp/e2e/pki/kc.test.pem --https-certificate-key-file=/tmp/e2e/pki/kc.test.key
