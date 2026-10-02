#!/bin/bash
# usage: ui-start.sh [extra env as VAR=val ...]
[ -f /tmp/e2e/ui.pid ] && kill $(cat /tmp/e2e/ui.pid) 2>/dev/null; sleep 1
cd /home/user/falcosidekick-ui
env NO_PROXY=kc.test,ui.test,localhost,127.0.0.1 \
 FALCOSIDEKICK_UI_AUTH_MODE=oidc \
 FALCOSIDEKICK_UI_OIDC_ISSUER=https://kc.test:8444/realms/falco \
 FALCOSIDEKICK_UI_OIDC_CLIENT_ID=falcosidekick-ui \
 FALCOSIDEKICK_UI_OIDC_CLIENT_SECRET=ui-secret-xyz \
 FALCOSIDEKICK_UI_OIDC_REDIRECT_URL=https://ui.test:2803/api/v1/auth/oidc/callback \
 FALCOSIDEKICK_UI_OIDC_ALLOWED_GROUPS=falco-viewers \
 FALCOSIDEKICK_UI_OIDC_CA_FILE=/tmp/e2e/pki/ca.pem \
 FALCOSIDEKICK_UI_OIDC_POST_LOGOUT_REDIRECT_URL=https://ui.test:2803/ \
 FALCOSIDEKICK_UI_INGEST_AUTH=oidc \
 FALCOSIDEKICK_UI_INGEST_OIDC_ISSUER=https://kc.test:8444/realms/falco \
 FALCOSIDEKICK_UI_INGEST_OIDC_AUDIENCE=falcosidekick-ui-ingest \
 FALCOSIDEKICK_UI_INGEST_OIDC_ALLOWED_CLIENTS=falcosidekick \
 FALCOSIDEKICK_UI_INGEST_OIDC_CA_FILE=/tmp/e2e/pki/ca.pem \
 FALCOSIDEKICK_UI_LOGLEVEL=debug \
"$@" /tmp/e2e/ui-bin > /tmp/e2e/ui.log 2>&1 &
echo $! > /tmp/e2e/ui.pid
