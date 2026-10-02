#!/bin/bash
# Configure a throwaway Keycloak (realm falco) for the OIDC e2e checks. See README.md.
set -e
export JAVA_TOOL_OPTIONS=""
K=/tmp/e2e/keycloak-26.6.0/bin/kcadm.sh
keytool -importcert -noprompt -alias qa -file /tmp/e2e/pki/ca.pem -keystore /tmp/e2e/pki/ca.jks -storepass changeit
$K config truststore --trustpass changeit /tmp/e2e/pki/ca.jks
$K config credentials --server https://kc.test:8444 --realm master --user admin --password admin
$K create realms -s realm=falco -s enabled=true
$K create groups -r falco -s name=falco-viewers
for u in alice bob; do
  $K create users -r falco -s username=$u -s enabled=true -s email=$u@example.test -s emailVerified=true -s firstName=$u -s lastName=x
  $K set-password -r falco --username $u --new-password ${u}pw
done
GID=$($K get groups -r falco -q search=falco-viewers --fields id --format csv --noquotes)
AID=$($K get users -r falco -q username=alice --fields id --format csv --noquotes)
$K update users/$AID/groups/$GID -r falco -s realm=falco -s userId=$AID -s groupId=$GID -n
$K create clients -r falco -f - <<'JSON'
{"clientId":"falcosidekick-ui","enabled":true,"publicClient":false,"secret":"ui-secret-xyz","standardFlowEnabled":true,"directAccessGrantsEnabled":true,
 "redirectUris":["https://ui.test:2803/api/v1/auth/oidc/callback"],
 "attributes":{"pkce.code.challenge.method":"S256","post.logout.redirect.uris":"https://ui.test:2803/"},
 "protocolMappers":[{"name":"groups","protocol":"openid-connect","protocolMapper":"oidc-group-membership-mapper","config":{"claim.name":"groups","full.path":"false","id.token.claim":"true","access.token.claim":"true","userinfo.token.claim":"true"}}]}
JSON
mk() { # clientId audience
$K create clients -r falco -f - <<JSON
{"clientId":"$1","enabled":true,"publicClient":false,"secret":"$1-secret","standardFlowEnabled":false,"serviceAccountsEnabled":true,
 "protocolMappers":[{"name":"aud","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.custom.audience":"$2","access.token.claim":"true","id.token.claim":"false"}}]}
JSON
}
mk falcosidekick falcosidekick-ui-ingest   # allowed client
mk rogue         falcosidekick-ui-ingest   # valid token, client not in allow-list
mk wrongaud      something-else            # wrong audience
