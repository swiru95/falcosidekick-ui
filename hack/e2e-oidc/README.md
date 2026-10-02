# OIDC end-to-end security checks (QA, optional)

`e2e.py` drives a real Keycloak with a real login form (scripted HTTP client + cookie jar) against
falcosidekick-ui in `oidc` mode with `INGEST_AUTH=oidc`, and prints status + body evidence for every
positive and negative (fail-closed) case. It is environment specific (paths under `/tmp/e2e`) and is
not run by CI.

Layout used when it was written:
* throwaway CA + certs for `kc.test` and `ui.test` in `/tmp/e2e/pki` (hosts entries -> 127.0.0.1)
* Keycloak 26.x `start-dev` over TLS on :8444 (`kc-start.sh`; the distribution came from Maven Central
  because quay.io was blocked by the sandbox proxy), configured by `kc-setup.sh`
* redis-stack-server on :6379
* falcosidekick-ui on :2802 started by `ui-start.sh` (oidc login + ingest auth, `OIDC_CA_FILE` = the CA, no
  `INSECURE_ALLOW_HTTP`) behind a tiny TLS reverse proxy on :2803 (`tlsproxy.go.txt`, rename to main.go) so
  the `__Host-` cookies work
* run with `NO_PROXY=kc.test,ui.test,localhost,127.0.0.1 python3 e2e.py` (needs `requests`, `cryptography`)
