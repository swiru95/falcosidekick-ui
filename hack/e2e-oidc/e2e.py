#!/usr/bin/env python3
"""E2E security checks for falcosidekick-ui OIDC (login + ingestion) against a real Keycloak.
Expects: Keycloak https://kc.test:8444 (realm falco), UI behind TLS proxy https://ui.test:2803,
direct UI http://127.0.0.1:2802, CA at /tmp/e2e/pki/ca.pem. Prints evidence (status + body) per case."""
import os, re, sys, json, time, base64, hmac, hashlib, html, uuid, datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
os.environ["NO_PROXY"] = "kc.test,ui.test,localhost,127.0.0.1"
os.environ["REQUESTS_CA_BUNDLE"] = "/tmp/e2e/pki/ca.pem"
import requests
CA = "/tmp/e2e/pki/ca.pem"
KC = "https://kc.test:8444/realms/falco"
UI = "https://ui.test:2803"
UIDIRECT = "http://127.0.0.1:2802"
RESULTS = []

def rec(name, ok, evidence):
    RESULTS.append((name, ok, evidence))
    print(("PASS" if ok else "FAIL"), "|", name, "|", evidence.replace("\n", " ")[:400])

def S():
    s = requests.Session(); s.verify = CA; return s

def body(r, n=160):
    return (r.text or "")[:n].replace("\n", " ")

def kc_login_form(s, auth_url, user, pw):
    r = s.get(auth_url, allow_redirects=False)
    if r.status_code != 200:
        return r
    m = re.search(r'action="([^"]+)"', r.text)
    act = html.unescape(m.group(1))
    return s.post(act, data={"username": user, "password": pw, "credentialId": ""}, allow_redirects=False)

def start_flow(s):
    """GET /login at the UI; returns (login_resp, authorize_url)"""
    r = s.get(UI + "/api/v1/auth/oidc/login", allow_redirects=False)
    return r, r.headers.get("Location")

def do_login(user, pw):
    s = S()
    r, au = start_flow(s)
    r2 = kc_login_form(s, au, user, pw)
    return s, r, au, r2

def cc_token(client, secret=None, extra=None):
    d = {"grant_type": "client_credentials", "client_id": client, "client_secret": secret or f"{client}-secret"}
    r = requests.post(KC + "/protocol/openid-connect/token", data=d, verify=CA)
    return r.json()["access_token"]

def b64(d): return base64.urlsafe_b64encode(d).rstrip(b"=").decode()
def unb64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

EVENT = lambda: {"outputs": ["webui"], "event": {"uuid": str(uuid.uuid4()), "output": "e2e test event", "priority": "Warning", "rule": "E2E Rule",
         "time": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), "source": "syscall", "hostname": "e2ehost",
         "output_fields": {"a": "b"}, "tags": ["e2e"]}}

def ingest(token, path="/api/v1/events/add", base=UIDIRECT, hdr=None, params=None, method="POST"):
    h = {"Content-Type": "application/json"}
    if token is not None: h["Authorization"] = "Bearer " + token
    if hdr: h.update(hdr)
    return requests.request(method, base + path, json=EVENT(), headers=h, params=params, verify=CA)

def main():
    # ---------- unauthenticated GETs
    for p in ["/api/v1/events/search", "/api/v1/configuration", "/api/v1/config", "/api/v1/outputs", "/api/v1/version",
              "/api/v1/events/count", "/api/v1/events/count/rule", "/api/v1/nonexistent"]:
        r = requests.get(UI + p, verify=CA)
        ok = r.status_code == 401 and '"error":"unauthenticated"' in r.text and len(r.text) < 60
        rec(f"unauth GET {p} -> 401, no data", ok, f"status={r.status_code} body={body(r)!r}")
    r = requests.get(UI + "/api/v1/healthz", verify=CA); rec("healthz public", r.status_code == 200, f"status={r.status_code} body={body(r)!r}")
    r = requests.get(UI + "/api/v1/auth/me", verify=CA)
    rec("auth/me unauth", r.status_code == 200 and '"authenticated":false' in r.text and r.headers.get("Cache-Control") == "no-store", f"status={r.status_code} body={body(r)!r} CC={r.headers.get('Cache-Control')}")
    # other methods on protected routes
    for m, p in [("POST", "/api/v1/auth"), ("POST", "/api/v1/authenticate")]:
        r = requests.request(m, UI + p, verify=CA)
        rec(f"{m} {p} in oidc mode -> 404", r.status_code == 404, f"status={r.status_code} body={body(r)!r}")
    for m in ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
        r = requests.request(m, UI + "/api/v1/events/search", verify=CA)
        rec(f"unauth {m} /api/v1/events/search not 2xx", r.status_code >= 400, f"status={r.status_code} body={body(r)!r}")
    # path tricks
    for p in ["//api/v1/events/search", "/api/v1/events/search/", "/api/v1/events//search", "/api/v1/../api/v1/events/search", "/api/v1/auth/me/../../events/search", "/API/v1/events/search", "/api/v1/events/search%2f", "/api/v1/healthz/../events/search", "/api/v1/auth/oidc/callback/../../events/search"]:
        r = requests.get(UI + p, verify=CA)
        rec(f"unauth path trick {p!r} not 2xx", r.status_code >= 400 and "results" not in r.text, f"status={r.status_code} body={body(r)!r}")

    # ---------- login flow params
    s = S(); r, au = start_flow(s)
    q = parse_qs(urlparse(au).query)
    rec("login 302 + no-store", r.status_code == 302 and r.headers.get("Cache-Control") == "no-store", f"status={r.status_code} CC={r.headers.get('Cache-Control')}")
    rec("authorize URL has S256 only", q.get("code_challenge_method") == ["S256"] and len(q.get("code_challenge", [""])[0]) == 43, f"method={q.get('code_challenge_method')} chal_len={len(q.get('code_challenge',[''])[0])}")
    rec("authorize URL has state+nonce+client_id+scope+redirect_uri", all(k in q for k in ["state", "nonce", "client_id", "scope", "redirect_uri", "response_type"]) and "openid" in q["scope"][0], f"keys={sorted(q)} scope={q.get('scope')} redirect={q.get('redirect_uri')}")
    sc = r.headers.get("Set-Cookie", "")
    rec("flow cookie attrs", "__Host-fsui_oidc_flow=" in sc and "HttpOnly" in sc and "Secure" in sc and "SameSite=Lax" in sc and "Path=/" in sc and "Domain" not in sc, sc)
    flow_cookie_val = s.cookies.get("__Host-fsui_oidc_flow")
    rec("flow cookie value independent of state (flow ID != state)", flow_cookie_val != q["state"][0], f"cookie==state? {flow_cookie_val == q['state'][0]}")
    # Keycloak PKCE enforcement
    base = au.split("?")[0]
    q2 = {k: v[0] for k, v in q.items() if k not in ("code_challenge", "code_challenge_method")}
    r = requests.get(base + "?" + urlencode(q2), verify=CA, allow_redirects=False)
    rec("Keycloak rejects authz request without PKCE", r.status_code in (302, 400) and ("error" in r.headers.get("Location", "") or "code_challenge" in r.text.lower() or r.status_code == 400), f"status={r.status_code} loc={r.headers.get('Location','')[:200]} body={body(r,100)!r}")
    q3 = dict(q2); q3["code_challenge"] = q["code_challenge"][0]; q3["code_challenge_method"] = "plain"
    r = requests.get(base + "?" + urlencode(q3), verify=CA, allow_redirects=False)
    rec("Keycloak rejects PKCE plain", r.status_code in (302, 400) and ("error" in r.headers.get("Location", "") or r.status_code == 400), f"status={r.status_code} loc={r.headers.get('Location','')[:200]} body={body(r,100)!r}")
    # open redirect attempts at login
    s2 = S(); r = s2.get(UI + "/api/v1/auth/oidc/login?redirect=https://evil.test&next=//evil.test&return_to=https://evil.test&redirect_uri=https://evil.test", allow_redirects=False)
    rec("login ignores user redirect params", "evil.test" not in r.headers.get("Location", ""), f"loc={r.headers.get('Location','')[:150]}")

    # ---------- positive login alice
    s, r, au, r2 = do_login("alice", "alicepw")
    cb = r2.headers.get("Location")
    rec("alice authenticates at Keycloak -> callback redirect incl iss", r2.status_code == 302 and cb.startswith(UI + "/api/v1/auth/oidc/callback?") and "iss=" in cb, f"status={r2.status_code} loc={(cb or '')[:90]}...")
    # keep a copy of the flow cookie for replay
    flow_cookie = s.cookies.get("__Host-fsui_oidc_flow")
    r3 = s.get(cb, allow_redirects=False)
    hdrs = r3.raw.headers.getlist("Set-Cookie")
    rec("callback -> 302 to app base (no open redirect)", r3.status_code == 302 and r3.headers.get("Location") == UI, f"status={r3.status_code} loc={r3.headers.get('Location')}")
    sess = [h for h in hdrs if h.startswith("__Host-fsui_session=")]
    rec("session cookie attrs HttpOnly Secure Lax Path=/ no Domain", bool(sess) and all(x in sess[0] for x in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"]) and "Domain" not in sess[0], sess[0][:25] + "..." + sess[0].split(";",1)[1] if sess else str(hdrs))
    flowclr = [h for h in hdrs if h.startswith("__Host-fsui_oidc_flow=")]
    rec("flow cookie cleared with Secure (required to delete __Host- cookie in browsers)", bool(flowclr) and "Secure" in flowclr[0], str(flowclr))
    cookie = s.cookies.get("__Host-fsui_session")
    me = s.get(UI + "/api/v1/auth/me")
    rec("auth/me authenticated as alice", '"authenticated":true' in me.text and '"username":"alice"' in me.text, body(me))
    for p in ["/api/v1/events/search", "/api/v1/outputs", "/api/v1/version", "/api/v1/events/count", "/api/v1/events/count/rule", "/api/v1/configuration"]:
        r = s.get(UI + p); rec(f"alice GET {p} -> 200", r.status_code == 200, f"status={r.status_code} body={body(r,80)!r}")
    conf = s.get(UI + "/api/v1/configuration").text
    leaks = [x for x in ["ui-secret-xyz", "OIDC", "client_secret", "Secret", "/tmp/e2e"] if x in conf]
    rec("configuration does not leak secrets/paths", not leaks and "admin:admin" not in conf, f"leaks={leaks} body={conf[:400]}")
    # redis check
    import subprocess
    keys = subprocess.run(["docker", "exec", "qa-redis", "redis-cli", "--scan", "--pattern", "fsui:*"], capture_output=True, text=True).stdout.split()
    rec("redis keys hashed (no raw cookie in key)", all(cookie not in k for k in keys) and len(keys) > 0, f"keys={keys}")
    for k in keys:
        if k.startswith("fsui:session:"):
            ttl = subprocess.run(["docker", "exec", "qa-redis", "redis-cli", "ttl", k], capture_output=True, text=True).stdout.strip()
            val = subprocess.run(["docker", "exec", "qa-redis", "redis-cli", "get", k], capture_output=True, text=True).stdout
            print("   session TTL", ttl, "keys in value:", sorted(json.loads(val).keys()))

    # replay of same callback URL, with the flow cookie (valid original cookie)
    s_r = S(); s_r.cookies.set("__Host-fsui_oidc_flow", flow_cookie, domain="ui.test", path="/", secure=True)
    r = s_r.get(cb, allow_redirects=False)
    rec("replay callback (same code+state+flow cookie) rejected, no session", "__Host-fsui_session" not in (r.headers.get("Set-Cookie") or "") and not (r.status_code == 302 and r.headers.get("Location") == UI), f"status={r.status_code} loc={r.headers.get('Location')} body={body(r,80)!r} set-cookie={r.headers.get('Set-Cookie')}")
    rec("replay: no session established", s_r.get(UI + "/api/v1/events/search").status_code == 401, "")

    # tampered state
    s_t, r, au, r2 = do_login("alice", "alicepw"); cb_t = r2.headers["Location"]
    p = urlparse(cb_t); qq = parse_qs(p.query); qq["state"] = [qq["state"][0][:-1] + ("A" if qq["state"][0][-1] != "A" else "B")]
    r = s_t.get(urlunparse(p._replace(query=urlencode({k: v[0] for k, v in qq.items()}))), allow_redirects=False)
    rec("tampered state -> 400", r.status_code == 400 and "__Host-fsui_session" not in (r.headers.get("Set-Cookie") or ""), f"status={r.status_code} body={body(r)!r} loc={r.headers.get('Location')}")
    r = s_t.get(cb_t, allow_redirects=False)
    rec("after tampered attempt flow is burnt: genuine callback now rejected", not (r.status_code == 302 and r.headers.get("Location") == UI), f"status={r.status_code} loc={r.headers.get('Location')} body={body(r)!r}")
    # state missing entirely
    s_t, r, au, r2 = do_login("alice", "alicepw"); cb_t = r2.headers["Location"]
    p = urlparse(cb_t); qq = {k: v[0] for k, v in parse_qs(p.query).items() if k != "state"}
    r = s_t.get(urlunparse(p._replace(query=urlencode(qq))), allow_redirects=False)
    rec("missing state -> 400", r.status_code == 400, f"status={r.status_code} body={body(r)!r}")
    # wrong iss
    s_t, r, au, r2 = do_login("alice", "alicepw"); cb_t = r2.headers["Location"]
    p = urlparse(cb_t); qq = {k: v[0] for k, v in parse_qs(p.query).items()}; qq["iss"] = "https://evil.test/realms/falco"
    r = s_t.get(urlunparse(p._replace(query=urlencode(qq))), allow_redirects=False)
    rec("wrong iss param -> 400", r.status_code == 400, f"status={r.status_code} body={body(r)!r}")
    # no flow cookie
    s_t, r, au, r2 = do_login("alice", "alicepw"); cb_t = r2.headers["Location"]
    s_n = S(); r = s_n.get(cb_t, allow_redirects=False)
    rec("callback without flow cookie -> 400", r.status_code == 400, f"status={r.status_code} body={body(r)!r}")
    # flow cookie from another login
    sA, _, _, rA = do_login("alice", "alicepw"); cbA = rA.headers["Location"]
    sB, _, _, rB = do_login("alice", "alicepw")
    rr = sB.get(cbA, allow_redirects=False)   # B's cookie + A's code/state
    rec("flow cookie from another login (B cookie, A callback) rejected", not (rr.status_code == 302 and rr.headers.get("Location") == UI), f"status={rr.status_code} loc={rr.headers.get('Location')} body={body(rr)!r}")
    # attacker-fixed session: pre-existing session cookie is deleted at login (fixation)
    sF, _, _, rF = do_login("alice", "alicepw")
    sF.cookies.set("__Host-fsui_session", cookie, domain="ui.test", path="/", secure=True)  # pre-existing 'alice' session
    rr = sF.get(rF.headers["Location"], allow_redirects=False)
    rec("fixation: new session id issued, old one deleted", sF.cookies.get("__Host-fsui_session") != cookie and requests.get(UI + "/api/v1/auth/me", cookies={"__Host-fsui_session": cookie}, verify=CA).json()["authenticated"] is False, f"status={rr.status_code}")
    # error param, reflected text
    sE, r, au, _ = do_login("alice", "alicepw") if False else (S(), None, None, None)
    r, au = start_flow(sE)
    rr = sE.get(UI + "/api/v1/auth/oidc/callback?error=%3Cscript%3Ealert(1)%3C/script%3E&error_description=%3Cscript%3E&state=x", allow_redirects=False)
    rec("IdP error not reflected", "script" not in rr.text and "script" not in rr.headers.get("Location", "") and rr.headers.get("Location", "").endswith("#/login?error=sso_failed"), f"status={rr.status_code} loc={rr.headers.get('Location')} body={body(rr)!r}")

    # ---------- bob forbidden
    sb, r, au, r2 = do_login("bob", "bobpw"); cbb = r2.headers["Location"]
    rb = sb.get(cbb, allow_redirects=False)
    rec("bob (no group) -> forbidden redirect, no session cookie", rb.status_code == 302 and rb.headers["Location"].endswith("#/login?error=forbidden") and "fsui_session" not in (rb.headers.get("Set-Cookie") or "") , f"status={rb.status_code} loc={rb.headers.get('Location')} set-cookie={rb.headers.get('Set-Cookie')}")
    rec("bob: no access to API", sb.get(UI + "/api/v1/events/search").status_code == 401 and sb.get(UI + "/api/v1/auth/me").json()["authenticated"] is False, "")
    # status code of forbidden: spec says 403 page/redirect; record
    # ---------- logout
    s, _, _, rl = do_login("alice", "alicepw"); s.get(rl.headers["Location"], allow_redirects=False); cookie = s.cookies.get("__Host-fsui_session")
    r = s.post(UI + "/api/v1/auth/logout")
    rec("logout without X-Requested-With -> 400 and session survives", r.status_code == 400 and s.get(UI + "/api/v1/auth/me").json()["authenticated"], f"status={r.status_code} body={body(r)!r}")
    r = s.post(UI + "/api/v1/auth/logout", headers={"X-Requested-With": "XMLHttpRequest", "Origin": "https://evil.test"})
    rec("logout with foreign Origin -> 400 and session survives", r.status_code == 400 and s.get(UI + "/api/v1/auth/me").json()["authenticated"], f"status={r.status_code} body={body(r)!r}")
    r = s.post(UI + "/api/v1/auth/logout", headers={"X-Requested-With": "XMLHttpRequest", "Origin": UI})
    lj = r.json() if r.status_code == 200 else {}
    rec("logout 200 + logout_url", r.status_code == 200 and "logout_url" in lj, f"status={r.status_code} body={body(r,500)!r}")
    lurl = lj.get("logout_url", "")
    rec("logout_url has id_token_hint, post_logout_redirect_uri, client_id", all(x in lurl for x in ["id_token_hint=", "post_logout_redirect_uri=", "client_id=falcosidekick-ui"]) and lurl.startswith(KC + "/protocol/openid-connect/logout?"), lurl[:200])
    scl = r.raw.headers.getlist("Set-Cookie")
    rec("logout expires session cookie with Secure+HttpOnly (browser-valid __Host- deletion)", bool(scl) and "Secure" in scl[0], str(scl))
    rec("old cookie after logout -> 401", requests.get(UI + "/api/v1/events/search", cookies={"__Host-fsui_session": cookie}, verify=CA).status_code == 401, "")
    # logout without cookie
    try:
        r = requests.post(UI + "/api/v1/auth/logout", headers={"X-Requested-With": "XMLHttpRequest", "Origin": UI}, verify=CA)
        rec("logout w/o session cookie works (spec: even if session expired)", r.status_code == 200, f"status={r.status_code} body={body(r)!r}")
    except Exception as e:
        rec("logout w/o session cookie works (spec: even if session expired)", False, f"exception {e!r}")
    # follow logout url at Keycloak
    if lurl:
        r = requests.get(lurl, verify=CA, allow_redirects=False)
        rec("Keycloak accepts logout_url", r.status_code in (200, 302) and "error" not in r.headers.get("Location", ""), f"status={r.status_code} loc={r.headers.get('Location')} body={body(r,100)!r}")

    # ---------- ingestion
    tok = cc_token("falcosidekick")
    r = ingest(tok); rec("ingest valid token -> 200", r.status_code == 200, f"status={r.status_code} body={body(r)!r}")
    for path, base in [("/", UIDIRECT), ("/api/v1/", UIDIRECT), ("/api/v1/events/add", UIDIRECT), ("/api/v1/events/add", UI)]:
        r = ingest(tok, path, base); rec(f"ingest valid token POST {path} via {base[:12]} -> 200", r.status_code == 200, f"status={r.status_code} body={body(r)!r}")
        r = ingest(None, path, base); rec(f"ingest no token POST {path} -> 401 WWW-Authenticate", r.status_code == 401 and "Bearer" in r.headers.get("WWW-Authenticate", ""), f"status={r.status_code} www={r.headers.get('WWW-Authenticate')} body={body(r)!r}")
    r = ingest(None, "/api/v1/events/add", params={"access_token": tok}); rec("token in query param ignored -> 401", r.status_code == 401, f"status={r.status_code} body={body(r)!r}")
    r = ingest(None, "/api/v1/events/add", hdr={"Authorization": "Basic YWRtaW46YWRtaW4="}); rec("Basic auth on ingest -> 401", r.status_code == 401, f"status={r.status_code} body={body(r)!r}")
    r = ingest(tok, "/api/v1/events/add", hdr={"Authorization": "bearer " + tok}); rec("lowercase bearer scheme accepted (RFC 6750)", r.status_code == 200, f"status={r.status_code}")
    r = ingest(tok + "x"); rec("tampered signature -> 401 invalid_token", r.status_code == 401 and "invalid_token" in r.headers.get("WWW-Authenticate", ""), f"status={r.status_code} www={r.headers.get('WWW-Authenticate')} body={body(r)!r}")
    rogue = cc_token("rogue"); r = ingest(rogue); rec("valid token for client not in allow-list (rogue) -> 401", r.status_code == 401, f"status={r.status_code} body={body(r)!r}")
    wa = cc_token("wrongaud"); r = ingest(wa); rec("wrong audience token -> 401", r.status_code == 401, f"status={r.status_code} body={body(r)!r}")
    # alice tokens
    d = {"grant_type": "password", "client_id": "falcosidekick-ui", "client_secret": "ui-secret-xyz", "username": "alice", "password": "alicepw", "scope": "openid"}
    tr = requests.post(KC + "/protocol/openid-connect/token", data=d, verify=CA).json()
    rec("(setup) obtained alice id_token/access_token via direct grant", "id_token" in tr and "access_token" in tr, str(list(tr.keys())))
    r = ingest(tr["id_token"]); rec("alice ID token as ingest bearer -> 401", r.status_code == 401, f"status={r.status_code} body={body(r)!r}")
    r = ingest(tr["access_token"]); rec("alice access token as ingest bearer -> 401", r.status_code == 401, f"status={r.status_code} body={body(r)!r}")
    # forged
    h, pl, sg = tok.split(".")
    hdr_none = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    r = ingest(f"{hdr_none}.{pl}."); rec("alg=none -> 401", r.status_code == 401, f"status={r.status_code} body={body(r)!r}")
    r = ingest(f"{hdr_none}.{pl}.{sg}"); rec("alg=none with sig -> 401", r.status_code == 401, f"status={r.status_code} body={body(r)!r}")
    jwks = requests.get(KC + "/protocol/openid-connect/certs", verify=CA).json()
    # HS256 using the PEM / JWK n as secret
    n = [k for k in jwks["keys"] if k.get("use") == "sig" and k["alg"] == "RS256"][0]
    for secret in [n["n"].encode(), unb64(n["n"]), (n.get("x5c") or [""])[0].encode()]:
        hh = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": n["kid"]}).encode())
        sig = b64(hmac.new(secret, f"{hh}.{pl}".encode(), hashlib.sha256).digest())
        r = ingest(f"{hh}.{pl}.{sig}"); rec("HS256 alg-confusion token -> 401", r.status_code == 401, f"status={r.status_code} body={body(r)!r}")
    # wrong typ in header (re-sign impossible; header change invalidates signature -> still 401)
    # forged claims with RS key of attacker
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    claims = json.loads(unb64(pl)); claims["exp"] = int(time.time()) + 300
    hh = b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": n["kid"]}).encode()); pp = b64(json.dumps(claims).encode())
    sig = b64(key.sign(f"{hh}.{pp}".encode(), padding.PKCS1v15(), hashes.SHA256()))
    r = ingest(f"{hh}.{pp}.{sig}"); rec("token signed by attacker key (kid of real key) -> 401", r.status_code == 401, f"status={r.status_code} body={body(r)!r}")
    claims2 = dict(claims); claims2["iss"] = "https://evil.test/realms/falco"
    pp = b64(json.dumps(claims2).encode()); sig = b64(key.sign(f"{hh}.{pp}".encode(), padding.PKCS1v15(), hashes.SHA256()))
    r = ingest(f"{hh}.{pp}.{sig}"); rec("attacker token wrong iss -> 401", r.status_code == 401, f"status={r.status_code} body={body(r)!r}")
    # expired: shorten falcosidekick token lifespan
    kc_adm = lambda *a: subprocess.run(["/tmp/e2e/keycloak-26.6.0/bin/kcadm.sh", *a], capture_output=True, text=True, env={**os.environ, "JAVA_TOOL_OPTIONS": ""})
    cid = kc_adm("get", "clients", "-r", "falco", "-q", "clientId=falcosidekick", "--fields", "id", "--format", "csv", "--noquotes").stdout.strip()
    kc_adm("update", f"clients/{cid}", "-r", "falco", "-s", "attributes.\"access.token.lifespan\"=3")
    short = cc_token("falcosidekick")
    r = ingest(short); rec("short-lived token fresh -> 200", r.status_code == 200, f"status={r.status_code}")
    time.sleep(6)
    r = ingest(short); rec("expired token -> 401", r.status_code == 401, f"status={r.status_code} body={body(r)!r}")
    kc_adm("update", f"clients/{cid}", "-r", "falco", "-s", "attributes.\"access.token.lifespan\"=")
    # path tricks for ingest bypass
    for p in ["//api/v1/events/add", "/api/v1/events/add/", "/api/v1//", "/api/v1"]:
        r = ingest(None, p); rec(f"ingest path trick {p!r} without token not accepted", r.status_code != 200, f"status={r.status_code} body={body(r)!r}")
    # event visible via alice
    sA, _, _, rA = do_login("alice", "alicepw"); sA.get(rA.headers["Location"], allow_redirects=False)
    time.sleep(1)
    r = sA.get(UI + "/api/v1/events/search", params={"hostname": "e2ehost", "since": "1h"})
    rec("ingested event visible in search for alice", r.status_code == 200 and "e2ehost" in r.text, f"status={r.status_code} body={body(r,120)!r}")
    print("\nSUMMARY:", sum(1 for x in RESULTS if x[1]), "pass,", sum(1 for x in RESULTS if not x[1]), "fail")
    json.dump([{"name": n, "pass": o, "evidence": e} for n, o, e in RESULTS], open("/tmp/e2e/results.json", "w"), indent=1)

main()
