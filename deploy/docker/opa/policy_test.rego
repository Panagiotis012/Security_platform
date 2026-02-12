package zerotrust.envoy.authz

import rego.v1

test_public_healthz_allows_without_jwt if {
  r := result with input as {"method": "GET", "path": "/healthz", "jwt": {}}
  r.allow == true
  r.reason == "public"
}

test_public_jwks_allows_without_jwt if {
  r := result with input as {"method": "GET", "path": "/.well-known/jwks.json", "jwt": {}}
  r.allow == true
  r.reason == "public"
}

test_public_login_allows_without_jwt if {
  r := result with input as {"method": "GET", "path": "/auth/login", "jwt": {}}
  r.allow == true
  r.reason == "public"
}

test_dev_token_issuer_denied_without_jwt if {
  r := result with input as {"method": "POST", "path": "/auth/dev/issue-token", "jwt": {}}
  r.allow == false
  r.reason == "missing_jwt"
}

test_dev_token_issuer_allowed_for_local_client if {
  r := result with input as {
    "method": "POST",
    "path": "/auth/dev/issue-token",
    "jwt": {},
    "client": {"x_forwarded_for": "127.0.0.1"},
  }
  r.allow == true
  r.reason == "public"
}

test_workload_token_denied_without_jwt if {
  r := result with input as {"method": "POST", "path": "/auth/workload/token", "jwt": {}}
  r.allow == false
  r.reason == "missing_jwt"
}

test_missing_jwt_denies_protected_paths if {
  r := result with input as {"method": "GET", "path": "/v1/keys", "jwt": {}}
  r.allow == false
  r.reason == "missing_jwt"
}

test_admin_required_for_keys if {
  r := result with input as {"method": "GET", "path": "/v1/keys", "jwt": {"sub": "u1", "roles": ["user"], "step_up_level": 2}}
  r.allow == false
  r.reason == "admin_required"
}

test_step_up_required_for_signing if {
  r := result with input as {"method": "POST", "path": "/v1/sign", "jwt": {"sub": "u1", "roles": ["admin"], "step_up_level": 0}}
  r.allow == false
  r.reason == "step_up_required"
  r.headers["x-zt-step-up-required"] == "true"
  r.headers["x-zt-required-step-up-level"] == "2"
}

test_step_up_ok_allows_signing if {
  r := result with input as {"method": "POST", "path": "/v1/sign", "jwt": {"sub": "u1", "roles": ["admin"], "step_up_level": 2}}
  r.allow == true
}
