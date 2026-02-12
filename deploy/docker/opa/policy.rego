package zerotrust.envoy.authz

# Envoy ext_authz policy (OPA/Rego)
# Input format is defined by policy-engine's /v1/envoy/authz adapter.
#
# This policy is intentionally "fail-closed":
# - Public endpoints are explicitly allowlisted
# - Everything else requires a verified JWT (validated by Envoy) and is subject
#   to step-up and basic RBAC rules.

default result := {"allow": false, "reason": "default_deny"}

# ---------------------------------------------------------------------------
# Public endpoints (no JWT required)
# ---------------------------------------------------------------------------

# Identity browser/session flow endpoints that cannot rely on edge JWT
# verification (they use OIDC redirects, session cookies, and CSRF checks).
public_auth_path if startswith(input.path, "/auth/login")
public_auth_path if startswith(input.path, "/auth/callback")
public_auth_path if startswith(input.path, "/auth/token/refresh")
public_auth_path if startswith(input.path, "/auth/logout")
public_auth_path if startswith(input.path, "/auth/session")
public_auth_path if startswith(input.path, "/auth/step-up/")
public_auth_path if startswith(input.path, "/auth/webauthn/")

first_client_ip := ip if {
  client := object.get(input, "client", {})
  xff := object.get(client, "x_forwarded_for", "")
  is_string(xff)
  parts := split(xff, ",")
  count(parts) > 0
  ip := trim(parts[0], " ")
} else := ""

local_dev_client if regex.match("^(127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|::1)", first_client_ip)

public_path if public_auth_path
# Allow the dev token issuer only from local/private clients. This keeps
# local smoke tests usable while preventing internet exposure by default.
public_path if {
  startswith(input.path, "/auth/dev/issue-token")
  local_dev_client
}
public_path if startswith(input.path, "/health")
public_path if startswith(input.path, "/healthz")
public_path if startswith(input.path, "/ready")
public_path if startswith(input.path, "/readyz")
public_path if startswith(input.path, "/startupz")
public_path if input.path == "/.well-known/jwks.json"

# ---------------------------------------------------------------------------
# Identity helpers
# ---------------------------------------------------------------------------

has_jwt if jwt_sub != ""

jwt_sub := s if {
  s := object.get(input.jwt, "sub", "")
  is_string(s)
}

jwt_roles := rs if {
  rs := object.get(input.jwt, "roles", [])
  is_array(rs)
} else := []

has_role(role) if {
  some i
  jwt_roles[i] == role
}

is_admin if has_role("admin") else := false

step_up_level := n if {
  raw := object.get(input.jwt, "step_up_level", 0)
  n := to_number(raw)
} else := 0

step_up_ok if step_up_level >= 2

# ---------------------------------------------------------------------------
# Risk and privilege rules
# ---------------------------------------------------------------------------

# Step-up required for dangerous methods or sensitive endpoints.
needs_step_up if upper(input.method) == "DELETE"
needs_step_up if startswith(input.path, "/v1/sign")
needs_step_up if startswith(input.path, "/v1/keys/rotate")
needs_step_up if startswith(input.path, "/v1/admission")
needs_step_up if startswith(input.path, "/v1/runtime")
needs_step_up if startswith(input.path, "/v1/vuln")

# Admin role required for supply-chain actions that can affect deployments.
requires_admin if startswith(input.path, "/v1/sign")
requires_admin if startswith(input.path, "/v1/admission")
requires_admin if startswith(input.path, "/v1/keys")

# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

result := {"allow": true, "reason": "public"} if { public_path }
else := {"allow": false, "reason": "missing_jwt"} if { not has_jwt }
else := {"allow": false, "reason": "admin_required"} if { requires_admin; not is_admin }
else := {"allow": false, "reason": "step_up_required", "headers": {"x-zt-step-up-required": "true", "x-zt-required-step-up-level": "2"}} if { needs_step_up; not step_up_ok }
else := {"allow": true, "reason": "allow_authenticated"} if { has_jwt }
