# Local bootstrap policy for tenant "ztna".
# In production this file is replaced by the Policy Distribution API
# (see policyagent); it only serves as a fallback when Node 1 is unreachable.
package ztna

default allow = false

# Deny immediately if the session is in the blocked set
default is_blocked = false
is_blocked {
    input.is_blocked == true
}

# Extract request path from Envoy metadata
path := input.attributes.request.http.path

# Define minimum score per resource route
required_score = 70 {
    startswith(path, "/server")
} else = 50 {
    true
}

# Main authorization rule
allow {
    not is_blocked
    input.trust_score >= required_score
}
