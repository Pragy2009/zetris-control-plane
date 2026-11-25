package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/open-policy-agent/opa/rego"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
)

type accessV1Config struct {
	Host, RoleClient string
	Audiences        []string
	Now              func() time.Time
	Sessions         *v1SessionTracker
}

func loadAccessV1Config(tenant, issuer string) (*accessV1Config, error) {
	switch getEnv("ACCESS_POLICY_MODE", "legacy") {
	case "legacy":
		return nil, nil
	case "v1":
	default:
		return nil, fmt.Errorf("ACCESS_POLICY_MODE must be legacy or v1")
	}
	host := getEnv("POLICY_V1_APP_HOST", "")
	if tenant == "" || issuer == "" || !regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)+$`).MatchString(host) {
		return nil, fmt.Errorf("v1 requires a bound tenant, issuer and POLICY_V1_APP_HOST")
	}
	return &accessV1Config{Host: host, RoleClient: getEnv("POLICY_V1_ROLE_CLIENT", "node2-app-connector"), Audiences: splitCSV(getEnv("POLICY_V1_AUDIENCES", "node2-app-connector,envoy-proxy")), Now: time.Now, Sessions: newV1SessionTracker(time.Now().Unix(), 10000)}, nil
}

type v1Principal struct {
	Verified        bool     `json:"verified"`
	Subject         string   `json:"subject"`
	Session         string   `json:"session"`
	Tenant          string   `json:"tenant"`
	Issuer          string   `json:"issuer"`
	RoleClient      string   `json:"role_client"`
	Roles           []string `json:"roles"`
	Kind            string   `json:"kind"`
	Username        string   `json:"username"`
	AuthorizedParty string   `json:"authorized_party"`
	ExpiresAt       int64    `json:"expires_at"`
	NotBefore       int64    `json:"not_before"`
	AuthTime        int64    `json:"auth_time"`
	IssuedAt        int64    `json:"issued_at"`
	ACR             string   `json:"acr"`
}
type v1Resource struct {
	Tenant       string `json:"tenant"`
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Action       string `json:"action"`
	Supported    bool   `json:"supported"`
	OwnerSubject string `json:"owner_subject"`
}
type v1Risk struct {
	Subject   string `json:"subject"`
	Session   string `json:"session"`
	Available bool   `json:"available"`
	Blocked   bool   `json:"blocked"`
	Score     int    `json:"score"`
	Level     string `json:"level"`
	UpdatedAt int64  `json:"updated_at"`
}
type v1Input struct {
	Schema    int                    `json:"schema_version"`
	Now       int64                  `json:"now"`
	Principal v1Principal            `json:"principal"`
	HTTP      map[string]string      `json:"http"`
	Resource  v1Resource             `json:"resource"`
	Risk      v1Risk                 `json:"risk"`
	Approval  map[string]interface{} `json:"approval"`
	Context   map[string]string      `json:"context"`
	Device    map[string]interface{} `json:"device"`
}
type v1Decision struct {
	Allow       bool                     `json:"allow"`
	Action      string                   `json:"action"`
	Reasons     []string                 `json:"reasons"`
	Version     string                   `json:"policy_version"`
	Application string                   `json:"application_id"`
	AccessRule  string                   `json:"access_rule_id"`
	TimeoutRule string                   `json:"timeout_rule_id"`
	Constraints v1SessionConstraints     `json:"session_constraints"`
	ValidUntil  int64                    `json:"decision_valid_until"`
	Trace       []map[string]interface{} `json:"trace"`
}

func parseV1Decision(value interface{}) (v1Decision, error) {
	object, ok := value.(map[string]interface{})
	if !ok {
		return v1Decision{}, fmt.Errorf("invalid_policy_decision")
	}
	if _, ok := object["allow"].(bool); !ok {
		return v1Decision{}, fmt.Errorf("invalid_policy_decision")
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		return v1Decision{}, fmt.Errorf("invalid_policy_decision")
	}
	var decision v1Decision
	if json.Unmarshal(encoded, &decision) != nil || decision.Version == "" || decision.Reasons == nil || decision.Allow && len(decision.Reasons) > 0 || !decision.Allow && len(decision.Reasons) == 0 {
		return v1Decision{}, fmt.Errorf("invalid_policy_decision")
	}
	if !decision.Constraints.valid() || decision.Trace == nil || len(decision.Trace) > 256 || decision.Application == "" || decision.AccessRule == "" || decision.TimeoutRule == "" || decision.ValidUntil < 0 || decision.Allow && (decision.Action != "allow" || decision.ValidUntil == 0) || !decision.Allow && (decision.Action != "deny" && decision.Action != "reauthenticate" || decision.ValidUntil != 0) {
		return v1Decision{}, fmt.Errorf("invalid_policy_decision")
	}
	return decision, nil
}

type v1Claims struct {
	jwtPayload
	Exp            int64           `json:"exp"`
	Nbf            int64           `json:"nbf"`
	Iat            int64           `json:"iat"`
	AuthTime       int64           `json:"auth_time"`
	ACR            string          `json:"acr"`
	Audience       json.RawMessage `json:"aud"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
}

var v1SafeID = regexp.MustCompile(`^[A-Za-z0-9._:@-]{1,200}$`)
var v1SafePath = regexp.MustCompile(`^/[A-Za-z0-9_./-]*$`)
var v1Probe = regexp.MustCompile(`^/juice/simulation/probe/([a-f0-9-]{36})/(auth-failure|missing|latency)/([0-9]{1,3})$`)

// Only Envoy's JWT filter metadata crosses this trust boundary. Authorization,
// roles, tenant, MFA, approval and risk headers are never decoded or copied.
func (s *opaSidecar) v1Principal(req *envoy_auth.CheckRequest, now int64) (v1Principal, error) {
	raw := req.GetAttributes().GetMetadataContext().GetFilterMetadata()["envoy.filters.http.jwt_authn"].GetFields()["jwt_payload"].GetStructValue()
	if raw == nil {
		return v1Principal{}, fmt.Errorf("verified_jwt_metadata_required")
	}
	body, err := json.Marshal(raw.AsMap())
	if err != nil || len(body) > 32768 {
		return v1Principal{}, fmt.Errorf("invalid_verified_claims")
	}
	var c v1Claims
	if json.Unmarshal(body, &c) != nil {
		return v1Principal{}, fmt.Errorf("invalid_verified_claims")
	}
	if c.Iss != s.expectedIssuer || s.tenant == "" || tenantFromIssuer(c.Iss) != s.tenant || !v1SafeID.MatchString(c.Sub) || !v1SafeID.MatchString(c.PreferredUsername) || c.Exp <= now || c.Nbf > now || c.Iat > now+30 || c.AuthTime > now {
		return v1Principal{}, fmt.Errorf("invalid_identity_or_token_time")
	}
	var aud []string
	if json.Unmarshal(c.Audience, &aud) != nil {
		var one string
		if json.Unmarshal(c.Audience, &one) != nil {
			return v1Principal{}, fmt.Errorf("invalid_audience")
		}
		aud = []string{one}
	}
	accepted := false
	for _, a := range aud {
		for _, allowed := range s.accessV1.Audiences {
			if a == allowed {
				accepted = true
			}
		}
	}
	if !accepted {
		return v1Principal{}, fmt.Errorf("audience_not_served")
	}
	session := c.SessionState
	if session == "" {
		session = c.Sid
	}
	if c.SessionState != "" && c.Sid != "" && c.SessionState != c.Sid {
		return v1Principal{}, fmt.Errorf("conflicting_session_claims")
	}
	kind := "human"
	if c.AuthorizedParty == "zetris-risk-simulator" && c.PreferredUsername == "service-account-zetris-risk-simulator" {
		run := req.GetAttributes().GetRequest().GetHttp().GetHeaders()["x-zetris-demo-run"]
		if !demoUUID.MatchString(run) || !demoUUID.MatchString(c.Sub) {
			return v1Principal{}, fmt.Errorf("invalid_simulation_session")
		}
		kind = "simulator"
		session = "sim-" + c.Sub + "-" + run
	}
	if !v1SafeID.MatchString(session) {
		return v1Principal{}, fmt.Errorf("verified_session_required")
	}
	roles := c.ResourceAccess[s.accessV1.RoleClient].Roles
	if roles == nil {
		roles = []string{}
	}
	if len(roles) > 32 {
		return v1Principal{}, fmt.Errorf("invalid_roles")
	}
	for _, role := range roles {
		if len(role) > 80 {
			return v1Principal{}, fmt.Errorf("invalid_roles")
		}
	}
	return v1Principal{Verified: true, Subject: c.Sub, Session: session, Tenant: s.tenant, Issuer: c.Iss, RoleClient: s.accessV1.RoleClient, Roles: roles, Kind: kind, Username: c.PreferredUsername, AuthorizedParty: c.AuthorizedParty, ExpiresAt: c.Exp, NotBefore: c.Nbf, AuthTime: c.AuthTime, IssuedAt: c.Iat, ACR: c.ACR}, nil
}

func v1Route(tenant, method, path string) v1Resource {
	r := v1Resource{Tenant: tenant, ID: "unmapped", Kind: "unmapped", Action: "unknown"}
	set := func(kind, action, id string) v1Resource {
		r.Kind = kind
		r.Action = action
		r.ID = id
		r.Supported = true
		return r
	}
	read := method == "GET" || method == "HEAD"
	switch {
	case read && (path == "/juice/" || path == "/juice/index.html"):
		return set("workspace", "view", "workspace")
	case read && (path == "/demo/" || path == "/demo/dashboard"):
		return set("developer_app", "view", "developer-app")
	case read && path == "/demo/healthz":
		return set("diagnostics", "view", "service-health")
	case read && (path == "/dummy/" || path == "/demo/admin" || path == "/demo/admin/" || path == "/demo/admin/users" || path == "/demo/admin/config"):
		return set("admin_console", "view", "admin-console")
	case read && (path == "/demo/files" || path == "/demo/files/"):
		return set("file", "view", "files-index")
	case read && (path == "/demo/files/1k.bin" || path == "/demo/files/100k.bin" || path == "/demo/files/1m.bin" || path == "/demo/files/10m.bin"):
		return set("file", "download", path)
	case read && (path == "/juice/simulation" || path == "/juice/simulation.js"):
		return set("simulation_control", "manage", "risk-demo")
	case method == "GET" && path == "/juice/simulation/status":
		return set("simulation_control", "manage", "risk-demo")
	case method == "POST" && (path == "/juice/simulation/run" || path == "/juice/simulation/stop"):
		return set("simulation_control", "manage", "risk-demo")
	case method == "GET" && path == "/juice/simulation/normal":
		return set("simulation_probe", "probe", "risk-demo-probe")
	}
	if m := v1Probe.FindStringSubmatch(path); m != nil && demoUUID.MatchString(m[1]) {
		index, _ := strconv.Atoi(m[3])
		if index >= 180 {
			return r
		}
		expected := "GET"
		if m[2] == "auth-failure" {
			expected = "POST"
		}
		if method == expected {
			return set("simulation_probe", "probe", "risk-demo-probe")
		}
	}
	// CRUD, exports, approvals and administrative APIs have no implemented,
	// trusted resource registry yet. Unknown routes always remain unsupported.
	return r
}

func (s *opaSidecar) v1Request(req *envoy_auth.CheckRequest, p v1Principal, score *scoreResponse, now int64) (v1Input, error) {
	http := req.GetAttributes().GetRequest().GetHttp()
	host := strings.ToLower(http.GetHost())
	if host == s.accessV1.Host+":443" {
		host = s.accessV1.Host
	}
	if host != s.accessV1.Host {
		return v1Input{}, fmt.Errorf("host_not_served")
	}
	u, err := url.ParseRequestURI(http.GetPath())
	if err != nil || u.IsAbs() || !v1SafePath.MatchString(u.Path) || strings.Contains(strings.SplitN(http.GetPath(), "?", 2)[0], "%") || strings.Contains(u.Path, "//") {
		return v1Input{}, fmt.Errorf("ambiguous_request_path")
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return v1Input{}, fmt.Errorf("ambiguous_request_path")
		}
	}
	if score == nil || score.UserID != p.Subject || score.SessionID != p.Session || score.RiskUpdatedAt < 0 {
		return v1Input{}, fmt.Errorf("risk_session_owner_mismatch")
	}
	level := score.RiskLevel
	if level == "" && score.RiskUpdatedAt == 0 {
		level = "UNKNOWN"
	}
	resource := v1Route(s.tenant, http.GetMethod(), u.Path)
	if m := v1Probe.FindStringSubmatch(u.Path); m != nil && resource.Supported && !strings.HasSuffix(p.Session, "-"+m[1]) {
		return v1Input{}, fmt.Errorf("simulation_run_mismatch")
	}
	sourceIP := req.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress()
	if net.ParseIP(sourceIP) == nil {
		sourceIP = ""
	}
	return v1Input{Schema: 1, Now: now, Principal: p, HTTP: map[string]string{"host": host, "port": "443", "protocol": "tcp", "method": http.GetMethod(), "path": u.Path}, Resource: resource, Risk: v1Risk{Subject: score.UserID, Session: score.SessionID, Available: true, Blocked: score.Blocked, Score: score.Score, Level: level, UpdatedAt: score.RiskUpdatedAt / 1000}, Approval: map[string]interface{}{"verified": false}, Context: map[string]string{"client_type": "envoy_http", "source_ip": sourceIP}, Device: map[string]interface{}{"verified": false}}, nil
}

func (s *opaSidecar) checkAccessV1(ctx context.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {
	start := time.Now()
	outcome := "deny"
	defer func() {
		checkTotal.WithLabelValues(s.tenant, outcome).Inc()
		checkDuration.WithLabelValues(s.tenant).Observe(time.Since(start).Seconds())
	}()
	now := s.accessV1.Now().Unix()
	pq, version, v1 := s.policies.getWithMode(s.tenant)
	var principal v1Principal
	var input v1Input
	finish := func(decision v1Decision) *envoy_auth.CheckResponse {
		rule := "pre_policy_validation"
		if decision.Version != "not_evaluated" {
			rule = input.Resource.Kind + "." + input.Resource.Action
		}
		slog.Info("access policy decision", "tenant", s.tenant, "subject", principal.Subject, "session", principal.Session,
			"identity_verified", principal.Verified, "roles", principal.Roles,
			"policy_version", decision.Version, "installed_version", version, "rule", rule,
			"resource", input.Resource.ID, "resource_kind", input.Resource.Kind, "action", input.Resource.Action,
			"risk_available", input.Risk.Available, "risk_score", input.Risk.Score, "risk_level", input.Risk.Level,
			"risk_updated_at", input.Risk.UpdatedAt, "blocked", input.Risk.Blocked,
			"auth_time", principal.AuthTime, "acr", principal.ACR, "approval_verified", input.Approval["verified"] == true,
			"application", decision.Application, "access_rule", decision.AccessRule, "timeout_rule", decision.TimeoutRule,
			"session_constraints", decision.Constraints, "decision_valid_until", decision.ValidUntil, "trace", decision.Trace,
			"allow", decision.Allow, "action", decision.Action, "reasons", decision.Reasons)
		response := deny(codes.PermissionDenied, strings.Join(decision.Reasons, ","))
		if decision.Action == "reauthenticate" {
			response = deny(codes.Unauthenticated, strings.Join(decision.Reasons, ","))
			response.GetDeniedResponse().Status.Code = envoy_type.StatusCode_Unauthorized
		}
		if decision.Allow {
			outcome = "allow"
			response = allow(map[string]string{"x-session-id": principal.Session, "x-current-user": principal.Username, "x-tenant-id": s.tenant})
		}
		reasons := make([]interface{}, len(decision.Reasons))
		for i, r := range decision.Reasons {
			reasons[i] = r
		}
		response.DynamicMetadata, _ = structpb.NewStruct(map[string]interface{}{"access_policy_version": decision.Version, "access_policy_installed_version": version, "access_policy_reasons": reasons, "access_policy_allow": decision.Allow, "access_policy_action": decision.Action, "access_policy_application": decision.Application, "access_policy_access_rule": decision.AccessRule, "access_policy_timeout_rule": decision.TimeoutRule, "access_policy_valid_until": decision.ValidUntil})
		return response
	}
	reject := func(reason string) (*envoy_auth.CheckResponse, error) {
		return finish(v1Decision{Action: "deny", Reasons: []string{reason}, Version: "not_evaluated"}), nil
	}
	var err error
	principal, err = s.v1Principal(req, now)
	if err != nil {
		return reject(err.Error())
	}
	if pq == nil || !v1 {
		return reject("v1_policy_required")
	}
	if s.trustEngineMode != "grpc" || s.trustClient == nil {
		return reject("authenticated_risk_service_required")
	}
	score, err := s.fetchScoreGRPC(ctx, principal.Session, s.tenant, principal.Subject)
	trustEngineCalls.WithLabelValues("grpc", metricResult(err)).Inc()
	if err != nil {
		return reject("risk_service_unavailable")
	}
	input, err = s.v1Request(req, principal, score, now)
	if err != nil {
		return reject(err.Error())
	}
	// Passing a JSON object keeps Rego input identical to standalone opa tests.
	body, _ := json.Marshal(input)
	var normalized map[string]interface{}
	_ = json.Unmarshal(body, &normalized)
	results, err := pq.Eval(ctx, rego.EvalInput(normalized))
	if err != nil || len(results) != 1 || len(results[0].Expressions) != 1 {
		return reject("policy_evaluation_failed")
	}
	decision, err := parseV1Decision(results[0].Expressions[0].Value)
	if err != nil {
		return reject("invalid_policy_decision")
	}
	if decision.Allow {
		// The stable gateway kind prevents catalogue renaming from resetting idle history.
		if reason, stateUntil := s.accessV1.Sessions.authorize(principal, input.Resource.Kind, decision.Constraints, now); reason != "" {
			decision.Allow = false
			decision.Action = "reauthenticate"
			if reason == "session_state_unavailable" || reason == "session_capacity_reached" {
				decision.Action = "deny"
			}
			decision.Reasons = []string{reason}
			decision.ValidUntil = 0
			decision.Trace = append(decision.Trace, map[string]interface{}{"stage": "session", "result": reason})
		} else {
			// Idle state is checked and updated atomically above, never cached.
			if stateUntil < decision.ValidUntil {
				decision.ValidUntil = stateUntil
			}
		}
	}
	return finish(decision), nil
}
