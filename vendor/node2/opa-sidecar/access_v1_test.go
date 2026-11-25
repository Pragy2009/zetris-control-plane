package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	trustv1 "github.com/ztna/app-connector/opa-sidecar/gen/trust/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
)

const v1FixtureNow int64 = 2000000000

type v1FakeTrust struct {
	response *trustv1.LookupScoreResponse
	err      error
	calls    int
	last     *trustv1.LookupScoreRequest
}

func (f *v1FakeTrust) LookupScore(_ context.Context, r *trustv1.LookupScoreRequest, _ ...grpc.CallOption) (*trustv1.LookupScoreResponse, error) {
	f.calls++
	f.last = r
	return f.response, f.err
}

func v1Fixture(t *testing.T, tenant string) (*opaSidecar, *v1FakeTrust, []byte) {
	t.Helper()
	module, err := os.ReadFile(filepath.Join("..", "..", "node1", "policies", "access-v1", tenant+".rego"))
	if err != nil {
		t.Fatal(err)
	}
	host := "app.ztna.sc.deeptrustxai.com"
	if tenant == "ztna-tenant-2" {
		host = "tenant2-" + host
	}
	pm := newPolicyManager()
	if err := pm.apply(tenant, "fixture-policy-sha", module); err != nil {
		t.Fatal(err)
	}
	trust := &v1FakeTrust{response: &trustv1.LookupScoreResponse{SessionId: "session-1", UserId: "subject-1", Score: 100, RiskLevel: "LOW", RiskUpdatedAt: (v1FixtureNow - 10) * 1000}}
	s := &opaSidecar{tenant: tenant, expectedIssuer: "https://auth.ztna.sc.deeptrustxai.com/realms/" + tenant, policies: pm, trustEngineMode: "grpc", trustClient: trust,
		accessV1: &accessV1Config{Host: host, RoleClient: "node2-app-connector", Audiences: []string{"node2-app-connector", "envoy-proxy"}, Now: func() time.Time { return time.Unix(v1FixtureNow, 0) }, Sessions: newV1SessionTracker(v1FixtureNow-3600, 10000)}}
	return s, trust, module
}
func v1ClaimsFixture(s *opaSidecar, roles []string) map[string]interface{} {
	return map[string]interface{}{"iss": s.expectedIssuer, "sub": "subject-1", "sid": "session-1", "session_state": "session-1", "preferred_username": "alice", "azp": "node2-app-connector", "aud": []interface{}{"node2-app-connector"}, "exp": v1FixtureNow + 3600, "nbf": 0, "iat": v1FixtureNow - 30, "auth_time": v1FixtureNow - 30, "acr": "urn:zetris:acr:mfa", "resource_access": map[string]interface{}{"node2-app-connector": map[string]interface{}{"roles": roles}}}
}
func v1Req(t *testing.T, s *opaSidecar, method, path string, claims map[string]interface{}) *envoy_auth.CheckRequest {
	t.Helper()
	r := makeCheckRequest("Bearer ignored-unverified-header", path)
	r.Attributes.Request.Http.Host = s.accessV1.Host
	r.Attributes.Request.Http.Method = method
	if claims != nil {
		meta := v1Metadata(t, claims)
		r.Attributes.MetadataContext = &envoy_core.Metadata{FilterMetadata: map[string]*structpb.Struct{"envoy.filters.http.jwt_authn": meta}}
	}
	return r
}

func v1Metadata(t *testing.T, claims map[string]interface{}) *structpb.Struct {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{"jwt_payload": claims})
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]interface{}
	if err := json.Unmarshal(body, &object); err != nil {
		t.Fatal(err)
	}
	meta, err := structpb.NewStruct(object)
	if err != nil {
		t.Fatal(err)
	}
	return meta
}
func v1Check(t *testing.T, s *opaSidecar, r *envoy_auth.CheckRequest, want bool) *envoy_auth.CheckResponse {
	t.Helper()
	result, err := s.Check(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	got := result.GetStatus().GetCode() == int32(codes.OK)
	if got != want {
		t.Fatalf("allow=%v want=%v: %s", got, want, result.GetDeniedResponse().GetBody())
	}
	return result
}

func TestAccessV1GatewayRouteMatrixBothTenants(t *testing.T) {
	rows := []struct {
		method, path string
		roles        []string
	}{
		{"GET", "/juice/", []string{"viewer", "developer", "tenant_admin"}},
		{"HEAD", "/juice/index.html", []string{"viewer", "developer", "tenant_admin"}},
		{"GET", "/demo/dashboard", []string{"developer", "tenant_admin"}},
		{"GET", "/dummy/", []string{"tenant_admin"}},
		{"GET", "/demo/admin/users", []string{"tenant_admin"}},
		{"GET", "/demo/healthz", []string{"platform_operator"}},
		{"GET", "/demo/files/1k.bin", []string{"developer", "tenant_admin"}},
		{"GET", "/demo/files/", []string{"developer", "tenant_admin"}},
		{"GET", "/juice/simulation", []string{"tenant_admin"}},
		{"POST", "/juice/simulation/run", []string{"tenant_admin"}},
		{"GET", "/juice/api/documents/doc-1", nil}, {"PATCH", "/juice/api/documents/doc-1", nil}, {"DELETE", "/juice/api/documents/doc-1", nil},
		{"POST", "/juice/api/export", nil}, {"POST", "/dummy/api/users", nil}, {"PUT", "/dummy/api/policies", nil}, {"POST", "/dummy/api/session/unblock", nil},
		{"POST", "/juice/", nil}, {"GET", "/unmapped", nil}, {"TRACE", "/juice/", nil},
	}
	for _, tenant := range []string{"ztna", "ztna-tenant-2"} {
		t.Run(tenant, func(t *testing.T) {
			s, trust, _ := v1Fixture(t, tenant)
			for _, row := range rows {
				for _, role := range []string{"viewer", "developer", "tenant_admin", "platform_operator", "admin"} {
					t.Run(row.method+row.path+"/"+role, func(t *testing.T) {
						want := false
						for _, allowed := range row.roles {
							if role == allowed {
								want = true
							}
						}
						result := v1Check(t, s, v1Req(t, s, row.method, row.path, v1ClaimsFixture(s, []string{role})), want)
						if trust.last.GetTenantId() != tenant || trust.last.GetUserId() != "subject-1" || trust.last.GetSessionId() != "session-1" {
							t.Fatal("untrusted identity reached Score")
						}
						if result.GetDynamicMetadata().GetFields()["access_policy_version"].GetStringValue() != "access-v1.1.0" {
							t.Fatal("decision version missing")
						}
					})
				}
			}
		})
	}
}

func TestAccessV1DoesNotTrustBearerOrHeaders(t *testing.T) {
	s, trust, _ := v1Fixture(t, "ztna")
	r := v1Req(t, s, "GET", "/dummy/", nil)
	r.Attributes.Request.Http.Headers["authorization"] = "Bearer " + makeJWT("admin", "sid")
	missingIdentity := v1Check(t, s, r, false)
	metadata := missingIdentity.GetDynamicMetadata().GetFields()
	if metadata["access_policy_version"].GetStringValue() != "not_evaluated" || metadata["access_policy_installed_version"].GetStringValue() != "fixture-policy-sha" || metadata["access_policy_reasons"].GetListValue().GetValues()[0].GetStringValue() != "verified_jwt_metadata_required" {
		t.Fatal("early identity denial lost its audit evidence")
	}
	if trust.calls != 0 {
		t.Fatal("unverified token reached Score")
	}
	claims := v1ClaimsFixture(s, []string{"viewer"})
	claims["preferred_username"] = "zetris-admin"
	r = v1Req(t, s, "GET", "/dummy/", claims)
	for k, v := range map[string]string{"x-role": "tenant_admin", "x-roles": "tenant_admin", "x-mfa": "true", "x-tenant-id": "ztna", "x-current-user": "zetris-admin", "x-risk-level": "LOW", "x-trust-score": "100", "x-approval": "approved", "x-session-id": "attacker-session"} {
		r.Attributes.Request.Http.Headers[k] = v
	}
	v1Check(t, s, r, false)
	if trust.last.SessionId != "session-1" {
		t.Fatal("header overrode verified session")
	}
	r = v1Req(t, s, "GET", "/juice/", v1ClaimsFixture(s, []string{"viewer"}))
	r.Attributes.Request.Http.Headers["x-current-user"] = "attacker"
	result := v1Check(t, s, r, true)
	found := false
	for _, h := range result.GetOkResponse().GetHeaders() {
		if h.GetHeader().GetKey() == "x-current-user" {
			found = true
			if h.GetHeader().GetValue() != "alice" {
				t.Fatal("spoofed identity forwarded")
			}
		}
	}
	if !found {
		t.Fatal("verified backend identity not supplied")
	}
}

func TestAccessV1IdentityAndPathBoundaryCases(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*envoy_auth.CheckRequest, map[string]interface{})
	}{
		{"expired", func(r *envoy_auth.CheckRequest, c map[string]interface{}) { c["exp"] = v1FixtureNow }},
		{"future nbf", func(r *envoy_auth.CheckRequest, c map[string]interface{}) { c["nbf"] = v1FixtureNow + 1 }},
		{"future iat", func(r *envoy_auth.CheckRequest, c map[string]interface{}) { c["iat"] = v1FixtureNow + 31 }},
		{"foreign issuer", func(r *envoy_auth.CheckRequest, c map[string]interface{}) {
			c["iss"] = "https://auth.ztna.sc.deeptrustxai.com/realms/ztna-tenant-2"
		}},
		{"bad audience", func(r *envoy_auth.CheckRequest, c map[string]interface{}) { c["aud"] = []interface{}{"zetris-audit"} }},
		{"missing audience", func(r *envoy_auth.CheckRequest, c map[string]interface{}) { delete(c, "aud") }},
		{"missing session", func(r *envoy_auth.CheckRequest, c map[string]interface{}) {
			delete(c, "sid")
			delete(c, "session_state")
		}},
		{"conflicting session", func(r *envoy_auth.CheckRequest, c map[string]interface{}) { c["sid"] = "other-session" }},
		{"malformed roles", func(r *envoy_auth.CheckRequest, c map[string]interface{}) {
			c["resource_access"] = map[string]interface{}{"node2-app-connector": map[string]interface{}{"roles": "tenant_admin"}}
		}},
		{"audit roles", func(r *envoy_auth.CheckRequest, c map[string]interface{}) {
			c["resource_access"] = map[string]interface{}{"zetris-audit": map[string]interface{}{"roles": []string{"tenant_admin"}}}
		}},
		{"realm roles", func(r *envoy_auth.CheckRequest, c map[string]interface{}) {
			delete(c, "resource_access")
			c["realm_access"] = map[string]interface{}{"roles": []string{"tenant_admin"}}
		}},
		{"foreign host", func(r *envoy_auth.CheckRequest, c map[string]interface{}) {
			r.Attributes.Request.Http.Host = "tenant2-app.ztna.sc.deeptrustxai.com"
		}},
		{"lookalike host", func(r *envoy_auth.CheckRequest, c map[string]interface{}) {
			r.Attributes.Request.Http.Host = "app.ztna.sc.deeptrustxai.com.evil.test"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := v1Fixture(t, "ztna")
			c := v1ClaimsFixture(s, []string{"viewer"})
			r := v1Req(t, s, "GET", "/juice/", c)
			tc.mutate(r, c)
			meta := v1Metadata(t, c)
			r.Attributes.MetadataContext.FilterMetadata["envoy.filters.http.jwt_authn"] = meta
			v1Check(t, s, r, false)
		})
	}
	s, _, _ := v1Fixture(t, "ztna")
	for _, path := range []string{"/juice/../dummy/", "/juice/%2e%2e/dummy/", "/juice/%252e%252e/dummy/", "//juice/", "/juice//", "/juice/;admin", "/juice/\\dummy/", "/juice/%2f", "/juice/%00", "https://app.ztna.sc.deeptrustxai.com/juice/"} {
		t.Run(path, func(t *testing.T) {
			v1Check(t, s, v1Req(t, s, "GET", path, v1ClaimsFixture(s, []string{"tenant_admin"})), false)
		})
	}
	r := v1Req(t, s, "GET", "/juice/?role=tenant_admin&tenant=other&approval=true", v1ClaimsFixture(s, []string{"viewer"}))
	v1Check(t, s, r, true)
	r = v1Req(t, s, "HEAD", "/juice/", v1ClaimsFixture(s, []string{"viewer"}))
	r.Attributes.Request.Http.Host = strings.ToUpper(s.accessV1.Host) + ":443"
	v1Check(t, s, r, true)
}

func TestAccessV1RiskMFAAndRecovery(t *testing.T) {
	s, trust, _ := v1Fixture(t, "ztna")
	viewer := func() *envoy_auth.CheckRequest {
		return v1Req(t, s, "GET", "/juice/", v1ClaimsFixture(s, []string{"viewer"}))
	}
	admin := func(c map[string]interface{}) *envoy_auth.CheckRequest { return v1Req(t, s, "GET", "/dummy/", c) }
	v1Check(t, s, viewer(), true)
	trust.err = fmt.Errorf("unavailable")
	v1Check(t, s, viewer(), false)
	trust.err = nil
	trust.response.UserId = "other-user"
	v1Check(t, s, viewer(), false)
	trust.response.UserId = "subject-1"
	trust.response.SessionId = "other-session"
	v1Check(t, s, viewer(), false)
	trust.response.SessionId = "session-1"
	trust.response.Blocked = true
	v1Check(t, s, viewer(), false)
	trust.response.Blocked = false
	v1Check(t, s, viewer(), true)
	trust.response.Score = 2
	trust.response.RiskLevel = "CRITICAL"
	v1Check(t, s, viewer(), false)
	trust.response.Score = 100
	trust.response.RiskLevel = "LOW"
	for _, age := range []int64{10, 600, 601} {
		trust.response.RiskUpdatedAt = (v1FixtureNow - age) * 1000
		c := v1ClaimsFixture(s, []string{"tenant_admin"})
		v1Check(t, s, admin(c), age <= 600)
		v1Check(t, s, viewer(), true)
	}
	trust.response.RiskUpdatedAt = 0
	trust.response.RiskLevel = ""
	v1Check(t, s, viewer(), true)
	v1Check(t, s, admin(v1ClaimsFixture(s, []string{"tenant_admin"})), false)
	trust.response.RiskUpdatedAt = (v1FixtureNow - 10) * 1000
	trust.response.RiskLevel = "LOW"
	for _, acr := range []string{"", "1", "2", "mfa"} {
		c := v1ClaimsFixture(s, []string{"tenant_admin"})
		c["acr"] = acr
		v1Check(t, s, admin(c), false)
	}
	c := v1ClaimsFixture(s, []string{"tenant_admin"})
	c["auth_time"] = v1FixtureNow - 301
	v1Check(t, s, admin(c), false)
	c["auth_time"] = v1FixtureNow - 300
	// This boundary case is a separate authentication-history fixture.
	s.accessV1.Sessions = newV1SessionTracker(v1FixtureNow-3600, 10000)
	v1Check(t, s, admin(c), true)
	trust.response.Score = 40
	trust.response.RiskLevel = "HIGH"
	v1Check(t, s, viewer(), true)
	v1Check(t, s, admin(c), false)
	trust.response.Score = 100
	trust.response.RiskLevel = "LOW"
	trust.response.RiskUpdatedAt = (v1FixtureNow + 31) * 1000
	v1Check(t, s, viewer(), false)
}

func TestAccessV1ReloadAndSchemaFailClosed(t *testing.T) {
	s, _, module := v1Fixture(t, "ztna")
	r := v1Req(t, s, "GET", "/juice/", v1ClaimsFixture(s, []string{"viewer"}))
	v1Check(t, s, r, true)
	if err := s.policies.apply("ztna", "bad", []byte("# zetris-access-policy: v1\npackage ztna\ninvalid {")); err == nil {
		t.Fatal("invalid policy accepted")
	}
	v1Check(t, s, r, true)
	_, version, mode := s.policies.getWithMode("ztna")
	if version != "fixture-policy-sha" || !mode {
		t.Fatal("failed reload changed installed policy")
	}
	for _, bad := range []string{"package ztna\nallow = true", `package ztna
decision = true`, `package ztna
decision = {"allow":true,"reasons":[],"policy_version":"bad"}`, `package wrong_tenant
decision = {"allow":false,"reasons":["deny"],"policy_version":"bad"}`} {
		if err := s.policies.apply("ztna", "bad-schema", []byte("# zetris-access-policy: v1\n"+bad)); err == nil {
			t.Fatal("semantically invalid policy replaced last-known-good")
		}
		v1Check(t, s, r, true)
	}
	if err := s.policies.apply("ztna", "legacy", []byte(simplePolicy)); err != nil {
		t.Fatal(err)
	}
	v1Check(t, s, r, false)
	if err := s.policies.apply("ztna", "restored", module); err != nil {
		t.Fatal(err)
	}
	v1Check(t, s, r, true)
	s.accessV1 = nil
	v1Check(t, s, r, false)
}

func TestAccessV1BoundSimulatorCannotEscalate(t *testing.T) {
	s, trust, module := v1Fixture(t, "ztna")
	const subject = "11111111-1111-4111-8111-111111111111"
	const run = "22222222-2222-4222-8222-222222222222"
	modified := strings.Replace(string(module), `"simulator_subject": ""`, `"simulator_subject": "`+subject+`"`, 1)
	if modified == string(module) {
		t.Fatal("fixture simulator binding missing")
	}
	if err := s.policies.apply("ztna", "simulator-fixture", []byte(modified)); err != nil {
		t.Fatal(err)
	}
	c := v1ClaimsFixture(s, []string{})
	c["sub"] = subject
	c["azp"] = "zetris-risk-simulator"
	c["preferred_username"] = "service-account-zetris-risk-simulator"
	delete(c, "sid")
	delete(c, "session_state")
	trust.response.UserId = subject
	trust.response.SessionId = "sim-" + subject + "-" + run
	trust.response.RiskLevel = ""
	trust.response.RiskUpdatedAt = 0
	request := func(method, path string) *envoy_auth.CheckRequest {
		r := v1Req(t, s, method, path, c)
		r.Attributes.Request.Http.Headers["x-zetris-demo-run"] = run
		return r
	}
	v1Check(t, s, request("GET", "/juice/simulation/normal"), true)
	v1Check(t, s, request("POST", "/juice/simulation/probe/"+run+"/auth-failure/0"), true)
	v1Check(t, s, request("POST", "/juice/simulation/probe/"+run+"/auth-failure/180"), false)
	for _, path := range []string{"/juice/", "/dummy/", "/demo/", "/juice/simulation/run"} {
		v1Check(t, s, request("GET", path), false)
	}
	trust.response.Blocked = true
	v1Check(t, s, request("GET", "/juice/simulation/normal"), false)
	trust.response.Blocked = false
	c["azp"] = "node2-app-connector"
	c["sid"] = "session-1"
	c["resource_access"] = map[string]interface{}{"node2-app-connector": map[string]interface{}{"roles": []string{"tenant_admin"}}}
	trust.response.SessionId = "session-1"
	trust.response.RiskLevel = "LOW"
	trust.response.RiskUpdatedAt = (v1FixtureNow - 10) * 1000
	v1Check(t, s, request("GET", "/juice/"), false)
}

func TestAccessV1ConfigIsExplicitAndOffByDefault(t *testing.T) {
	t.Setenv("ACCESS_POLICY_MODE", "")
	c, err := loadAccessV1Config("ztna", "issuer")
	if err != nil || c != nil {
		t.Fatal("v1 implicitly enabled")
	}
	t.Setenv("ACCESS_POLICY_MODE", "bogus")
	if _, err := loadAccessV1Config("ztna", "issuer"); err == nil {
		t.Fatal("unknown mode accepted")
	}
	t.Setenv("ACCESS_POLICY_MODE", "v1")
	t.Setenv("POLICY_V1_APP_HOST", "")
	if _, err := loadAccessV1Config("ztna", "issuer"); err == nil {
		t.Fatal("missing host accepted")
	}
	t.Setenv("POLICY_V1_APP_HOST", "app.ztna.sc.deeptrustxai.com")
	if _, err := loadAccessV1Config("ztna", "issuer"); err != nil {
		t.Fatal(err)
	}
}
