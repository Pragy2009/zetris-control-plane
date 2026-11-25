package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/open-policy-agent/opa/rego"
)

func makeJWT(sub, sessionID string) string {
	return makeJWTForIss(sub, sessionID, "https://auth.ztnaiitm.me/realms/ztna")
}

func makeJWTForIss(sub, sessionID, iss string) string {
	header := `{"alg":"RS256","typ":"JWT","kid":"test-key-1"}`
	payload := fmt.Sprintf(`{"sub":"%s","session_state":"%s","sid":"%s","azp":"envoy-proxy","preferred_username":"testuser","iss":"%s"}`, sub, sessionID, sessionID, iss)
	b64 := func(data string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(data))
	}
	return b64(header) + "." + b64(payload) + ".fakesignature"
}

func TestTenantFromIssuer(t *testing.T) {
	cases := []struct {
		iss  string
		want string
	}{
		{"https://auth.ztnaiitm.me/realms/ztna", "ztna"},
		{"https://auth.ztnaiitm.me/realms/acme", "acme"},
		{"https://auth.ztnaiitm.me/realms/acme/", "acme"},
		{"https://keycloak.example.com/auth/realms/dev", "dev"},
		{"", ""},
		{"not-a-url", ""},
		{"https://issuer.example.com/", ""},
	}
	for _, c := range cases {
		if got := tenantFromIssuer(c.iss); got != c.want {
			t.Errorf("tenantFromIssuer(%q) = %q, want %q", c.iss, got, c.want)
		}
	}
}

func makeCheckRequest(authHeader, path string) *envoy_auth.CheckRequest {
	req := &envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Request: &envoy_auth.AttributeContext_Request{
				Http: &envoy_auth.AttributeContext_HttpRequest{
					Headers: map[string]string{},
					Path:    path,
					Method:  "GET",
					Host:    "app.ztnaiitm.me",
				},
			},
		},
	}
	if authHeader != "" {
		req.Attributes.Request.Http.Headers["authorization"] = authHeader
	}
	return req
}

const simplePolicy = `package ztna

default allow = false

default is_blocked = false
is_blocked {
    input.is_blocked == true
}

path := input.attributes.request.http.path

required_score = 70 {
    startswith(path, "/server")
} else = 50 {
    true
}

allow {
    not is_blocked
    input.trust_score >= required_score
}
`

func makeRegoDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ztna.rego"), []byte(simplePolicy), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func setupSidecar(t *testing.T, teURL string) *opaSidecar {
	t.Helper()
	dir := makeRegoDir(t)
	pm := newPolicyManager()
	loadCachedPolicies(pm, []string{dir}, []string{"ztna"})
	if pq, _ := pm.get("ztna"); pq == nil {
		t.Fatal("policy for ztna not loaded")
	}
	return &opaSidecar{
		trustEngineAddr: teURL,
		tenant:          "ztna",
		expectedIssuer:  "https://auth.ztnaiitm.me/realms/ztna",
		policies:        pm,
	}
}

type testTrustEngine struct {
	score   int
	blocked bool
}

func (te *testTrustEngine) handler(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing session_id"})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"session_id": sessionID,
		"score":      te.score,
		"blocked":    te.blocked,
	})
}

func TestCheck_NoToken(t *testing.T) {
	te := &testTrustEngine{score: 85}
	srv := httptest.NewServer(http.HandlerFunc(te.handler))
	defer srv.Close()

	s := setupSidecar(t, srv.Listener.Addr().String())
	resp, err := s.Check(context.Background(), makeCheckRequest("", "/"))
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected denied response, got ok")
	}
	if denied.Status == nil || denied.Status.Code != 403 {
		t.Errorf("expected HTTP 403, got %v", denied.Status)
	}
}

func TestCheck_InvalidToken(t *testing.T) {
	te := &testTrustEngine{score: 85}
	srv := httptest.NewServer(http.HandlerFunc(te.handler))
	defer srv.Close()

	s := setupSidecar(t, srv.Listener.Addr().String())
	resp, err := s.Check(context.Background(), makeCheckRequest("[REDACTED:bearer-auth:22]", "/"))
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected denied response, got ok")
	}
}

func TestCheck_ValidToken_HighScore(t *testing.T) {
	te := &testTrustEngine{score: 85}
	srv := httptest.NewServer(http.HandlerFunc(te.handler))
	defer srv.Close()

	s := setupSidecar(t, srv.Listener.Addr().String())
	token := "Bearer " + makeJWT("test-sub", "test-session-001")
	resp, err := s.Check(context.Background(), makeCheckRequest(token, "/app"))
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatal("expected ok response, got denied")
	}

	hdrs := headerMap(ok.Headers)
	if hdrs["x-session-id"] != "test-session-001" {
		t.Errorf("x-session-id = %q, want test-session-001", hdrs["x-session-id"])
	}
	if hdrs["x-current-user"] != "testuser" {
		t.Errorf("x-current-user = %q, want testuser", hdrs["x-current-user"])
	}
	if hdrs["x-tenant-id"] != "ztna" {
		t.Errorf("x-tenant-id = %q, want ztna", hdrs["x-tenant-id"])
	}
}

func TestCheck_ValidToken_LowScore(t *testing.T) {
	te := &testTrustEngine{score: 30}
	srv := httptest.NewServer(http.HandlerFunc(te.handler))
	defer srv.Close()

	s := setupSidecar(t, srv.Listener.Addr().String())
	token := "Bearer " + makeJWT("test-sub", "test-session-002")
	resp, err := s.Check(context.Background(), makeCheckRequest(token, "/app"))
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected denied for low score")
	}
}

func TestCheck_BlockedSession(t *testing.T) {
	te := &testTrustEngine{score: 85, blocked: true}
	srv := httptest.NewServer(http.HandlerFunc(te.handler))
	defer srv.Close()

	s := setupSidecar(t, srv.Listener.Addr().String())
	token := "Bearer " + makeJWT("test-sub", "test-session-003")
	resp, err := s.Check(context.Background(), makeCheckRequest(token, "/app"))
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected denied for blocked session")
	}
}

func TestCheck_TrustEngineUnreachable(t *testing.T) {
	s := setupSidecar(t, "127.0.0.1:1")
	token := "Bearer " + makeJWT("test-sub", "test-session-004")
	resp, err := s.Check(context.Background(), makeCheckRequest(token, "/app"))
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected denied when trust engine unreachable")
	}
}

func TestCheck_PathBasedPolicy(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		score  int
		denied bool
	}{
		{"server-high-score", "/server", 75, false},
		{"server-medium-score", "/server", 60, true},
		{"app-medium-score", "/app", 60, false},
		{"app-low-score", "/app", 40, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			te := &testTrustEngine{score: tc.score}
			srv := httptest.NewServer(http.HandlerFunc(te.handler))
			defer srv.Close()

			s := setupSidecar(t, srv.Listener.Addr().String())
			token := "Bearer " + makeJWT("test-sub", "test-session-path-"+tc.name)
			resp, err := s.Check(context.Background(), makeCheckRequest(token, tc.path))
			if err != nil {
				t.Fatalf("Check returned error: %v", err)
			}
			denied := resp.GetDeniedResponse() != nil
			if denied != tc.denied {
				t.Errorf("path=%s score=%d: denied=%v, want %v", tc.path, tc.score, denied, tc.denied)
			}
		})
	}
}

func TestCheck_TenantFromIssuer(t *testing.T) {
	te := &testTrustEngine{score: 85}
	srv := httptest.NewServer(http.HandlerFunc(te.handler))
	defer srv.Close()

	s := setupSidecar(t, srv.Listener.Addr().String())
	s.tenant = ""
	token := "Bearer " + makeJWTForIss("test-sub", "test-session-tenant", "https://auth.ztnaiitm.me/realms/ztna")
	resp, err := s.Check(context.Background(), makeCheckRequest(token, "/app"))
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatal("expected ok response, got denied")
	}
	if hdrs := headerMap(ok.Headers); hdrs["x-tenant-id"] != "ztna" {
		t.Errorf("x-tenant-id = %q, want ztna (derived from issuer)", hdrs["x-tenant-id"])
	}
}

func TestCheck_TenantFromIssuer_UnknownTenant(t *testing.T) {
	te := &testTrustEngine{score: 85}
	srv := httptest.NewServer(http.HandlerFunc(te.handler))
	defer srv.Close()

	s := setupSidecar(t, srv.Listener.Addr().String())
	s.tenant = ""
	token := "Bearer " + makeJWTForIss("test-sub", "test-session-acme", "https://auth.ztnaiitm.me/realms/acme")
	resp, err := s.Check(context.Background(), makeCheckRequest(token, "/app"))
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if resp.GetDeniedResponse() == nil {
		t.Fatal("expected denied for tenant with no installed policy")
	}
}

func TestCheck_NoPolicyLoaded(t *testing.T) {
	te := &testTrustEngine{score: 85}
	srv := httptest.NewServer(http.HandlerFunc(te.handler))
	defer srv.Close()

	pm := newPolicyManager()
	s := &opaSidecar{
		trustEngineAddr: srv.Listener.Addr().String(),
		tenant:          "ztna",
		expectedIssuer:  "https://auth.ztnaiitm.me/realms/ztna",
		policies:        pm,
	}
	token := "Bearer " + makeJWT("test-sub", "test-session-nopolicy")
	resp, err := s.Check(context.Background(), makeCheckRequest(token, "/app"))
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if resp.GetDeniedResponse() == nil {
		t.Fatal("expected denied when no policy is loaded")
	}
}

func TestPolicyReload(t *testing.T) {
	dir := makeRegoDir(t)
	pm := newPolicyManager()
	loadCachedPolicies(pm, []string{dir}, []string{"ztna"})

	stricter := `package ztna
default allow = false
allow { input.trust_score >= 90 }
`
	if err := pm.apply("ztna", "v2", []byte(stricter)); err != nil {
		t.Fatalf("apply v2: %v", err)
	}
	pq, version := pm.get("ztna")
	if pq == nil {
		t.Fatal("query lost after reload")
	}
	if version != "v2" {
		t.Errorf("version = %q, want v2", version)
	}
	allowed := evalAllow(t, pq, 85)
	if allowed {
		t.Error("score 85 still allowed after stricter policy")
	}

	if err := pm.apply("ztna", "v3", []byte("package ztna\nallow {")); err == nil {
		t.Fatal("expected parse error for broken policy")
	}
	_, version = pm.get("ztna")
	if version != "v2" {
		t.Errorf("version after failed reload = %q, want v2", version)
	}
}

func evalAllow(t *testing.T, pq *rego.PreparedEvalQuery, score int) bool {
	t.Helper()
	results, err := pq.Eval(context.Background(), rego.EvalInput(map[string]interface{}{"trust_score": score}))
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	return len(results) > 0 && results.Allowed()
}

func headerMap(headers []*envoy_core.HeaderValueOption) map[string]string {
	m := make(map[string]string)
	for _, h := range headers {
		if h.GetHeader() != nil {
			m[h.GetHeader().Key] = h.GetHeader().Value
		}
	}
	return m
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests for new health / metrics endpoints and helpers
// ──────────────────────────────────────────────────────────────────────────────

func TestHealthzHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	healthzHandler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("healthz = %d, want 200", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("healthz body not JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("healthz status = %q, want ok", body["status"])
	}
}

func TestReadyzHandler_NotReady(t *testing.T) {
	pm := newPolicyManager() // no policies loaded
	handler := readyzHandler(pm)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz (empty) = %d, want 503", w.Code)
	}
}

func TestReadyzHandler_Ready(t *testing.T) {
	dir := makeRegoDir(t)
	pm := newPolicyManager()
	loadCachedPolicies(pm, []string{dir}, []string{"ztna"})

	handler := readyzHandler(pm)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("readyz (loaded) = %d, want 200", w.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("readyz body not JSON: %v", err)
	}
	if body["status"] != "ready" {
		t.Errorf("readyz status = %q, want ready", body["status"])
	}
}

func TestMetricResult(t *testing.T) {
	if got := metricResult(nil); got != "success" {
		t.Errorf("metricResult(nil) = %q, want success", got)
	}
	if got := metricResult(fmt.Errorf("oops")); got != "error" {
		t.Errorf("metricResult(err) = %q, want error", got)
	}
}

func TestRegoSafePackage(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{"ztna", "ztna"},
		{"ztna-tenant-2", "ztna_tenant_2"},
		{"acme-corp", "acme_corp"},
	}
	for _, c := range cases {
		if got := regoSafePackage(c.input); got != c.want {
			t.Errorf("regoSafePackage(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}
