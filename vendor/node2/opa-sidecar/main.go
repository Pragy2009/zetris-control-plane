package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/open-policy-agent/opa/rego"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/wrapperspb"

	trustv1 "github.com/ztna/app-connector/opa-sidecar/gen/trust/v1"
	"github.com/ztna/app-connector/opa-sidecar/policyagent"
)

// ──────────────────────────────────────────────────────────────────────────────
// Prometheus metrics — exposed on the /metrics endpoint.
// ──────────────────────────────────────────────────────────────────────────────

var (
	checkTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "opa_check_total",
			Help: "Total OPA ext_authz Check calls, by tenant and result.",
		},
		[]string{"tenant", "result"}, // result ∈ {allow, deny, error}
	)
	checkDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "opa_check_duration_seconds",
			Help:    "OPA Check latency (seconds), by tenant.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		},
		[]string{"tenant"},
	)
	trustEngineCalls = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "opa_trust_engine_calls_total",
			Help: "Trust Engine lookup calls, by mode and result.",
		},
		[]string{"mode", "result"}, // mode ∈ {grpc, http}; result ∈ {success, error}
	)
	policyReloads = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "opa_policy_reloads_total",
			Help: "Policy install/reload attempts, by tenant and result.",
		},
		[]string{"tenant", "result"}, // result ∈ {success, error}
	)
)

func init() {
	prometheus.MustRegister(checkTotal, checkDuration, trustEngineCalls, policyReloads)
}

// ──────────────────────────────────────────────────────────────────────────────
// HTTP handlers for /healthz, /readyz, and /metrics.
// ──────────────────────────────────────────────────────────────────────────────

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok"}`)
}

// readyz returns 200 only after the policy manager has at least one tenant
// installed (or in static mode, after loadCachedPolicies ran).
func readyzHandler(pm *policyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pm.mu.RLock()
		n := len(pm.queries)
		pm.mu.RUnlock()
		if n == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"status":"not_ready","reason":"no policies loaded"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ready","tenants":%d}`, n)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// JWT / request types
// ──────────────────────────────────────────────────────────────────────────────

type jwtPayload struct {
	Sub               string `json:"sub"`
	SessionState      string `json:"session_state"`
	Sid               string `json:"sid"`
	PreferredUsername string `json:"preferred_username"`
	AuthorizedParty   string `json:"azp"`
	Iss               string `json:"iss"`
}

var demoUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type scoreResponse struct {
	SessionID     string `json:"session_id"`
	Score         int    `json:"score"`
	Blocked       bool   `json:"blocked"`
	RiskLevel     string `json:"risk_level,omitempty"` // M2: LOW|MEDIUM|HIGH|CRITICAL
	RiskFactors   string `json:"risk_factors,omitempty"`
	UserID        string `json:"user_id"`
	RiskUpdatedAt int64  `json:"risk_updated_at"`
}

// ──────────────────────────────────────────────────────────────────────────────
// policyManager — thread-safe per-tenant OPA query store
// ──────────────────────────────────────────────────────────────────────────────

// policyManager holds the currently installed OPA queries per tenant. It is
// safe for concurrent use: Check() reads under RLock while the sync agent
// swaps in freshly parsed policies under Lock.
type policyManager struct {
	mu       sync.RWMutex
	queries  map[string]*rego.PreparedEvalQuery
	versions map[string]string
	v1       map[string]bool
}

func newPolicyManager() *policyManager {
	return &policyManager{
		queries:  map[string]*rego.PreparedEvalQuery{},
		versions: map[string]string{},
		v1:       map[string]bool{},
	}
}

// get returns the prepared query and version installed for a tenant.
func (pm *policyManager) get(tenant string) (*rego.PreparedEvalQuery, string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.queries[tenant], pm.versions[tenant]
}

func policyV1(content []byte) bool {
	return strings.TrimSpace(strings.SplitN(string(content), "\n", 2)[0]) == "# zetris-access-policy: v1"
}

func (pm *policyManager) getWithMode(tenant string) (*rego.PreparedEvalQuery, string, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.queries[tenant], pm.versions[tenant], pm.v1[tenant]
}

// install prepares the legacy allow or v1 structured-decision contract.
func (pm *policyManager) install(tenant string, content []byte) (*rego.PreparedEvalQuery, error) {
	query := fmt.Sprintf("data.%s.allow", regoSafePackage(tenant))
	if policyV1(content) {
		query = fmt.Sprintf("data.%s.decision", regoSafePackage(tenant))
	}
	r := rego.New(
		rego.Query(query),
		rego.Module(tenant+".rego", string(content)),
	)
	pq, err := r.PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("prepare rego for tenant %q: %w", tenant, err)
	}
	if policyV1(content) {
		// Syntactically valid policies can still omit the decision contract.
		// Reject those before replacing the last-known-good installed policy.
		results, evalErr := pq.Eval(context.Background(), rego.EvalInput(map[string]interface{}{}))
		if evalErr != nil || len(results) != 1 || len(results[0].Expressions) != 1 {
			return nil, fmt.Errorf("v1 policy must deny missing context with a structured decision")
		}
		decision, parseErr := parseV1Decision(results[0].Expressions[0].Value)
		if parseErr != nil || decision.Allow {
			return nil, fmt.Errorf("v1 policy must deny missing context with a structured decision")
		}
	}
	return &pq, nil
}

// apply parses and installs a new policy version. On parse failure the previous
// policy stays in effect (fail-closed on reload, never a half-written policy).
func (pm *policyManager) apply(tenant, version string, content []byte) error {
	pq, err := pm.install(tenant, content)
	if err != nil {
		policyReloads.WithLabelValues(tenant, "error").Inc()
		return err
	}
	pm.mu.Lock()
	pm.queries[tenant] = pq
	pm.versions[tenant] = version
	pm.v1[tenant] = policyV1(content)
	pm.mu.Unlock()
	policyReloads.WithLabelValues(tenant, "success").Inc()
	slog.Info("policy reloaded",
		"tenant", tenant,
		"version", shortVersion(version),
	)
	return nil
}

// loadCachedPolicies loads <tenant>.rego files from dirs (first match wins)
// so a restart resumes with the last-known-good policy before syncing.
func loadCachedPolicies(pm *policyManager, dirs []string, tenants []string) {
	for _, t := range tenants {
		var content []byte
		var src string
		for _, d := range dirs {
			b, err := os.ReadFile(filepath.Join(d, t+".rego"))
			if err == nil {
				content = b
				src = d
				break
			}
		}
		if content == nil {
			continue
		}
		version := ""
		if v, err := os.ReadFile(filepath.Join(src, t+".version")); err == nil {
			version = strings.TrimSpace(string(v))
		}
		if err := pm.apply(t, version, content); err != nil {
			slog.Error("cached policy rejected",
				"tenant", t,
				"src", src,
				"error", err,
			)
			continue
		}
		slog.Info("loaded cached policy",
			"tenant", t,
			"src", src,
		)
	}
}

func shortVersion(v string) string {
	if len(v) > 12 {
		return v[:12]
	}
	return v
}

// ──────────────────────────────────────────────────────────────────────────────
// opaSidecar — gRPC ext_authz service + Trust Engine client
// ──────────────────────────────────────────────────────────────────────────────

type opaSidecar struct {
	trustEngineAddr string
	trustEngineMode string
	tenant          string
	expectedIssuer  string
	policies        *policyManager
	tlsConfig       *tls.Config
	trustConn       *grpc.ClientConn // one connection, opened once at startup
	trustClient     trustv1.TrustIngestClient
	accessV1        *accessV1Config
}

func extractBearer(authHeader string) string {
	for _, prefix := range []string{"Bearer ", "bearer "} {
		if strings.HasPrefix(authHeader, prefix) {
			return strings.TrimSpace(authHeader[len(prefix):])
		}
	}
	return ""
}

func decodeJWT(token string) (*jwtPayload, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("not a JWT: %d parts", len(parts))
	}
	payload := parts[1]
	padding := 4 - len(payload)%4
	if padding < 4 {
		payload += strings.Repeat("=", padding)
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	var p jwtPayload
	if err := json.Unmarshal(decoded, &p); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	return &p, nil
}

// regoSafePackage maps a tenant id (Keycloak realm name) to a Rego-safe
// package name: hyphens are not valid in Rego identifiers, so "ztna-tenant-2"
// becomes "ztna_tenant_2". Policy files must declare this sanitized package.
func regoSafePackage(tenant string) string {
	return strings.ReplaceAll(tenant, "-", "_")
}

// tenantFromIssuer extracts the tenant id from an OIDC issuer URL.
var safeTenantID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

func tenantFromIssuer(iss string) string {
	if iss == "" {
		return ""
	}
	u, err := url.Parse(iss)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return ""
	}
	path := strings.Trim(u.Path, "/")
	if path == "" {
		return ""
	}
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[len(parts)-2] != "realms" {
		return ""
	}
	tenant := parts[len(parts)-1]
	if !safeTenantID.MatchString(tenant) {
		return ""
	}
	return tenant
}

// Startup and request handling must agree on the one issuer/tenant served.
func connectorTenant(issuer, override string, tenants []string) (string, error) {
	tenant := tenantFromIssuer(issuer)
	if tenant == "" || (override != "" && override != tenant) {
		return "", fmt.Errorf("KEYCLOAK_ISSUER must identify this connector's TENANT over HTTPS")
	}
	if len(tenants) > 1 || (len(tenants) == 1 && tenants[0] != tenant) {
		return "", fmt.Errorf("one tenant per connector: TENANTS must match the issuer realm")
	}
	return tenant, nil
}

var TEDNS = "TEcert.local"

func loadTLS(certsDir string, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(certsDir, "client.crt"),
		filepath.Join(certsDir, "client.key"),
	)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	caCert, err := os.ReadFile(filepath.Join(certsDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

var httpClient = &http.Client{Timeout: 5 * time.Second}

func (s *opaSidecar) fetchScore(ctx context.Context, sessionID string) (*scoreResponse, error) {
	u := fmt.Sprintf("http://%s/score?session_id=%s", s.trustEngineAddr, url.QueryEscape(sessionID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return nil, fmt.Errorf("trust engine returned %d: %s", resp.StatusCode, strings.TrimSpace(buf.String()))
	}
	var sr scoreResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	return &sr, nil
}

func (s *opaSidecar) fetchScoreGRPC(ctx context.Context, sessionID, tenantID, userID string) (*scoreResponse, error) {
	resp, err := s.trustClient.LookupScore(ctx, &trustv1.LookupScoreRequest{
		SessionId: sessionID,
		TenantId:  tenantID,
		UserId:    userID,
	})
	if err != nil {
		return nil, fmt.Errorf("LookupScore: %w", err)
	}

	return &scoreResponse{
		SessionID:     resp.SessionId,
		Score:         int(resp.Score),
		Blocked:       resp.Blocked,
		RiskLevel:     resp.RiskLevel,
		RiskFactors:   resp.RiskFactors,
		UserID:        resp.UserId,
		RiskUpdatedAt: resp.RiskUpdatedAt,
	}, nil
}

// buildOPAInput combines the trust-engine LookupScore response with the Envoy
// ext_authz request attributes into the document evaluated by the policy.
func buildOPAInput(sub string, score *scoreResponse, httpReq *envoy_auth.AttributeContext_HttpRequest, src *envoy_auth.AttributeContext_Peer) map[string]interface{} {
	headers := make(map[string]string)
	for k, v := range httpReq.GetHeaders() {
		if strings.EqualFold(k, "authorization") || strings.EqualFold(k, "cookie") {
			continue
		}
		headers[k] = v
	}
	input := map[string]interface{}{
		"subject":      sub,
		"trust_score":  score.Score,
		"is_blocked":   score.Blocked,
		"risk_level":   score.RiskLevel,
		"risk_factors": score.RiskFactors,
		"attributes": map[string]interface{}{
			"request": map[string]interface{}{
				"http": map[string]interface{}{
					"path":    httpReq.GetPath(),
					"method":  httpReq.GetMethod(),
					"host":    httpReq.GetHost(),
					"scheme":  httpReq.GetScheme(),
					"headers": headers,
				},
			},
		},
	}
	if addr := src.GetAddress().GetSocketAddress(); addr != nil {
		input["source"] = map[string]interface{}{"address": addr.GetAddress()}
	}
	return input
}

func (s *opaSidecar) Check(ctx context.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {
	if s.accessV1 != nil {
		return s.checkAccessV1(ctx, req)
	}
	start := time.Now()
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	src := req.GetAttributes().GetSource()

	slog.Info("check request",
		"source", src.GetAddress().GetSocketAddress().GetAddress(),
		"host", httpReq.GetHost(),
		"method", httpReq.GetMethod(),
		"path", httpReq.GetPath(),
		"scheme", httpReq.GetScheme(),
	)

	headers := httpReq.GetHeaders()
	authHeader := headers["authorization"]
	if authHeader == "" {
		authHeader = headers["Authorization"]
	}

	token := extractBearer(authHeader)
	if token == "" {
		slog.Warn("missing authorization header",
			"path", httpReq.GetPath(),
		)
		checkTotal.WithLabelValues("", "deny").Inc()
		checkDuration.WithLabelValues("").Observe(time.Since(start).Seconds())
		return deny(codes.PermissionDenied, "missing authorization header"), nil
	}

	payload, err := decodeJWT(token)
	if err != nil {
		slog.Warn("invalid JWT",
			"error", err,
		)
		checkTotal.WithLabelValues("", "deny").Inc()
		checkDuration.WithLabelValues("").Observe(time.Since(start).Seconds())
		return deny(codes.PermissionDenied, "invalid token"), nil
	}

	sessionID := payload.SessionState
	if sessionID == "" {
		sessionID = payload.Sid
	}
	if sessionID == "" {
		sessionID = payload.Sub
	}
	if payload.AuthorizedParty == "zetris-risk-simulator" && payload.PreferredUsername == "service-account-zetris-risk-simulator" {
		run := httpReq.GetHeaders()["x-zetris-demo-run"]
		if !demoUUID.MatchString(run) || !demoUUID.MatchString(payload.Sub) {
			return deny(codes.PermissionDenied, "valid simulation run required"), nil
		}
		// Only this signed service identity may choose its own run namespace.
		// An ordinary user's header cannot replace their Keycloak session.
		sessionID = "sim-" + payload.Sub + "-" + run
	}
	if sessionID == "" {
		slog.Warn("no session id in token",
			"sub", payload.Sub,
		)
		checkTotal.WithLabelValues("", "deny").Inc()
		checkDuration.WithLabelValues("").Observe(time.Since(start).Seconds())
		return deny(codes.PermissionDenied, "no session id in token"), nil
	}

	// Envoy verifies signature/audience first. Bind the verified issuer to this
	// connector as well; a TENANT override must never relabel another realm.
	if s.expectedIssuer == "" || payload.Iss != s.expectedIssuer {
		return deny(codes.PermissionDenied, "issuer not served by connector"), nil
	}
	tenant := s.tenant
	if tenant != "" && tenantFromIssuer(payload.Iss) != tenant {
		return deny(codes.PermissionDenied, "tenant mismatch"), nil
	}
	if tenant == "" {
		tenant = tenantFromIssuer(payload.Iss)
	}
	if tenant == "" {
		slog.Warn("cannot determine tenant",
			"iss", payload.Iss,
		)
		checkTotal.WithLabelValues("", "deny").Inc()
		checkDuration.WithLabelValues("").Observe(time.Since(start).Seconds())
		return deny(codes.PermissionDenied, "cannot determine tenant"), nil
	}

	var score *scoreResponse
	if s.trustEngineMode == "grpc" {
		slog.Debug("fetching score via gRPC",
			"session", sessionID,
			"tenant", tenant,
			"user", payload.Sub,
		)
		score, err = s.fetchScoreGRPC(ctx, sessionID, tenant, payload.Sub)
		trustEngineCalls.WithLabelValues("grpc", metricResult(err)).Inc()
	} else {
		slog.Debug("fetching score via HTTP",
			"session", sessionID,
		)
		score, err = s.fetchScore(ctx, sessionID)
		trustEngineCalls.WithLabelValues("http", metricResult(err)).Inc()
	}
	if err != nil {
		slog.Error("trust engine call failed — denying",
			"error", err,
			"session", sessionID,
		)
		checkTotal.WithLabelValues(tenant, "deny").Inc()
		checkDuration.WithLabelValues(tenant).Observe(time.Since(start).Seconds())
		return deny(codes.PermissionDenied, "trust engine unavailable"), nil
	}

	if score.Blocked {
		slog.Warn("session blocked",
			"session", sessionID,
			"tenant", tenant,
			"score", score.Score,
		)
		checkTotal.WithLabelValues(tenant, "deny").Inc()
		checkDuration.WithLabelValues(tenant).Observe(time.Since(start).Seconds())
		return deny(codes.PermissionDenied, "session blocked"), nil
	}

	pq, version, v1 := s.policies.getWithMode(tenant)
	if v1 {
		return deny(codes.PermissionDenied, "policy schema requires ACCESS_POLICY_MODE=v1"), nil
	}
	if pq == nil {
		slog.Error("no policy loaded — denying (fail-closed)",
			"tenant", tenant,
		)
		checkTotal.WithLabelValues(tenant, "deny").Inc()
		checkDuration.WithLabelValues(tenant).Observe(time.Since(start).Seconds())
		return deny(codes.PermissionDenied, "no policy loaded"), nil
	}

	results, err := pq.Eval(ctx, rego.EvalInput(buildOPAInput(payload.Sub, score, httpReq, src)))
	if err != nil {
		slog.Error("policy evaluation failed",
			"error", err,
			"tenant", tenant,
		)
		checkTotal.WithLabelValues(tenant, "error").Inc()
		checkDuration.WithLabelValues(tenant).Observe(time.Since(start).Seconds())
		return deny(codes.PermissionDenied, "policy evaluation failed"), nil
	}

	if len(results) == 0 || !results.Allowed() {
		slog.Info("access denied by policy",
			"tenant", tenant,
			"version", shortVersion(version),
			"user", payload.PreferredUsername,
			"session", sessionID,
			"score", score.Score,
			"path", httpReq.GetPath(),
		)
		checkTotal.WithLabelValues(tenant, "deny").Inc()
		checkDuration.WithLabelValues(tenant).Observe(time.Since(start).Seconds())
		return deny(codes.PermissionDenied, "denied by policy"), nil
	}

	slog.Info("access allowed",
		"user", payload.PreferredUsername,
		"session", sessionID,
		"tenant", tenant,
		"score", score.Score,
		"path", httpReq.GetPath(),
	)
	checkTotal.WithLabelValues(tenant, "allow").Inc()
	checkDuration.WithLabelValues(tenant).Observe(time.Since(start).Seconds())
	return allow(map[string]string{
		"x-session-id":   sessionID,
		"x-current-user": payload.PreferredUsername,
		"x-tenant-id":    tenant,
	}), nil
}

// metricResult returns "success" when err is nil, "error" otherwise.
func metricResult(err error) string {
	if err != nil {
		return "error"
	}
	return "success"
}

func allow(hdrs map[string]string) *envoy_auth.CheckResponse {
	var headers []*envoy_core.HeaderValueOption
	for k, v := range hdrs {
		headers = append(headers, &envoy_core.HeaderValueOption{
			Header: &envoy_core.HeaderValue{
				Key:   k,
				Value: v,
			},
			Append: &wrapperspb.BoolValue{Value: false},
		})
	}
	return &envoy_auth.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &envoy_auth.CheckResponse_OkResponse{
			OkResponse: &envoy_auth.OkHttpResponse{
				Headers: headers,
			},
		},
	}
}

func deny(code codes.Code, body string) *envoy_auth.CheckResponse {
	return &envoy_auth.CheckResponse{
		Status: &status.Status{Code: int32(code)},
		HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Forbidden,
				},
				Body: body,
			},
		},
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// main
// ──────────────────────────────────────────────────────────────────────────────

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	addr := flag.String("addr", "0.0.0.0:9191", "gRPC listen address")
	metricsAddr := flag.String("metrics-addr", "0.0.0.0:9192", "Prometheus metrics + health listen address")
	trustEngineAddr := flag.String("trust-engine-addr", "", "Trust Engine address (host:port)")
	trustEngineMode := flag.String("trust-engine-mode", "", "grpc or http")
	policiesDir := flag.String("policies-dir", "", "path to Rego policies directory (static fallback)")
	certsDir := flag.String("certs-dir", "", "path to mTLS certificates")
	tenant := flag.String("tenant", "", "tenant id override; when empty, derived per-request from the JWT issuer (Keycloak realm)")
	policyServer := flag.String("policy-server", "", "Policy Distribution API base URL (e.g. http://<node1-mesh-ip>:50553)")
	tenants := flag.String("tenants", "", "comma-separated tenants to sync (default: the -tenant flag; when both unset, discover from the policy server)")
	connectorID := flag.String("connector-id", "", "connector id (default: hostname)")
	connectorName := flag.String("connector-name", "", "connector display name")
	connectorEndpoint := flag.String("connector-endpoint", "", "connector endpoint advertised to Node 1")
	outDir := flag.String("policy-out-dir", "", "writable dir for synced policies (default: <policies-dir>-live)")
	flag.Parse()

	if *policiesDir == "" {
		*policiesDir = getEnv("POLICIES_DIR", "/policies")
	}
	teAddr := flagOrEnv(trustEngineAddr, "TRUST_ENGINE_ADDR", "127.0.0.1:50052")
	teMode := flagOrEnv(trustEngineMode, "TRUST_ENGINE_MODE", "http")
	tlsDir := flagOrEnv(certsDir, "TLS_CERTS_DIR", "/certs")
	tenantID := flagOrEnv(tenant, "TENANT", "")
	expectedIssuer := getEnv("KEYCLOAK_ISSUER", "https://auth.ztnaiitm.me/realms/ztna")
	serverURL := flagOrEnv(policyServer, "POLICY_SERVER", "")
	if teMode != "grpc" || !strings.HasPrefix(serverURL, "https://") {
		log.Fatal("deployment requires mTLS gRPC scoring and an HTTPS policy API")
	}
	signingKey := getEnv("POLICY_SIGNING_KEY", "")
	id := flagOrEnv(connectorID, "CONNECTOR_ID", "")
	name := flagOrEnv(connectorName, "CONNECTOR_NAME", "")
	endpoint := flagOrEnv(connectorEndpoint, "CONNECTOR_ENDPOINT", "")
	tenantsCSV := flagOrEnv(tenants, "TENANTS", "")
	if id == "" {
		id = hostname()
	}

	tenantList := splitCSV(tenantsCSV)
	var tenantErr error
	tenantID, tenantErr = connectorTenant(expectedIssuer, tenantID, tenantList)
	if tenantErr != nil {
		log.Fatal(tenantErr)
	}
	if len(tenantList) == 0 && tenantID != "" {
		tenantList = []string{tenantID}
	}

	s := &opaSidecar{
		trustEngineAddr: teAddr,
		trustEngineMode: teMode,
		tenant:          tenantID,
		expectedIssuer:  expectedIssuer,
		policies:        newPolicyManager(),
	}
	accessConfig, accessErr := loadAccessV1Config(tenantID, expectedIssuer)
	if accessErr != nil {
		log.Fatal(accessErr)
	}
	s.accessV1 = accessConfig

	if teMode == "grpc" {
		tlsCfg, err := loadTLS(tlsDir, TEDNS)
		if err != nil {
			log.Fatalf("failed to load TLS config: %v", err)
		}
		s.tlsConfig = tlsCfg
		conn, err := grpc.NewClient(teAddr,
			grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		)
		if err != nil {
			log.Fatalf("failed to create trust engine client: %v", err)
		}
		s.trustConn = conn
		s.trustClient = trustv1.NewTrustIngestClient(conn)
		slog.Info("trust engine connected", "mode", "grpc", "addr", teAddr)
	} else {
		slog.Info("trust engine connected", "mode", "http", "addr", teAddr)
	}

	var (
		agent       *policyagent.Client
		agentCancel context.CancelFunc
	)
	if serverURL != "" {
		if !strings.HasPrefix(serverURL, "https://") || s.tlsConfig == nil {
			log.Fatal("policy sync requires HTTPS and connector mTLS credentials (TRUST_ENGINE_MODE=grpc)")
		}
		out := *outDir
		if out == "" {
			out = getEnv("POLICY_OUT_DIR", filepath.Join(*policiesDir, "-live"))
		}
		agent = policyagent.New(policyagent.Config{
			Server:     serverURL,
			ID:         id,
			Name:       name,
			Endpoint:   endpoint,
			Tenants:    tenantList,
			OutDir:     out,
			SigningKey: signingKey,
			TLSConfig:  s.tlsConfig.Clone(),
		})
		apply := func(t, v string, content []byte) error {
			return s.policies.apply(t, v, content)
		}

		loadCachedPolicies(s.policies, []string{out, *policiesDir}, tenantList)

		initCtx, initCancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := agent.InitialSync(initCtx, apply); err != nil {
			slog.Error("initial policy sync failed — serving cached", "error", err)
		}
		initCancel()

		agentCtx, cancel := context.WithCancel(context.Background())
		agentCancel = cancel
		go func() { _ = agent.Run(agentCtx, apply) }()
		slog.Info("policy sync agent running",
			"connector", id,
			"server", serverURL,
			"tenants", tenantList,
			"out", out,
			"signing", signingKey != "",
		)
	} else {
		if len(tenantList) == 0 {
			tenantList = regoFilesTenants(*policiesDir)
			if len(tenantList) == 0 {
				log.Fatalf("no tenants configured (TENANT/TENANTS) and no *.rego found in %s — refusing to start with zero policy", *policiesDir)
			}
		}
		loadCachedPolicies(s.policies, []string{*policiesDir}, tenantList)
		loaded := 0
		for _, t := range tenantList {
			if pq, _ := s.policies.get(t); pq != nil {
				loaded++
			}
		}
		if loaded == 0 {
			log.Fatalf("no policy found for tenants %v in %s — refusing to start with zero policy", tenantList, *policiesDir)
		}
	}

	// Metrics / health HTTP server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", healthzHandler)
	mux.HandleFunc("/readyz", readyzHandler(s.policies))
	metricsSrv := &http.Server{
		Addr:              *metricsAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		slog.Info("metrics server listening", "addr", *metricsAddr)
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics server failed", "error", err)
		}
	}()

	// gRPC ext_authz server
	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}

	gs := grpc.NewServer()
	envoy_auth.RegisterAuthorizationServer(gs, s)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Info("shutting down", "signal", sig)
		if agent != nil {
			dctx, dcancel := context.WithTimeout(context.Background(), 3*time.Second)
			if err := agent.Deregister(dctx); err != nil {
				slog.Warn("deregister failed (best-effort)", "error", err)
			}
			dcancel()
		}
		if agentCancel != nil {
			agentCancel()
		}
		if s.trustConn != nil {
			_ = s.trustConn.Close()
		}
		mctx, mcancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = metricsSrv.Shutdown(mctx)
		mcancel()
		gs.GracefulStop()
	}()

	slog.Info("OPA sidecar listening",
		"grpc_addr", *addr,
		"tenant_override", tenantID,
		"tenants", tenantList,
		"mode", teMode,
	)
	if err := gs.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func flagOrEnv(f *string, env, fallback string) string {
	if f != nil && *f != "" {
		return *f
	}
	return getEnv(env, fallback)
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func regoFilesTenants(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.Error("cannot list policies dir", "dir", dir, "error", err)
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if name := e.Name(); strings.HasSuffix(name, ".rego") {
			out = append(out, strings.TrimSuffix(name, ".rego"))
		}
	}
	sort.Strings(out)
	return out
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "app-connector"
	}
	return h
}
