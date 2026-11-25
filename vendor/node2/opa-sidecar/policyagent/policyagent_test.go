package policyagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockPolicyServer implements the Policy Distribution API surface used by the
// client, with hooks for triggering policy changes and asserting call counts.
type mockPolicyServer struct {
	mu sync.Mutex

	policies   map[string]string // tenant -> rego content
	versions   map[string]string // tenant -> version
	changeCh   chan struct{}     // closed to wake up long-polls with a change
	connectors map[string]time.Time

	registerCount   int
	heartbeatCount  int
	deregisterCount int
	fetchCount      map[string]int
	lastRegistered  Connector // payload of the most recent register
}

func newMockPolicyServer() *mockPolicyServer {
	return &mockPolicyServer{
		policies:   map[string]string{},
		versions:   map[string]string{},
		changeCh:   make(chan struct{}),
		connectors: map[string]time.Time{},
		fetchCount: map[string]int{},
	}
}

// setPolicy installs a new policy version and wakes any pending long-polls.
func (m *mockPolicyServer) setPolicy(tenant, content string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies[tenant] = content
	m.versions[tenant] = sha256Hex([]byte(content))
	close(m.changeCh)
	m.changeCh = make(chan struct{})
}

func (m *mockPolicyServer) version(tenant string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.versions[tenant]
}

func (m *mockPolicyServer) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("GET /v1/policies", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		type entry struct {
			Tenant  string `json:"tenant"`
			Version string `json:"version"`
		}
		var out []entry
		for t, v := range m.versions {
			out = append(out, entry{Tenant: t, Version: v})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"policies": out})
	})

	mux.HandleFunc("GET /v1/policies/{tenant}", func(w http.ResponseWriter, r *http.Request) {
		tenant := r.PathValue("tenant")
		m.mu.Lock()
		content, ok := m.policies[tenant]
		m.fetchCount[tenant]++
		m.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		ver := m.version(tenant)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", `"`+ver+`"`)
		w.Header().Set("X-Policy-Version", ver)
		fmt.Fprint(w, content)
	})

	mux.HandleFunc("GET /v1/policies/{tenant}/changes", func(w http.ResponseWriter, r *http.Request) {
		tenant := r.PathValue("tenant")
		since := r.URL.Query().Get("since")
		timeout := 1 * time.Second
		if t := r.URL.Query().Get("timeout"); t != "" {
			if secs, err := time.ParseDuration(t + "s"); err == nil && secs < 60*time.Second {
				timeout = secs
			}
		}
		m.mu.Lock()
		version := m.versions[tenant]
		changeCh := m.changeCh
		m.mu.Unlock()
		if since == version && since != "" {
			// long-poll: hang until a change or the timeout elapses
			select {
			case <-changeCh:
			case <-time.After(timeout):
			case <-r.Context().Done():
				return
			}
			version = m.version(tenant)
			if since == version {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{"changed": false, "since": since})
				return
			}
		}
		m.mu.Lock()
		content := m.policies[tenant]
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"changed": true,
			"tenant":  tenant,
			"version": version,
			"policy":  content,
		})
	})

	mux.HandleFunc("POST /v1/connectors", func(w http.ResponseWriter, r *http.Request) {
		var c Connector
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		now := time.Now()
		if _, ok := m.connectors[c.ID]; !ok {
			m.connectors[c.ID] = now // keep first_seen
		}
		m.registerCount++
		m.lastRegistered = c
		m.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c)
	})

	mux.HandleFunc("POST /v1/connectors/{id}/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		m.mu.Lock()
		defer m.mu.Unlock()
		if _, ok := m.connectors[id]; !ok {
			http.NotFound(w, r)
			return
		}
		m.connectors[id] = time.Now()
		m.heartbeatCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "id": id})
	})

	mux.HandleFunc("DELETE /v1/connectors/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		m.mu.Lock()
		delete(m.connectors, id)
		m.deregisterCount++
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "removed", "id": id})
	})

	return mux
}

func startMock(t *testing.T, m *mockPolicyServer) string {
	t.Helper()
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	return srv.URL
}

const testPolicyV1 = `package ztna
default allow = false
allow { input.trust_score >= 50 }
`

const testPolicyV2 = `package ztna
default allow = false
allow { input.trust_score >= 90 }
`

func testClient(server string, cfg Config) *Client {
	cfg.Server = server
	cfg.ID = "test-connector"
	cfg.PollTimeout = 2 // keep test long-polls short
	return New(cfg)
}

func TestRegister(t *testing.T) {
	m := newMockPolicyServer()
	srv := startMock(t, m)
	c := testClient(srv, Config{Tenants: []string{"ztna"}})

	if err := c.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	m.mu.Lock()
	seen, ok := m.connectors["test-connector"]
	count := m.registerCount
	m.mu.Unlock()
	if !ok {
		t.Fatal("connector not registered on server")
	}
	if count != 1 {
		t.Errorf("register count = %d, want 1", count)
	}
	_ = seen
	m.mu.Lock()
	advertised := m.lastRegistered.Tenants
	m.mu.Unlock()
	if len(advertised) != 1 || advertised[0] != "ztna" {
		t.Errorf("advertised tenants = %v, want [ztna]", advertised)
	}

	// idempotent: registering again does not fail and still counts
	if err := c.Register(context.Background()); err != nil {
		t.Fatalf("re-Register: %v", err)
	}
	m.mu.Lock()
	count = m.registerCount
	m.mu.Unlock()
	if count != 2 {
		t.Errorf("re-register count = %d, want 2", count)
	}
}

func TestSignedPolicyCannotChangeTenant(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := "ztna"
			if foreign {
				tenant = "other"
			}
			json.NewEncoder(w).Encode(ChangesResponse{Changed: true, Tenant: tenant, Version: "v2", Policy: testPolicyV2})
		}))
		c := testClient(server.URL, Config{})
		_, err := c.PollChanges(context.Background(), "ztna", "v1")
		server.Close()
		if (err != nil) != foreign {
			t.Fatal("foreign policy response was not rejected")
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Policy-Version", "v1")
		w.Header().Set("X-Policy-Signature", "invalid-signature")
		fmt.Fprint(w, testPolicyV1)
	}))
	defer server.Close()
	c := testClient(server.URL, Config{SigningKey: "disposable-test-signing-key"})
	if _, _, err := c.FetchPolicy(context.Background(), "ztna"); err == nil {
		t.Fatal("invalid signature accepted")
	}
}

func TestFailedApplyRetriesWithoutAdvancingVersion(t *testing.T) {
	m := newMockPolicyServer()
	m.setPolicy("ztna", testPolicyV2)
	server := startMock(t, m)
	dir := t.TempDir()
	if err := WritePolicyFiles(dir, "ztna", "old", []byte(testPolicyV1)); err != nil {
		t.Fatal(err)
	}
	c := testClient(server, Config{OutDir: dir})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	calls := 0
	c.pollLoop(ctx, "ztna", func(_, _ string, _ []byte) error {
		calls++
		if calls == 1 {
			return errors.New("test activation failure")
		}
		cancel()
		return nil
	})
	if calls != 2 || c.Version("ztna") != m.version("ztna") {
		t.Fatal("failed activation advanced poll version and prevented retry")
	}
}

func TestHeartbeatReRegistersOn404(t *testing.T) {
	m := newMockPolicyServer()
	srv := startMock(t, m)
	c := testClient(srv, Config{Tenants: []string{"ztna"}})

	// heartbeat before registering → 404 → client re-registers
	if err := c.Heartbeat(context.Background()); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	m.mu.Lock()
	reg := m.registerCount
	_, ok := m.connectors["test-connector"]
	m.mu.Unlock()
	if reg != 1 {
		t.Errorf("re-register count = %d, want 1", reg)
	}
	if !ok {
		t.Error("connector not present after auto re-register")
	}

	// now it heartbeats cleanly
	if err := c.Heartbeat(context.Background()); err != nil {
		t.Fatalf("second Heartbeat: %v", err)
	}
}

func TestFetchPolicy(t *testing.T) {
	m := newMockPolicyServer()
	m.setPolicy("ztna", testPolicyV1)
	srv := startMock(t, m)
	c := testClient(srv, Config{Tenants: []string{"ztna"}})

	version, content, err := c.FetchPolicy(context.Background(), "ztna")
	if err != nil {
		t.Fatalf("FetchPolicy: %v", err)
	}
	if version != m.version("ztna") {
		t.Errorf("version = %q, want %q", version, m.version("ztna"))
	}
	if string(content) != testPolicyV1 {
		t.Errorf("content mismatch:\n%s", content)
	}
}

func TestFetchPolicyNotFound(t *testing.T) {
	m := newMockPolicyServer()
	srv := startMock(t, m)
	c := testClient(srv, Config{Tenants: []string{"ztna"}})

	_, _, err := c.FetchPolicy(context.Background(), "nope")
	var nf *NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected NotFoundError, got %v", err)
	}
}

func TestInitialSyncAppliesAndDiscovers(t *testing.T) {
	m := newMockPolicyServer()
	m.setPolicy("ztna", testPolicyV1)
	srv := startMock(t, m)

	// empty Tenants → discovered from /v1/policies
	c := testClient(srv, Config{})
	var applied []string
	apply := func(tenant, version string, content []byte) error {
		applied = append(applied, tenant+":"+string(content))
		return nil
	}
	if err := c.InitialSync(context.Background(), apply); err != nil {
		t.Fatalf("InitialSync: %v", err)
	}
	if len(applied) != 1 || applied[0] != "ztna:"+testPolicyV1 {
		t.Fatalf("apply not called with discovered tenant, got %v", applied)
	}
	if len(c.tenants) != 1 || c.tenants[0] != "ztna" {
		t.Errorf("resolved tenants = %v, want [ztna]", c.tenants)
	}
}

func TestPollChangesImmediateWhenVersionDiffers(t *testing.T) {
	m := newMockPolicyServer()
	m.setPolicy("ztna", testPolicyV1)
	srv := startMock(t, m)
	c := testClient(srv, Config{Tenants: []string{"ztna"}})

	cr, err := c.PollChanges(context.Background(), "ztna", "stale-version")
	if err != nil {
		t.Fatalf("PollChanges: %v", err)
	}
	if !cr.Changed {
		t.Fatal("expected changed:true for stale since")
	}
	if cr.Version != m.version("ztna") || cr.Policy != testPolicyV1 {
		t.Errorf("unexpected changes response: %+v", cr)
	}
}

func TestPollChangesHangsUntilChange(t *testing.T) {
	m := newMockPolicyServer()
	m.setPolicy("ztna", testPolicyV1)
	srv := startMock(t, m)
	c := testClient(srv, Config{Tenants: []string{"ztna"}})
	ver := m.version("ztna")

	done := make(chan *ChangesResponse, 1)
	errCh := make(chan error, 1)
	go func() {
		cr, err := c.PollChanges(context.Background(), "ztna", ver)
		if err != nil {
			errCh <- err
			return
		}
		done <- cr
	}()

	select {
	case cr := <-done:
		t.Fatalf("poll returned early before change: %+v", cr)
	case err := <-errCh:
		t.Fatalf("poll errored early: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	// trigger a change → the hanging poll should return changed:true
	go func() {
		time.Sleep(100 * time.Millisecond)
		m.setPolicy("ztna", testPolicyV2)
	}()

	select {
	case cr := <-done:
		if !cr.Changed || cr.Version != m.version("ztna") || cr.Policy != testPolicyV2 {
			t.Errorf("unexpected change response: %+v", cr)
		}
	case err := <-errCh:
		t.Fatalf("poll errored: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("poll did not return after policy change")
	}
}

func TestPollChangesTimeoutReturnsChangedFalse(t *testing.T) {
	m := newMockPolicyServer()
	m.setPolicy("ztna", testPolicyV1)
	srv := startMock(t, m)
	c := testClient(srv, Config{Tenants: []string{"ztna"}})
	ver := m.version("ztna")

	start := time.Now()
	cr, err := c.PollChanges(context.Background(), "ztna", ver)
	if err != nil {
		t.Fatalf("PollChanges: %v", err)
	}
	if cr.Changed {
		t.Fatal("expected changed:false on timeout")
	}
	if time.Since(start) < 500*time.Millisecond {
		t.Error("long-poll returned too quickly — server did not hold it")
	}
}

func TestWritePolicyFilesAtomic(t *testing.T) {
	dir := t.TempDir()
	tenant, version, content := "ztna", "abc123", "package ztna\n"

	if err := WritePolicyFiles(dir, tenant, version, []byte(content)); err != nil {
		t.Fatalf("WritePolicyFiles: %v", err)
	}
	rego, err := os.ReadFile(filepath.Join(dir, tenant+".rego"))
	if err != nil || string(rego) != content {
		t.Errorf("rego file wrong: %q err=%v", rego, err)
	}
	v, err := os.ReadFile(filepath.Join(dir, tenant+".version"))
	if err != nil || strings.TrimSpace(string(v)) != version {
		t.Errorf("version file wrong: %q err=%v", v, err)
	}
	if _, err := os.Stat(filepath.Join(dir, tenant+".rego.tmp")); !os.IsNotExist(err) {
		t.Error("leftover .tmp file after write")
	}
}

func TestVersionPersistedAndRead(t *testing.T) {
	dir := t.TempDir()
	c := &Client{cfg: Config{OutDir: dir}}
	if got := c.Version("ztna"); got != "" {
		t.Errorf("Version before write = %q, want empty", got)
	}
	WritePolicyFiles(dir, "ztna", "v-1", []byte("x"))
	if got := c.Version("ztna"); got != "v-1" {
		t.Errorf("Version after write = %q, want v-1", got)
	}
}

// TestRunFullLifecycle exercises register → initial pull → long-poll change →
// heartbeat, and that cancellation stops everything cleanly.
func TestRunFullLifecycle(t *testing.T) {
	m := newMockPolicyServer()
	m.setPolicy("ztna", testPolicyV1)
	srv := startMock(t, m)

	cfg := Config{Tenants: []string{"ztna"}, HeartbeatEvery: 150 * time.Millisecond, PollTimeout: 2}
	cfg.Server = srv
	cfg.ID = "lifecycle-connector"
	cfg.OutDir = t.TempDir()
	c := New(cfg)

	var (
		mu      sync.Mutex
		applied []string
	)
	apply := func(tenant, version string, content []byte) error {
		mu.Lock()
		applied = append(applied, version)
		mu.Unlock()
		return nil
	}

	if err := c.InitialSync(context.Background(), apply); err != nil {
		t.Fatalf("InitialSync: %v", err)
	}
	mu.Lock()
	initialCount := len(applied)
	mu.Unlock()
	if initialCount != 1 {
		t.Fatalf("initial apply count = %d, want 1", initialCount)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, apply) }()

	// let the poll loop settle on the current version, then push a change
	time.Sleep(300 * time.Millisecond)
	m.setPolicy("ztna", testPolicyV2)

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(applied)
		mu.Unlock()
		if n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("policy change not applied, applied=%d", n)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// heartbeat loop must be ticking
	m.mu.Lock()
	hb := m.heartbeatCount
	m.mu.Unlock()
	if hb == 0 {
		t.Error("no heartbeats observed")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// TestRunSurvivesServerDown proves the client never crashes when the API is
// unreachable and keeps running until the context is cancelled.
func TestRunSurvivesServerDown(t *testing.T) {
	c := New(Config{
		Server:         "http://127.0.0.1:1", // nothing listening
		ID:             "down-connector",
		Tenants:        []string{"ztna"},
		PollTimeout:    1,
		HeartbeatEvery: 100 * time.Millisecond,
		RetryInterval:  200 * time.Millisecond,
	})
	applied := 0
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, func(string, string, []byte) error { applied++; return nil }) }()

	time.Sleep(400 * time.Millisecond) // several failed polls + heartbeats
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if applied != 0 {
		t.Errorf("apply called %d times with server down", applied)
	}
}

func TestDeregister(t *testing.T) {
	m := newMockPolicyServer()
	srv := startMock(t, m)
	c := testClient(srv, Config{Tenants: []string{"ztna"}})

	if err := c.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := c.Deregister(context.Background()); err != nil {
		t.Fatalf("Deregister: %v", err)
	}
	m.mu.Lock()
	_, ok := m.connectors["test-connector"]
	m.mu.Unlock()
	if ok {
		t.Error("connector still registered after Deregister")
	}
}
