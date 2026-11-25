// Package policyagent implements the Policy Distribution API client that keeps
// an app connector's OPA Rego policies in sync with Node 1's trust-engine.
//
// The sync protocol (as specified by the Policy Distribution API):
//
//	register → initial pull (all tenants) → [ heartbeat every 30s ]
//	→ per tenant: long-poll /v1/policies/{tenant}/changes → apply → repeat
//
// The client never crashes on a failed poll: it keeps the last-known-good
// policy and retries with exponential backoff.
//
// Since the hardening pass, the client OPTIONALLY verifies an HMAC-SHA256
// signature over "<version>\n<content>" on every fetched policy when
// Config.SigningKey is set. A missing or invalid signature is treated as a
// failed fetch — the previous policy stays in effect (fail-closed). When no
// signing key is configured, the legacy behavior (no verification) is kept
// for backwards compatibility with unsigned policy servers.
package policyagent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Protocol defaults per the Policy Distribution API contract.
const (
	DefaultPollTimeout    = 50               // seconds; the server requires < 60
	DefaultHeartbeatEvery = 30 * time.Second // well under the server's 90s TTL
	DefaultRetryInterval  = 30 * time.Second
	maxPolicyBytes        = 1 << 20
)

// Policy is one tenant entry from GET /v1/policies.
type Policy struct {
	Tenant    string    `json:"tenant"`
	Version   string    `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

type policiesResponse struct {
	Policies []Policy `json:"policies"`
}

// ChangesResponse is the body of GET /v1/policies/{tenant}/changes.
type ChangesResponse struct {
	Changed   bool   `json:"changed"`
	Tenant    string `json:"tenant"`
	Version   string `json:"version"`
	Policy    string `json:"policy"`
	Signature string `json:"signature"` // HMAC-SHA256 over version+"\n"+policy ("" when server unsigned)
	Updated   string `json:"updated"`
	Since     string `json:"since"`
}

// Connector is the registration payload for POST /v1/connectors.
type Connector struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Endpoint string   `json:"endpoint"`
	Tenants  []string `json:"tenants"`
}

// NotFoundError is returned when the server has no entry for a tenant (404).
type NotFoundError struct {
	Tenant string
	What   string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("%s %q not found on policy server", e.What, e.Tenant)
}

// ApplyFunc receives a tenant's newly fetched policy. It must parse and install
// the policy before returning; on error the previous policy stays in effect.
type ApplyFunc func(tenant, version string, content []byte) error

// Config holds the client's static configuration.
type Config struct {
	Server   string   // base URL, e.g. http://<node1-mesh-ip>:50553
	ID       string   // connector id (required, unique per connector)
	Name     string   // display name
	Endpoint string   // address the connector is reachable at
	Tenants  []string // tenants to sync; empty = discover from GET /v1/policies
	OutDir   string   // where <tenant>.rego + <tenant>.version are persisted

	// SigningKey is the shared HMAC-SHA256 secret used to verify policy
	// signatures served by the policy API (POLICY_SIGNING_KEY). When non-empty
	// every fetched policy is verified and a bad signature is rejected.
	SigningKey string
	TLSConfig  *tls.Config

	// Optional tuning (zero values select defaults).
	HeartbeatEvery time.Duration
	PollTimeout    int           // seconds, must be < 60
	RetryInterval  time.Duration // max backoff between retries
}

// Client is a Policy Distribution API client.
type Client struct {
	cfg     Config
	hc      *http.Client
	tenants []string

	mu         sync.Mutex
	registered bool
}

// New creates a Client. The HTTP client timeout is set to pollTimeout + margin
// so long-polls complete without being cut short by the client.
func New(cfg Config) *Client {
	pollTimeout := cfg.PollTimeout
	if pollTimeout <= 0 || pollTimeout >= 60 {
		pollTimeout = DefaultPollTimeout
	}
	return &Client{
		cfg:     cfg,
		tenants: append([]string(nil), cfg.Tenants...),
		hc: &http.Client{
			Timeout:       time.Duration(pollTimeout+10) * time.Second,
			Transport:     &http.Transport{TLSClientConfig: cfg.TLSConfig},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (c *Client) base() string { return strings.TrimSuffix(c.cfg.Server, "/") }

func (c *Client) url(path string) string { return c.base() + path }

func (c *Client) pollTimeout() int {
	if c.cfg.PollTimeout > 0 && c.cfg.PollTimeout < 60 {
		return c.cfg.PollTimeout
	}
	return DefaultPollTimeout
}

// Register POSTs this connector to /v1/connectors. Registration is idempotent:
// re-registering refreshes last_seen on the server and keeps first_seen.
func (c *Client) Register(ctx context.Context) error {
	body, err := json.Marshal(Connector{
		ID:       c.cfg.ID,
		Name:     c.cfg.Name,
		Endpoint: c.cfg.Endpoint,
		Tenants:  c.tenants,
	})
	if err != nil {
		return fmt.Errorf("register: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/v1/connectors"), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register: server returned %d", resp.StatusCode)
	}
	c.mu.Lock()
	c.registered = true
	c.mu.Unlock()
	log.Printf("policy-agent: registered connector %q (name=%q tenants=%v)", c.cfg.ID, c.cfg.Name, c.tenants)
	return nil
}

// Heartbeat POSTs to /v1/connectors/{id}/heartbeat. When the server no longer
// knows the connector (404 — expired or never registered) it re-registers.
func (c *Client) Heartbeat(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.url("/v1/connectors/"+url.PathEscape(c.cfg.ID)+"/heartbeat"), nil)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		log.Printf("policy-agent: connector %q expired on server — re-registering", c.cfg.ID)
		return c.Register(ctx)
	default:
		return fmt.Errorf("heartbeat: server returned %d", resp.StatusCode)
	}
}

// Deregister best-effort DELETE of the connector, used on shutdown.
func (c *Client) Deregister(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		c.url("/v1/connectors/"+url.PathEscape(c.cfg.ID)), nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("deregister: server returned %d", resp.StatusCode)
	}
	log.Printf("policy-agent: deregistered connector %q", c.cfg.ID)
	return nil
}

// ListPolicies returns all tenants served by the policy server.
func (c *Client) ListPolicies(ctx context.Context) ([]Policy, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/v1/policies"), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list policies: server returned %d", resp.StatusCode)
	}
	var pr policiesResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&pr); err != nil {
		return nil, err
	}
	return pr.Policies, nil
}

// FetchPolicy GETs /v1/policies/{tenant} and returns the raw Rego plus the
// server-assigned version (X-Policy-Version or ETag header, else sha256(body)).
// When a signing key is configured the X-Policy-Signature header is verified
// and a mismatch is returned as an error (caller keeps its last-known-good).
func (c *Client) FetchPolicy(ctx context.Context, tenant string) (string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.url("/v1/policies/"+url.PathEscape(tenant)), nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		content, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicyBytes))
		if err != nil {
			return "", nil, err
		}
		version := resp.Header.Get("X-Policy-Version")
		if version == "" {
			version = strings.Trim(resp.Header.Get("ETag"), `"`)
		}
		if version == "" {
			version = sha256Hex(content)
		}
		if c.cfg.SigningKey != "" {
			sig := resp.Header.Get("X-Policy-Signature")
			if err := c.verifySignature(version, content, sig); err != nil {
				return "", nil, fmt.Errorf("policy %q: %w", tenant, err)
			}
		}
		return version, content, nil
	case http.StatusNotFound:
		return "", nil, &NotFoundError{Tenant: tenant, What: "policy"}
	default:
		return "", nil, fmt.Errorf("fetch policy %q: server returned %d", tenant, resp.StatusCode)
	}
}

// PollChanges long-polls /v1/policies/{tenant}/changes. It blocks until the
// tenant's policy changes (changed:true with the new policy), the server's
// timeout elapses (changed:false), or ctx is cancelled. The HTTP client
// timeout exceeds the timeout query param. When a signing key is configured,
// a changed payload with a bad signature is returned as an error.
func (c *Client) PollChanges(ctx context.Context, tenant, since string) (*ChangesResponse, error) {
	q := url.Values{}
	if since != "" {
		q.Set("since", since)
	}
	q.Set("timeout", strconv.Itoa(c.pollTimeout()))
	u := c.url("/v1/policies/"+url.PathEscape(tenant)+"/changes") + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var cr ChangesResponse
		if err := json.NewDecoder(io.LimitReader(resp.Body, 2*maxPolicyBytes)).Decode(&cr); err != nil {
			return nil, err
		}
		if cr.Changed && cr.Tenant != tenant {
			return nil, fmt.Errorf("policy response tenant does not match requested tenant")
		}
		if cr.Changed && c.cfg.SigningKey != "" {
			if err := c.verifySignature(cr.Version, []byte(cr.Policy), cr.Signature); err != nil {
				return nil, fmt.Errorf("tenant %q change: %w", tenant, err)
			}
		}
		return &cr, nil
	case http.StatusNotFound:
		return nil, &NotFoundError{Tenant: tenant, What: "tenant"}
	default:
		return nil, fmt.Errorf("poll changes %q: server returned %d", tenant, resp.StatusCode)
	}
}

// verifySignature checks the HMAC-SHA256 signature over version+"\n"+content.
// When the server did not sign at all (empty sig) this is a hard failure when
// the client expects signing: fail-closed rather than install an unsigned
// policy that could have been tampered with.
func (c *Client) verifySignature(version string, content []byte, sig string) error {
	if sig == "" {
		return errors.New("policy signature missing (server not signing?) — refusing to install")
	}
	want := c.sign(version, content)
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return errors.New("policy signature mismatch — refusing to install")
	}
	return nil
}

func (c *Client) sign(version string, content []byte) string {
	mac := hmac.New(sha256.New, []byte(c.cfg.SigningKey))
	mac.Write([]byte(version))
	mac.Write([]byte("\n"))
	mac.Write(content)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// InitialSync registers the connector and pulls the latest policy for every
// tenant, so a connector never starts with zero policy. Tenants configured as
// empty are discovered from GET /v1/policies. On partial failure the already
// applied tenants are kept and the first error is returned (caller keeps its
// last-known-good policies).
func (c *Client) InitialSync(ctx context.Context, apply ApplyFunc) error {
	if err := c.Register(ctx); err != nil {
		return fmt.Errorf("register: %w", err)
	}
	if len(c.tenants) == 0 {
		ps, err := c.ListPolicies(ctx)
		if err != nil {
			return fmt.Errorf("discover tenants: %w", err)
		}
		for _, p := range ps {
			c.tenants = append(c.tenants, p.Tenant)
		}
		log.Printf("policy-agent: discovered tenants %v from server", c.tenants)
	}
	var firstErr error
	for _, t := range c.tenants {
		version, content, err := c.FetchPolicy(ctx, t)
		if err != nil {
			log.Printf("policy-agent: initial pull %q failed: %v — keeping last-known-good", t, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := c.applyPolicy(apply, t, version, content); err != nil {
			log.Printf("policy-agent: initial apply %q failed: %v — keeping previous policy", t, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		log.Printf("policy-agent: installed %s v%s", t, shortVersion(version))
	}
	return firstErr
}

// Run executes the sync loop until ctx is cancelled: a heartbeat ticker plus a
// long-poll loop per tenant. InitialSync must have been called first. It never
// returns an error caused by a transient API failure — it keeps the
// last-known-good policy and retries with backoff.
func (c *Client) Run(ctx context.Context, apply ApplyFunc) error {
	hbEvery := c.cfg.HeartbeatEvery
	if hbEvery <= 0 {
		hbEvery = DefaultHeartbeatEvery
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.heartbeatLoop(ctx, hbEvery)
	}()
	for _, tenant := range c.tenants {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			c.pollLoop(ctx, t, apply)
		}(tenant)
	}
	wg.Wait()
	return nil
}

func (c *Client) heartbeatLoop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.Heartbeat(ctx); err != nil {
				log.Printf("policy-agent: heartbeat: %v", err)
			}
		}
	}
}

func (c *Client) pollLoop(ctx context.Context, tenant string, apply ApplyFunc) {
	// Resume from the version persisted on disk, so a restart that missed
	// changes long-polls correctly instead of re-applying stale policies.
	since := c.Version(tenant)
	backoff := time.Duration(0)
	for {
		if ctx.Err() != nil {
			return
		}
		cr, err := c.PollChanges(ctx, tenant, since)
		if err != nil {
			var nf *NotFoundError
			if errors.As(err, &nf) {
				log.Printf("policy-agent: tenant %q no longer on server — keeping last-known-good, will retry", tenant)
			} else {
				log.Printf("policy-agent: poll %q: %v — keeping last-known-good", tenant, err)
			}
			backoff = c.nextBackoff(backoff)
			if !sleepCtx(ctx, backoff) {
				return
			}
			continue
		}
		backoff = 0
		if cr.Changed {
			log.Printf("policy-agent: tenant %q changed → v%s", tenant, shortVersion(cr.Version))
			if err := c.applyPolicy(apply, tenant, cr.Version, []byte(cr.Policy)); err != nil {
				log.Printf("policy-agent: apply %q failed: %v — keeping previous policy", tenant, err)
				backoff = c.nextBackoff(backoff)
				if !sleepCtx(ctx, backoff) {
					return
				}
				continue
			}
			since = cr.Version
		} else {
			since = cr.Since
		}
	}
}

// applyPolicy hands a new policy to the ApplyFunc (in-memory install) and then
// persists it atomically to OutDir. The version file is written last so it
// marks the <tenant>.rego pair as committed.
func (c *Client) applyPolicy(apply ApplyFunc, tenant, version string, content []byte) error {
	if apply != nil {
		if err := apply(tenant, version, content); err != nil {
			return err
		}
	}
	if c.cfg.OutDir != "" {
		return WritePolicyFiles(c.cfg.OutDir, tenant, version, content)
	}
	return nil
}

func (c *Client) nextBackoff(current time.Duration) time.Duration {
	max := c.cfg.RetryInterval
	if max <= 0 {
		max = DefaultRetryInterval
	}
	if current <= 0 {
		return 2 * time.Second
	}
	current *= 2
	if current > max {
		current = max
	}
	return current
}

// Version returns the persisted policy version for a tenant ("" if none).
func (c *Client) Version(tenant string) string {
	b, err := os.ReadFile(filepath.Join(c.cfg.OutDir, tenant+".version"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// WritePolicyFiles atomically persists <tenant>.rego and <tenant>.version in
// dir: the Rego is written to a temp file and renamed into place, and the
// version file is written last as the commit marker.
func WritePolicyFiles(dir, tenant, version string, content []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	regoTmp := filepath.Join(dir, tenant+".rego.tmp")
	if err := os.WriteFile(regoTmp, content, 0o644); err != nil {
		return err
	}
	if err := os.Rename(regoTmp, filepath.Join(dir, tenant+".rego")); err != nil {
		os.Remove(regoTmp)
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, tenant+".version"), []byte(version+"\n"), 0o644); err != nil {
		return err
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func shortVersion(v string) string {
	if len(v) > 12 {
		return v[:12]
	}
	return v
}
