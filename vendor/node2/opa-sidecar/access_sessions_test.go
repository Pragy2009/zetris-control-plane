package main

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

func TestAccessV1IdleExpiryRequiresFreshAuthentication(t *testing.T) {
	s, _, _ := v1Fixture(t, "ztna")
	now := v1FixtureNow
	s.accessV1.Now = func() time.Time { return time.Unix(now, 0) }
	c := v1ClaimsFixture(s, []string{"viewer"})
	r := v1Req(t, s, "GET", "/juice/", c)
	result := v1Check(t, s, r, true)
	metadata := result.GetDynamicMetadata().GetFields()
	if metadata["access_policy_application"].GetStringValue() != "workspace" || metadata["access_policy_access_rule"].GetStringValue() != "human-application-access" || metadata["access_policy_timeout_rule"].GetStringValue() != "default" || metadata["access_policy_action"].GetStringValue() != "allow" || int64(metadata["access_policy_valid_until"].GetNumberValue()) != now+900 {
		t.Fatal("application/session evidence missing")
	}
	now += 900
	c["iat"] = now // A refreshed token retains the original login.
	c["exp"] = now + 3600
	result = v1Check(t, s, v1Req(t, s, "GET", "/juice/", c), false)
	if result.GetDeniedResponse().GetStatus().GetCode() != envoy_type.StatusCode_Unauthorized || result.GetDeniedResponse().GetBody() != "idle_session_expired" {
		t.Fatal("idle expiry did not require reauthentication")
	}
	// Changing the session header has no effect on the verified key.
	r = v1Req(t, s, "GET", "/juice/", c)
	r.Attributes.Request.Http.Headers["x-session-id"] = "new-session"
	v1Check(t, s, r, false)
	c["auth_time"] = now
	v1Check(t, s, v1Req(t, s, "GET", "/juice/", c), true)
}

func TestAccessV1MaximumLifetimeAndRestartRequireAuthentication(t *testing.T) {
	s, trust, _ := v1Fixture(t, "ztna")
	now := v1FixtureNow
	s.accessV1.Now = func() time.Time { return time.Unix(now, 0) }
	c := v1ClaimsFixture(s, []string{"viewer"})
	c["exp"] = now + 10000
	v1Check(t, s, v1Req(t, s, "GET", "/juice/", c), true)
	now += 3570 // The original auth_time was start-30: exactly one hour.
	c["iat"] = now
	result := v1Check(t, s, v1Req(t, s, "GET", "/juice/", c), false)
	if result.GetDynamicMetadata().GetFields()["access_policy_action"].GetStringValue() != "reauthenticate" {
		t.Fatal("maximum lifetime was not enforced")
	}
	c["auth_time"] = now
	v1Check(t, s, v1Req(t, s, "GET", "/juice/", c), true)
	now++
	s.accessV1.Sessions = newV1SessionTracker(now, 10000)
	result = v1Check(t, s, v1Req(t, s, "GET", "/juice/", c), false)
	if result.GetDeniedResponse().GetBody() != "session_history_requires_reauthentication" {
		t.Fatal("restart silently reset idle history")
	}
	now++
	c["auth_time"] = now
	c["iat"] = now
	v1Check(t, s, v1Req(t, s, "GET", "/juice/", c), true)
	trust.response.Blocked = true
	result = v1Check(t, s, v1Req(t, s, "GET", "/juice/", c), false)
	if result.GetDynamicMetadata().GetFields()["access_policy_action"].GetStringValue() != "deny" {
		t.Fatal("fresh login bypassed retained session block")
	}
}

func TestAccessV1TrustedContextDoesNotAcceptPostureOrSourceHeaders(t *testing.T) {
	s, trust, _ := v1Fixture(t, "ztna")
	r := v1Req(t, s, "GET", "/juice/", v1ClaimsFixture(s, []string{"viewer"}))
	for k, v := range map[string]string{"x-device-verified": "true", "x-device-managed": "true", "x-edr-healthy": "true", "x-device-observed-at": fmt.Sprint(v1FixtureNow), "x-forwarded-for": "100.64.0.10", "x-client-type": "full_client"} {
		r.Attributes.Request.Http.Headers[k] = v
	}
	p, err := s.v1Principal(r, v1FixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	score, err := s.fetchScoreGRPC(context.Background(), p.Session, s.tenant, p.Subject)
	if err != nil {
		t.Fatal(err)
	}
	input, err := s.v1Request(r, p, score, v1FixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	if input.Device["verified"] != false || len(input.Device) != 1 || input.Context["source_ip"] == "100.64.0.10" || input.Context["client_type"] != "envoy_http" || trust.calls != 1 {
		t.Fatal("untrusted posture/source context entered policy input")
	}
}

func TestAccessSessionKeysAndReplayState(t *testing.T) {
	limits := v1SessionConstraints{Reauth: 1000, Idle: 10, Max: 1000}
	p := v1Principal{Tenant: "t1", Subject: "alice", Session: "sid", Kind: "human", AuthTime: 1000}
	s := newV1SessionTracker(900, 100)
	if got, _ := s.authorize(p, "workspace", limits, 1000); got != "" {
		t.Fatal(got)
	}
	if got, _ := s.authorize(p, "workspace", limits, 1010); got != "idle_session_expired" {
		t.Fatal(got)
	}
	// A more permissive reload must not resurrect an expired session segment.
	loose := v1SessionConstraints{Reauth: 2000, Idle: 100, Max: 2000}
	if got, _ := s.authorize(p, "workspace", loose, 1011); got != "idle_session_expired" {
		t.Fatal(got)
	}
	variants := []struct {
		name    string
		p       v1Principal
		segment string
	}{
		{"other segment", p, "files"},
		{"other tenant", v1Principal{Tenant: "t2", Subject: "alice", Session: "sid", Kind: "human", AuthTime: 1000}, "workspace"},
		{"other subject", v1Principal{Tenant: "t1", Subject: "bob", Session: "sid", Kind: "human", AuthTime: 1000}, "workspace"},
		{"other session", v1Principal{Tenant: "t1", Subject: "alice", Session: "other", Kind: "human", AuthTime: 1000}, "workspace"},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			if got, _ := s.authorize(v.p, v.segment, limits, 1011); got != "" {
				t.Fatal(got)
			}
		})
	}
	p.AuthTime = 1012
	if got, _ := s.authorize(p, "workspace", limits, 1012); got != "" {
		t.Fatal(got)
	}
	p.AuthTime = 1000
	if got, _ := s.authorize(p, "workspace", limits, 1013); got != "stale_authentication_or_clock" {
		t.Fatal(got)
	}
}

func TestAccessSessionHardDeadlineSurvivesRelaxedPolicy(t *testing.T) {
	s := newV1SessionTracker(900, 10)
	p := v1Principal{Tenant: "t1", Subject: "alice", Session: "sid", Kind: "human", AuthTime: 1000}
	short := v1SessionConstraints{Reauth: 50, Idle: 1000, Max: 50}
	loose := v1SessionConstraints{Reauth: 2000, Idle: 1000, Max: 2000}
	if got, _ := s.authorize(p, "workspace", short, 1000); got != "" {
		t.Fatal(got)
	}
	if got, deadline := s.authorize(p, "workspace", loose, 1020); got != "" || deadline != 1050 {
		t.Fatalf("result=%q deadline=%d; expected original hard deadline 1050", got, deadline)
	}
	if got, _ := s.authorize(p, "workspace", loose, 1050); got != "previous_session_limit_expired" {
		t.Fatal(got)
	}
}

func TestAccessSessionCapacityAndSafeRetention(t *testing.T) {
	s := newV1SessionTracker(900, 1)
	p := v1Principal{Tenant: "t1", Subject: "alice", Session: "sid", Kind: "human", AuthTime: 1000}
	limits := v1SessionConstraints{Reauth: 3600, Idle: 10, Max: 3600}
	if got, _ := s.authorize(p, "workspace", limits, 1000); got != "" {
		t.Fatal(got)
	}
	other := p
	other.Session = "other"
	if got, _ := s.authorize(other, "workspace", limits, 1011); got != "session_capacity_reached" {
		t.Fatal(got)
	}
	if got, _ := s.authorize(p, "workspace", limits, 1011); got != "idle_session_expired" {
		t.Fatal(got)
	}
	now := int64(1000) + v1MaximumSessionSeconds
	other.AuthTime = now
	if got, _ := s.authorize(other, "workspace", limits, now); got != "" {
		t.Fatal(got)
	}
	if got, _ := s.authorize(p, "workspace", limits, now); got != "reauthentication_required" {
		t.Fatal(got)
	}
}

func TestAccessSessionConcurrentRequestsCannotReviveIdleState(t *testing.T) {
	s := newV1SessionTracker(900, 100)
	p := v1Principal{Tenant: "t1", Subject: "alice", Session: "sid", Kind: "human", AuthTime: 1000}
	limits := v1SessionConstraints{Reauth: 1000, Idle: 10, Max: 1000}
	for _, round := range []struct {
		now  int64
		want string
	}{{1000, ""}, {1010, "idle_session_expired"}} {
		var wg sync.WaitGroup
		errors := make(chan string, 32)
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if got, _ := s.authorize(p, "workspace", limits, round.now); got != round.want {
					errors <- got
				}
			}()
		}
		wg.Wait()
		close(errors)
		for got := range errors {
			t.Errorf("result=%q want=%q", got, round.want)
		}
	}
	if len(s.records) != 1 {
		t.Fatal("duplicate replay state")
	}
}
