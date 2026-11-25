package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSimulationSessionIsScopedToVerifiedServiceIdentity(t *testing.T) {
	const subject = "00000000-0000-4000-8000-000000000001"
	const run = "00000000-0000-4000-8000-000000000002"
	var session string
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		session = r.URL.Query().Get("session_id")
		w.Write([]byte(`{"score":100}`))
	}))
	defer upstream.Close()
	s := setupSidecar(t, upstream.Listener.Addr().String())
	token := func(client, user string) string {
		payload, _ := json.Marshal(jwtPayload{Sub: subject, SessionState: "ordinary-session", PreferredUsername: user, AuthorizedParty: client, Iss: s.expectedIssuer})
		return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
	}
	for _, tc := range []struct {
		client, user, run, want string
		denied                  bool
	}{
		{"ordinary-client", "ordinary-user", run, "ordinary-session", false},
		{"ordinary-client", "service-account-zetris-risk-simulator", run, "ordinary-session", false},
		{"zetris-risk-simulator", "ordinary-user", run, "ordinary-session", false},
		{"zetris-risk-simulator", "service-account-zetris-risk-simulator", run, "sim-" + subject + "-" + run, false},
		{"zetris-risk-simulator", "service-account-zetris-risk-simulator", "", "", true},
		{"zetris-risk-simulator", "service-account-zetris-risk-simulator", "foreign/session", "", true},
	} {
		req := makeCheckRequest("Bearer "+token(tc.client, tc.user), "/juice/")
		req.Attributes.Request.Http.Headers["x-zetris-demo-run"] = tc.run
		prior := calls
		_, err := s.Check(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if tc.denied {
			if calls != prior {
				t.Fatal("invalid demo session reached score lookup")
			}
		} else if session != tc.want {
			t.Fatalf("session=%q want %q", session, tc.want)
		}
	}
}
