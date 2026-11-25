package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWrongRealmRejectedBeforeScoreLookup(t *testing.T) {
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"score":100}`))
	}))
	defer upstream.Close()
	s := setupSidecar(t, upstream.Listener.Addr().String())
	for _, issuer := range []string{"https://auth.ztnaiitm.me/realms/ztna-tenant-2", "https://evil.example/realms/ztna", ""} {
		res, err := s.Check(context.Background(), makeCheckRequest("Bearer "+makeJWTForIss("u", "s", issuer), "/juice/"))
		if err != nil || res.GetDeniedResponse() == nil {
			t.Fatalf("issuer %q was not denied: %v", issuer, err)
		}
	}
	if calls != 0 {
		t.Fatalf("foreign realm caused %d score lookups", calls)
	}
}

func TestConnectorTenantConfiguration(t *testing.T) {
	issuer := "https://auth.ztnaiitm.me/realms/ztna"
	for _, tc := range []struct {
		issuer, tenant string
		tenants        []string
		valid          bool
	}{
		{issuer, "ztna", []string{"ztna"}, true},
		{issuer, "", nil, true},
		{"https://auth.ztnaiitm.me/realms/ztna-tenant-2", "ztna-tenant-2", []string{"ztna-tenant-2"}, true},
		{issuer, "ztna-tenant-2", nil, false},
		{issuer, "ztna", []string{"ztna", "ztna-tenant-2"}, false},
		{issuer, "ztna", []string{"ztna-tenant-2"}, false},
		{"http://auth.example/realms/ztna", "ztna", nil, false},
		{"https://user:password@auth.example/realms/ztna", "ztna", nil, false},
		{"https://auth.example/realms/ztna?tenant=b", "ztna", nil, false},
		{"https://auth.example/realms/ztna#fragment", "ztna", nil, false},
		{"https://auth.example/other/ztna", "ztna", nil, false},
		{"https://auth.example/realms/%7Aetna", "ztna", nil, false},
	} {
		_, err := connectorTenant(tc.issuer, tc.tenant, tc.tenants)
		if (err == nil) != tc.valid {
			t.Fatalf("configuration validation success = %v, want %v", err == nil, tc.valid)
		}
	}
}

func TestTenantOverrideCannotRelabelAcceptedIssuer(t *testing.T) {
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.Write([]byte(`{"score":100}`)) }))
	defer upstream.Close()
	s := setupSidecar(t, upstream.Listener.Addr().String())
	s.tenant = "ztna-tenant-2"
	res, err := s.Check(context.Background(), makeCheckRequest("Bearer "+makeJWT("u", "s"), "/juice/"))
	if err != nil || res.GetDeniedResponse() == nil || calls != 0 {
		t.Fatal("tenant override relabelled an accepted issuer")
	}
}
