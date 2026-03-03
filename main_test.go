package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscoverOIDCFromGrafanaRedirectClientID(t *testing.T) {
	t.Parallel()

	var idpURL string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(providerMetadata{
				Issuer:                idpURL,
				AuthorizationEndpoint: idpURL + "/oauth2/authorize",
				TokenEndpoint:         idpURL + "/oauth/token",
			})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer idp.Close()
	idpURL = idp.URL

	grafana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.Redirect(w, r, idpURL+"/oauth2/authorize?client_id=grafana-client&scope=openid+profile+email", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer grafana.Close()

	res, err := discoverOIDCFromGrafana(context.Background(), grafana.Client(), grafana.URL, oidcDiscoveryOptions{
		Timeout:      5 * time.Second,
		MaxRedirects: 10,
		AllowHTTP:    true,
	}, func(string, ...any) {})
	if err != nil {
		t.Fatalf("discoverOIDCFromGrafana returned error: %v", err)
	}
	if res.ClientID != "grafana-client" {
		t.Fatalf("client_id mismatch: got %q", res.ClientID)
	}
	if res.IssuerURL != idpURL {
		t.Fatalf("issuer mismatch: got %q want %q", res.IssuerURL, idpURL)
	}
	if strings.Join(res.Scopes, " ") != "openid profile email" {
		t.Fatalf("scope mismatch: got %q", strings.Join(res.Scopes, " "))
	}
}

func TestResolveLoginProfileMixedExplicitAndDiscovered(t *testing.T) {
	t.Parallel()

	var idpURL string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(providerMetadata{Issuer: idpURL})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer idp.Close()
	idpURL = idp.URL

	grafana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.Redirect(w, r, idpURL+"/oauth2/authorize?client_id=from-discovery", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer grafana.Close()

	explicitIssuer := idpURL
	p, err := resolveLoginProfile(context.Background(), profileConfig{}, loginResolveInput{
		GrafanaURL:        grafana.URL,
		IssuerURL:         explicitIssuer,
		IssuerProvided:    true,
		Discover:          true,
		DiscoverTimeout:   5 * time.Second,
		DiscoverAllowHTTP: true,
	}, grafana.Client(), func(string, ...any) {})
	if err != nil {
		t.Fatalf("resolveLoginProfile returned error: %v", err)
	}
	if p.IssuerURL != explicitIssuer {
		t.Fatalf("expected explicit issuer, got %q", p.IssuerURL)
	}
	if p.IssuerSource != "flag" {
		t.Fatalf("issuer source mismatch: %q", p.IssuerSource)
	}
	if p.ClientID != "from-discovery" {
		t.Fatalf("expected discovered client ID, got %q", p.ClientID)
	}
	if p.ClientSource != "discovered" {
		t.Fatalf("client source mismatch: %q", p.ClientSource)
	}
}

func TestDiscoverOIDCMaxDepth(t *testing.T) {
	t.Parallel()

	var baseURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.Redirect(w, r, baseURL+"/a", http.StatusFound)
		case "/a":
			http.Redirect(w, r, baseURL+"/b", http.StatusFound)
		case "/b":
			http.Redirect(w, r, baseURL+"/c", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	baseURL = srv.URL

	_, err := discoverOIDCFromGrafana(context.Background(), srv.Client(), srv.URL, oidcDiscoveryOptions{
		Timeout:      5 * time.Second,
		MaxRedirects: 2,
		AllowHTTP:    true,
	}, func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "max redirect depth") {
		t.Fatalf("expected max depth error, got %v", err)
	}
}

func TestDiscoverOIDCLoop(t *testing.T) {
	t.Parallel()

	var baseURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.Redirect(w, r, baseURL+"/a", http.StatusFound)
		case "/a":
			http.Redirect(w, r, baseURL+"/b", http.StatusFound)
		case "/b":
			http.Redirect(w, r, baseURL+"/a", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	baseURL = srv.URL

	_, err := discoverOIDCFromGrafana(context.Background(), srv.Client(), srv.URL, oidcDiscoveryOptions{
		Timeout:      5 * time.Second,
		MaxRedirects: 10,
		AllowHTTP:    true,
	}, func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "redirect loop") {
		t.Fatalf("expected loop error, got %v", err)
	}
}

func TestDiscoverOIDCRejectsNonHTTPS(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := discoverOIDCFromGrafana(context.Background(), srv.Client(), srv.URL, oidcDiscoveryOptions{
		Timeout:      5 * time.Second,
		MaxRedirects: 5,
		AllowHTTP:    false,
	}, func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("expected non-https error, got %v", err)
	}
}

func TestDiscoverOIDCMalformedURL(t *testing.T) {
	t.Parallel()

	_, err := discoverOIDCFromGrafana(context.Background(), http.DefaultClient, "://bad", oidcDiscoveryOptions{
		Timeout:      5 * time.Second,
		MaxRedirects: 5,
		AllowHTTP:    true,
	}, func(string, ...any) {})
	if err == nil {
		t.Fatal("expected malformed URL error")
	}
}

func TestResolveLoginProfileLoginHintMerge(t *testing.T) {
	t.Parallel()

	p, err := resolveLoginProfile(context.Background(), profileConfig{
		GrafanaURL: "https://grafana.example.com",
		IssuerURL:  "https://idp.example.com",
		ClientID:   "client",
		LoginHint:  "old@example.com",
	}, loginResolveInput{
		LoginHint: "new@example.com",
		Discover:  false,
	}, http.DefaultClient, func(string, ...any) {})
	if err != nil {
		t.Fatalf("resolveLoginProfile returned error: %v", err)
	}
	if p.LoginHint != "new@example.com" {
		t.Fatalf("expected login hint override, got %q", p.LoginHint)
	}
}

func TestDeriveIssuerCandidateFromAuthURLOkta(t *testing.T) {
	t.Parallel()

	u, err := url.Parse("https://acme.okta.com/oauth2/default/v1/authorize?client_id=abc")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	got := deriveIssuerCandidateFromAuthURL(u)
	want := "https://acme.okta.com/oauth2/default"
	if got != want {
		t.Fatalf("issuer derivation mismatch: got %q want %q", got, want)
	}
}

func TestDiscoverOIDCFromGrafanaSAMLFallbackToGenericOAuth(t *testing.T) {
	t.Parallel()

	var baseURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.Redirect(w, r, baseURL+"/sso/saml?SAMLRequest=abc", http.StatusFound)
		case "/sso/saml":
			w.WriteHeader(http.StatusOK)
		case "/login/generic_oauth":
			http.Redirect(w, r, baseURL+"/oauth2/default/v1/authorize?client_id=surfana&scope=openid+profile", http.StatusFound)
		case "/oauth2/default/v1/authorize":
			w.WriteHeader(http.StatusOK)
		case "/oauth2/default/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(providerMetadata{
				Issuer:                baseURL + "/oauth2/default",
				AuthorizationEndpoint: baseURL + "/oauth2/default/v1/authorize",
				TokenEndpoint:         baseURL + "/oauth2/default/v1/token",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	baseURL = srv.URL

	res, err := discoverOIDCFromGrafana(context.Background(), srv.Client(), baseURL, oidcDiscoveryOptions{
		Timeout:      5 * time.Second,
		MaxRedirects: 10,
		AllowHTTP:    true,
	}, func(string, ...any) {})
	if err != nil {
		t.Fatalf("discoverOIDCFromGrafana returned error: %v", err)
	}
	if res.ClientID != "surfana" {
		t.Fatalf("expected client_id surfana, got %q", res.ClientID)
	}
	if res.IssuerURL != baseURL+"/oauth2/default" {
		t.Fatalf("expected issuer from generic_oauth path, got %q", res.IssuerURL)
	}
}

func TestLoginIntegrationAutoDiscovery(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	mux := http.NewServeMux()
	var baseURL string

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, baseURL+"/oauth2/authorize?client_id=cli-client&scope=openid+profile+email", http.StatusFound)
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(providerMetadata{
			Issuer:                      baseURL,
			AuthorizationEndpoint:       baseURL + "/oauth2/authorize",
			TokenEndpoint:               baseURL + "/oauth/token",
			DeviceAuthorizationEndpoint: baseURL + "/oauth/device",
		})
	})
	mux.HandleFunc("/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/oauth/device", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(deviceAuthResponse{
			DeviceCode:      "dev-code",
			UserCode:        "ABCD",
			VerificationURI: baseURL + "/verify",
			ExpiresIn:       60,
			Interval:        1,
		})
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "test-token",
			"token_type":    "Bearer",
			"refresh_token": "test-refresh",
		})
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	baseURL = srv.URL

	oldClient := http.DefaultClient
	http.DefaultClient = srv.Client()
	defer func() { http.DefaultClient = oldClient }()

	err := executeWithArgs([]string{
		"login",
		"--profile", "itest",
		"--grafana-url", srv.URL,
		"--method", "device",
		"--open-browser=false",
	})
	if err != nil {
		t.Fatalf("cmdLogin returned error: %v", err)
	}

	cfgPath := filepath.Join(tmp, appName, "config.json")
	cfgBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg appConfig
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	p := cfg.Profiles["itest"]
	if p.IssuerURL == "" || p.ClientID == "" {
		t.Fatalf("expected discovered values in profile, got issuer=%q client_id=%q", p.IssuerURL, p.ClientID)
	}
	if p.ClientSource != "discovered" || p.IssuerSource != "discovered" {
		t.Fatalf("expected discovered sources, got issuer=%q client=%q", p.IssuerSource, p.ClientSource)
	}
}
