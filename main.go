package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	appName          = "surfana"
	defaultProfile   = "default"
	defaultUserAgent = "surfana-cli/0.1"
	defaultScope     = "openid profile email"
)

type appConfig struct {
	CurrentProfile string                   `json:"current_profile"`
	Profiles       map[string]profileConfig `json:"profiles"`
}

type profileConfig struct {
	GrafanaURL   string   `json:"grafana_url"`
	IssuerURL    string   `json:"issuer_url"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	LoginHint    string   `json:"login_hint,omitempty"`
	Scopes       []string `json:"scopes"`
	Audience     string   `json:"audience,omitempty"`
	IssuerSource string   `json:"issuer_source,omitempty"`
	ClientSource string   `json:"client_source,omitempty"`
	ScopesSource string   `json:"scopes_source,omitempty"`
	DiscoverUsed bool     `json:"discover_used,omitempty"`
}

type storedToken struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
}

type providerMetadata struct {
	Issuer                      string `json:"issuer"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	RevocationEndpoint          string `json:"revocation_endpoint"`
}

type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type oidcDiscoveryOptions struct {
	Timeout      time.Duration
	MaxRedirects int
	AllowHTTP    bool
	Debug        bool
}

type oidcDiscoveryResult struct {
	IssuerURL string
	ClientID  string
	Scopes    []string
}

type discoveryHints struct {
	ClientID   string
	Scopes     []string
	Candidates []string
	SawSAML    bool
}

type loginResolveInput struct {
	GrafanaURL        string
	IssuerURL         string
	ClientID          string
	ClientSecret      string
	LoginHint         string
	Audience          string
	Scope             string
	ScopeProvided     bool
	IssuerProvided    bool
	ClientIDProvided  bool
	Discover          bool
	DiscoverTimeout   time.Duration
	DiscoverAllowHTTP bool
}

func main() {
	if err := execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func resolveLoginProfile(ctx context.Context, existing profileConfig, in loginResolveInput, client *http.Client, debugf func(string, ...any)) (profileConfig, error) {
	p := profileConfig{
		GrafanaURL:   chooseNonEmpty(in.GrafanaURL, existing.GrafanaURL),
		IssuerURL:    chooseNonEmpty(in.IssuerURL, existing.IssuerURL),
		ClientID:     chooseNonEmpty(in.ClientID, existing.ClientID),
		ClientSecret: chooseNonEmpty(in.ClientSecret, existing.ClientSecret),
		LoginHint:    chooseNonEmpty(in.LoginHint, existing.LoginHint),
		Audience:     chooseNonEmpty(in.Audience, existing.Audience),
	}

	switch {
	case strings.TrimSpace(in.IssuerURL) != "":
		p.IssuerSource = "flag"
	case strings.TrimSpace(existing.IssuerURL) != "":
		p.IssuerSource = "profile"
	}
	switch {
	case strings.TrimSpace(in.ClientID) != "":
		p.ClientSource = "flag"
	case strings.TrimSpace(existing.ClientID) != "":
		p.ClientSource = "profile"
	}

	if in.ScopeProvided {
		p.Scopes = splitScopes(in.Scope)
		p.ScopesSource = "flag"
	} else if len(existing.Scopes) > 0 {
		p.Scopes = append([]string(nil), existing.Scopes...)
		p.ScopesSource = "profile"
	}

	needsDiscovery := in.Discover && p.GrafanaURL != "" && (p.IssuerURL == "" || p.ClientID == "" || len(p.Scopes) == 0)
	if needsDiscovery {
		debugf("starting oidc discovery from grafana-url=%s", p.GrafanaURL)
		res, err := discoverOIDCFromGrafana(ctx, client, p.GrafanaURL, oidcDiscoveryOptions{
			Timeout:      in.DiscoverTimeout,
			MaxRedirects: 10,
			AllowHTTP:    in.DiscoverAllowHTTP,
			Debug:        false,
		}, debugf)
		if err != nil {
			return profileConfig{}, err
		}
		p.DiscoverUsed = true
		if p.ClientID == "" && res.ClientID != "" {
			p.ClientID = res.ClientID
			p.ClientSource = "discovered"
		}
		if p.IssuerURL == "" && res.IssuerURL != "" {
			p.IssuerURL = res.IssuerURL
			p.IssuerSource = "discovered"
		}
		if len(p.Scopes) == 0 && len(res.Scopes) > 0 {
			p.Scopes = append([]string(nil), res.Scopes...)
			p.ScopesSource = "discovered"
		}
	}

	if len(p.Scopes) == 0 {
		p.Scopes = splitScopes(defaultScope)
		p.ScopesSource = "default"
	}

	if p.GrafanaURL == "" || p.IssuerURL == "" || p.ClientID == "" {
		if !in.Discover {
			return profileConfig{}, errors.New("login requires grafana-url, issuer-url, and client-id (or existing profile values); enable --discover or provide missing flags")
		}
		found := []string{}
		missing := []string{}
		if p.GrafanaURL != "" {
			found = append(found, fmt.Sprintf("grafana_url=%s", p.GrafanaURL))
		} else {
			missing = append(missing, "grafana_url")
		}
		if p.ClientID != "" {
			found = append(found, fmt.Sprintf("client_id=%s", p.ClientID))
		} else {
			missing = append(missing, "client_id")
		}
		if p.IssuerURL != "" {
			found = append(found, fmt.Sprintf("issuer_url=%s", p.IssuerURL))
		} else {
			missing = append(missing, "issuer_url")
		}
		return profileConfig{}, fmt.Errorf(
			"failed to auto-discover OIDC config from %s: found %s, missing %s; rerun with --issuer-url and/or --client-id (use --debug for diagnostics)",
			chooseNonEmpty(p.GrafanaURL, "<unset>"),
			strings.Join(found, ", "),
			strings.Join(missing, ", "),
		)
	}

	debugf("selected issuer_url=%s (source=%s)", p.IssuerURL, chooseNonEmpty(p.IssuerSource, "unknown"))
	debugf("selected client_id=%s (source=%s)", p.ClientID, chooseNonEmpty(p.ClientSource, "unknown"))
	debugf("selected scopes=%s (source=%s)", strings.Join(p.Scopes, " "), chooseNonEmpty(p.ScopesSource, "unknown"))
	return p, nil
}

func discoverOIDCFromGrafana(ctx context.Context, client *http.Client, grafanaURL string, opts oidcDiscoveryOptions, debugf func(string, ...any)) (oidcDiscoveryResult, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = 10
	}

	base, err := url.Parse(grafanaURL)
	if err != nil {
		return oidcDiscoveryResult{}, fmt.Errorf("invalid grafana-url %q: %w", grafanaURL, err)
	}
	if !opts.AllowHTTP && base.Scheme != "https" {
		return oidcDiscoveryResult{}, fmt.Errorf("grafana-url must use https for discovery: %s", grafanaURL)
	}

	loginURL, err := joinURLPath(grafanaURL, "/login")
	if err != nil {
		return oidcDiscoveryResult{}, err
	}

	discoveryCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	httpClient := *client
	httpClient.Timeout = opts.Timeout
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	hints, err := harvestDiscoveryHints(discoveryCtx, &httpClient, loginURL, opts, debugf)
	if err != nil {
		return oidcDiscoveryResult{}, err
	}

	entrypoints := []string{
		mustJoinURL(grafanaURL, "/login/generic_oauth"),
		mustJoinURL(grafanaURL, "/login/okta"),
		mustJoinURL(grafanaURL, "/login/oauth"),
		mustJoinURL(grafanaURL, "/login/azuread"),
		mustJoinURL(grafanaURL, "/login/auth0"),
	}

	for _, entry := range entrypoints {
		if entry == "" {
			continue
		}
		h, err := harvestDiscoveryHints(discoveryCtx, &httpClient, entry, opts, debugf)
		if err != nil {
			debugf("entrypoint %s failed: %v", redactURL(entry), err)
			continue
		}
		if hints.ClientID == "" && h.ClientID != "" {
			hints.ClientID = h.ClientID
		}
		if len(hints.Scopes) == 0 && len(h.Scopes) > 0 {
			hints.Scopes = h.Scopes
		}
		hints.Candidates = append(hints.Candidates, h.Candidates...)
		hints.SawSAML = hints.SawSAML || h.SawSAML
		if hints.ClientID != "" && len(hints.Candidates) > 0 {
			break
		}
	}

	issuer, meta, err := validateIssuerCandidates(discoveryCtx, &httpClient, hints.Candidates)
	if err != nil {
		found := []string{}
		if hints.ClientID != "" {
			found = append(found, fmt.Sprintf("client_id=%s", hints.ClientID))
		}
		if len(hints.Scopes) > 0 {
			found = append(found, fmt.Sprintf("scope=%s", strings.Join(hints.Scopes, " ")))
		}
		if hints.SawSAML {
			found = append(found, "saml_redirect=true")
		}
		return oidcDiscoveryResult{}, fmt.Errorf(
			"failed to auto-discover OIDC config from %s: found %s, missing issuer_url; rerun with --issuer-url (use --debug to inspect redirect chain): %w",
			grafanaURL,
			chooseNonEmpty(strings.Join(found, ", "), "none"),
			err,
		)
	}
	debugf("issuer validation succeeded via %s", issuer)
	if hints.ClientID == "" {
		extra := ""
		if hints.SawSAML {
			extra = " (saw SAML redirect; provide Grafana OAuth client id explicitly if your IdP hides it)"
		}
		return oidcDiscoveryResult{}, fmt.Errorf(
			"failed to auto-discover OIDC config from %s: found issuer_url=%s, missing client_id; rerun with --client-id%s",
			grafanaURL,
			issuer,
			extra,
		)
	}
	if len(hints.Scopes) == 0 && meta.AuthorizationEndpoint != "" {
		if _, scopes, _ := extractHintsFromURL(mustParseURL(meta.AuthorizationEndpoint)); len(scopes) > 0 {
			hints.Scopes = scopes
		}
	}

	return oidcDiscoveryResult{
		IssuerURL: issuer,
		ClientID:  hints.ClientID,
		Scopes:    hints.Scopes,
	}, nil
}

func harvestDiscoveryHints(ctx context.Context, client *http.Client, startURL string, opts oidcDiscoveryOptions, debugf func(string, ...any)) (discoveryHints, error) {
	current, err := url.Parse(startURL)
	if err != nil {
		return discoveryHints{}, err
	}

	var (
		hints      discoveryHints
		visited    = map[string]struct{}{}
		reachedMax = true
	)

	for step := 0; step < opts.MaxRedirects; step++ {
		if !opts.AllowHTTP && current.Scheme != "https" {
			return discoveryHints{}, fmt.Errorf("discovery redirect used non-https URL: %s", current.String())
		}
		currentKey := current.String()
		if _, ok := visited[currentKey]; ok {
			return discoveryHints{}, fmt.Errorf("discovery redirect loop detected at %s", redactURL(current.String()))
		}
		visited[currentKey] = struct{}{}
		debugf("discovery step %d: GET %s", step+1, redactURL(current.String()))

		if looksLikeSAMLURL(current) {
			hints.SawSAML = true
		}

		clientID, scopes, issuerHint := extractHintsFromURL(current)
		if clientID != "" && hints.ClientID == "" {
			hints.ClientID = clientID
			debugf("found client_id=%s", clientID)
		}
		if len(scopes) > 0 && len(hints.Scopes) == 0 {
			hints.Scopes = scopes
			debugf("found scope=%s", strings.Join(scopes, " "))
		}
		hints.Candidates = appendIssuerCandidate(hints.Candidates, issuerHint)
		hints.Candidates = appendIssuerCandidate(hints.Candidates, deriveIssuerCandidateFromAuthURL(current))
		hints.Candidates = appendIssuerCandidate(hints.Candidates, current.Scheme+"://"+current.Host)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return discoveryHints{}, err
		}
		req.Header.Set("User-Agent", defaultUserAgent)

		resp, err := client.Do(req)
		if err != nil {
			return discoveryHints{}, fmt.Errorf("discovery request failed at %s: %w", redactURL(current.String()), err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			return discoveryHints{}, readErr
		}

		if loc := resp.Header.Get("Location"); isRedirectStatus(resp.StatusCode) && loc != "" {
			next, err := resolveRedirectURL(current, loc)
			if err != nil {
				return discoveryHints{}, err
			}
			debugf("redirect -> %s", redactURL(next.String()))
			if looksLikeSAMLURL(next) {
				hints.SawSAML = true
			}
			current = next
			continue
		}

		if next, ok := parseMetaRefreshURL(current, body); ok {
			debugf("meta refresh -> %s", redactURL(next.String()))
			if looksLikeSAMLURL(next) {
				hints.SawSAML = true
			}
			current = next
			continue
		}

		reachedMax = false
		break
	}

	if reachedMax {
		return discoveryHints{}, fmt.Errorf("discovery exceeded max redirect depth (%d)", opts.MaxRedirects)
	}
	return hints, nil
}

func validateIssuerCandidates(ctx context.Context, client *http.Client, candidates []string) (string, providerMetadata, error) {
	seen := map[string]struct{}{}
	for _, raw := range candidates {
		candidate := strings.TrimSpace(strings.TrimRight(raw, "/"))
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		meta, err := discoverProviderMetadataWithClient(ctx, client, candidate)
		if err == nil {
			return candidate, meta, nil
		}
	}
	return "", providerMetadata{}, errors.New("no candidate issuer returned a valid openid-configuration")
}

func extractHintsFromURL(u *url.URL) (clientID string, scopes []string, issuer string) {
	if u == nil {
		return "", nil, ""
	}
	q := u.Query()
	clientID = q.Get("client_id")
	if rawScope := q.Get("scope"); rawScope != "" {
		scopes = splitScopes(rawScope)
	}
	issuer = q.Get("iss")
	return clientID, scopes, issuer
}

func deriveIssuerCandidateFromAuthURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	if u.Path == "" {
		return u.Scheme + "://" + u.Host
	}
	path := strings.TrimRight(u.Path, "/")
	suffixes := []string{
		"/v1/authorize",
		"/oauth2/authorize",
		"/oauth2/v1/authorize",
		"/oauth/authorize",
		"/protocol/openid-connect/auth",
		"/authorize",
		"/auth",
	}
	for _, suffix := range suffixes {
		if strings.HasSuffix(path, suffix) {
			basePath := strings.TrimSuffix(path, suffix)
			if basePath == "" {
				basePath = "/"
			}
			return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: basePath}).String()
		}
	}
	return ""
}

func appendIssuerCandidate(candidates []string, candidate string) []string {
	if strings.TrimSpace(candidate) == "" {
		return candidates
	}
	return append(candidates, candidate)
}

func looksLikeSAMLURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	q := u.Query()
	if q.Get("SAMLRequest") != "" || q.Get("SAMLResponse") != "" || q.Get("samlrequest") != "" || q.Get("samlresponse") != "" {
		return true
	}
	path := strings.ToLower(u.Path)
	return strings.Contains(path, "saml")
}

func resolveRedirectURL(current *url.URL, location string) (*url.URL, error) {
	loc, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return nil, fmt.Errorf("invalid redirect location %q: %w", location, err)
	}
	return current.ResolveReference(loc), nil
}

func isRedirectStatus(code int) bool {
	return code >= 300 && code <= 399
}

var metaRefreshRegex = regexp.MustCompile(`(?is)<meta[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"'>]*url=([^"'>]+)`)

func parseMetaRefreshURL(current *url.URL, body []byte) (*url.URL, bool) {
	matches := metaRefreshRegex.FindSubmatch(body)
	if len(matches) < 2 {
		return nil, false
	}
	next, err := resolveRedirectURL(current, string(matches[1]))
	if err != nil {
		return nil, false
	}
	return next, true
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for key := range q {
		if isSensitiveParam(key) {
			q.Set(key, "***")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func isSensitiveParam(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	switch k {
	case "code", "id_token", "access_token", "refresh_token", "client_secret", "assertion", "password", "samlrequest", "samlresponse", "token":
		return true
	default:
		return false
	}
}

func loginDeviceFlow(ctx context.Context, p profileConfig, meta providerMetadata, openBrowser bool) (*storedToken, error) {
	if meta.DeviceAuthorizationEndpoint == "" {
		return nil, errors.New("provider does not publish device_authorization_endpoint")
	}
	if meta.TokenEndpoint == "" {
		return nil, errors.New("provider does not publish token_endpoint")
	}

	values := url.Values{}
	values.Set("client_id", p.ClientID)
	values.Set("scope", strings.Join(p.Scopes, " "))
	if p.Audience != "" {
		values.Set("audience", p.Audience)
	}
	if p.LoginHint != "" {
		values.Set("login_hint", p.LoginHint)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.DeviceAuthorizationEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", defaultUserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("device authorization failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var da deviceAuthResponse
	if err := json.Unmarshal(body, &da); err != nil {
		return nil, err
	}
	if da.Interval <= 0 {
		da.Interval = 5
	}
	if da.DeviceCode == "" || da.VerificationURI == "" {
		return nil, errors.New("provider returned incomplete device authorization response")
	}

	fmt.Printf("Open %s and enter code %s\n", da.VerificationURI, da.UserCode)
	if openBrowser {
		urlToOpen := da.VerificationURI
		if da.VerificationURIComplete != "" {
			urlToOpen = da.VerificationURIComplete
		}
		_ = openURLInBrowser(urlToOpen)
	}

	deadline := time.Now().Add(time.Duration(da.ExpiresIn) * time.Second)
	if da.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}

	for time.Now().Before(deadline) {
		tok, retry, err := pollDeviceToken(ctx, p, meta, da.DeviceCode)
		if err == nil {
			return tok, nil
		}
		if !retry {
			return nil, err
		}
		time.Sleep(time.Duration(da.Interval) * time.Second)
	}

	return nil, errors.New("device authorization timed out")
}

func pollDeviceToken(ctx context.Context, p profileConfig, meta providerMetadata, deviceCode string) (*storedToken, bool, error) {
	values := url.Values{}
	values.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	values.Set("device_code", deviceCode)
	values.Set("client_id", p.ClientID)
	if p.ClientSecret != "" {
		values.Set("client_secret", p.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", defaultUserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}

	if resp.StatusCode >= 400 {
		var te tokenErrorResponse
		if json.Unmarshal(body, &te) == nil {
			switch te.Error {
			case "authorization_pending", "slow_down":
				return nil, true, nil
			case "expired_token", "access_denied":
				return nil, false, fmt.Errorf("device login failed: %s (%s)", te.Error, te.ErrorDescription)
			}
		}
		return nil, false, fmt.Errorf("token polling failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tok oauth2.Token
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, false, err
	}
	return oauthTokenToStoredToken(&tok), false, nil
}

func loginAuthCodeFlow(ctx context.Context, p profileConfig, meta providerMetadata, openBrowser bool) (*storedToken, error) {
	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" {
		return nil, errors.New("provider does not publish authorization/token endpoints")
	}
	state, err := randomURLSafe(32)
	if err != nil {
		return nil, err
	}
	verifier, err := randomURLSafe(64)
	if err != nil {
		return nil, err
	}
	challenge := pkceS256(verifier)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	redirectURL := "http://" + ln.Addr().String() + "/callback"

	oauthCfg := &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  meta.AuthorizationEndpoint,
			TokenURL: meta.TokenEndpoint,
		},
		RedirectURL: redirectURL,
		Scopes:      p.Scopes,
	}

	authURL := oauthCfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	if p.Audience != "" {
		u, err := url.Parse(authURL)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("audience", p.Audience)
		u.RawQuery = q.Encode()
		authURL = u.String()
	}
	if p.LoginHint != "" {
		u, err := url.Parse(authURL)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("login_hint", p.LoginHint)
		u.RawQuery = q.Encode()
		authURL = u.String()
	}

	type callbackResult struct {
		code string
		err  error
	}
	resultCh := make(chan callbackResult, 1)

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("state"); got != state {
			http.Error(w, "invalid state", http.StatusBadRequest)
			resultCh <- callbackResult{err: errors.New("state mismatch")}
			return
		}
		if e := r.URL.Query().Get("error"); e != "" {
			http.Error(w, "auth error", http.StatusBadRequest)
			resultCh <- callbackResult{err: fmt.Errorf("authorization failed: %s", e)}
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			resultCh <- callbackResult{err: errors.New("missing authorization code")}
			return
		}
		fmt.Fprintln(w, "Authentication complete. You can close this window.")
		resultCh <- callbackResult{code: code}
	})}
	go func() {
		_ = srv.Serve(ln)
	}()
	defer func() {
		_ = srv.Shutdown(context.Background())
	}()

	fmt.Printf("Open %s\n", authURL)
	if openBrowser {
		_ = openURLInBrowser(authURL)
	}

	select {
	case <-time.After(5 * time.Minute):
		return nil, errors.New("authorization timeout waiting for callback")
	case res := <-resultCh:
		if res.err != nil {
			return nil, res.err
		}
		tok, err := oauthCfg.Exchange(ctx, res.code, oauth2.SetAuthURLParam("code_verifier", verifier))
		if err != nil {
			return nil, err
		}
		return oauthTokenToStoredToken(tok), nil
	}
}

func discoverProviderMetadata(issuer string) (providerMetadata, error) {
	return discoverProviderMetadataWithClient(context.Background(), http.DefaultClient, issuer)
}

func discoverProviderMetadataWithClient(ctx context.Context, client *http.Client, issuer string) (providerMetadata, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return providerMetadata{}, err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return providerMetadata{}, err
	}
	req.Header.Set("User-Agent", defaultUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return providerMetadata{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return providerMetadata{}, err
	}
	if resp.StatusCode >= 400 {
		return providerMetadata{}, fmt.Errorf("oidc discovery failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var meta providerMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return providerMetadata{}, err
	}
	return meta, nil
}

func ensureValidToken(ctx context.Context, p profileConfig, meta providerMetadata, tok *storedToken) (*storedToken, bool, error) {
	if tok.AccessToken == "" {
		return nil, false, errors.New("stored token has no access token")
	}
	if tok.Expiry.IsZero() || time.Now().Add(30*time.Second).Before(tok.Expiry) {
		return tok, false, nil
	}
	if tok.RefreshToken == "" {
		return nil, false, errors.New("access token expired and no refresh token available; run login again")
	}
	if meta.TokenEndpoint == "" {
		return nil, false, errors.New("provider metadata missing token endpoint")
	}

	values := url.Values{}
	values.Set("grant_type", "refresh_token")
	values.Set("refresh_token", tok.RefreshToken)
	values.Set("client_id", p.ClientID)
	if p.ClientSecret != "" {
		values.Set("client_secret", p.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", defaultUserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}
	if resp.StatusCode >= 400 {
		return nil, false, fmt.Errorf("token refresh failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var refreshed oauth2.Token
	if err := json.Unmarshal(body, &refreshed); err != nil {
		return nil, false, err
	}
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = tok.RefreshToken
	}
	stored := oauthTokenToStoredToken(&refreshed)
	return stored, true, nil
}

func resolveProfile(requested string) (appConfig, string, profileConfig, error) {
	cfg, err := loadConfig()
	if err != nil {
		return appConfig{}, "", profileConfig{}, err
	}
	name := requested
	if name == "" {
		name = cfg.CurrentProfile
	}
	if name == "" {
		name = defaultProfile
	}
	p, ok := cfg.Profiles[name]
	if !ok {
		return appConfig{}, "", profileConfig{}, fmt.Errorf("profile %q not found; run login first", name)
	}
	return cfg, name, p, nil
}

func configDir() string {
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return filepath.Join(v, appName)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", appName)
}

func configPath() string {
	return filepath.Join(configDir(), "config.json")
}

func tokenPath(profile string) string {
	return filepath.Join(configDir(), fmt.Sprintf("token-%s.json", profile))
}

func loadConfig() (appConfig, error) {
	b, err := os.ReadFile(configPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return appConfig{Profiles: map[string]profileConfig{}}, nil
		}
		return appConfig{}, err
	}
	var cfg appConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return appConfig{}, err
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]profileConfig{}
	}
	return cfg, nil
}

func saveConfig(cfg appConfig) error {
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(), b, 0o600)
}

func loadToken(profile string) (*storedToken, error) {
	b, err := os.ReadFile(tokenPath(profile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no stored token for profile %q; run login", profile)
		}
		return nil, err
	}
	var tok storedToken
	if err := json.Unmarshal(b, &tok); err != nil {
		return nil, err
	}
	return &tok, nil
}

func saveToken(profile string, tok *storedToken) error {
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(tokenPath(profile), b, 0o600)
}

func oauthTokenToStoredToken(tok *oauth2.Token) *storedToken {
	return &storedToken{
		AccessToken:  tok.AccessToken,
		TokenType:    tok.TokenType,
		RefreshToken: tok.RefreshToken,
		Expiry:       tok.Expiry,
	}
}

func chooseNonEmpty(first, fallback string) string {
	if strings.TrimSpace(first) != "" {
		return strings.TrimSpace(first)
	}
	return strings.TrimSpace(fallback)
}

func splitScopes(v string) []string {
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func joinURLPath(baseURL, p string) (string, error) {
	b, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	rel, err := url.Parse(p)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(rel).String(), nil
}

func mustJoinURL(baseURL, p string) string {
	out, err := joinURLPath(baseURL, p)
	if err != nil {
		return ""
	}
	return out
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		return &url.URL{}
	}
	return u
}

func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func openURLInBrowser(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	return cmd.Start()
}
