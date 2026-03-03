package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	appName          = "surfana"
	defaultProfile   = "default"
	defaultUserAgent = "surfana-cli/0.1"
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
	Scopes       []string `json:"scopes"`
	Audience     string   `json:"audience,omitempty"`
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

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		printUsage()
		return nil
	}

	switch os.Args[1] {
	case "login":
		return cmdLogin(os.Args[2:])
	case "api":
		return cmdAPI(os.Args[2:])
	case "whoami":
		return cmdWhoAmI(os.Args[2:])
	case "logout":
		return cmdLogout(os.Args[2:])
	case "profiles":
		return cmdProfiles(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func printUsage() {
	fmt.Printf(`%s: Grafana CLI with OIDC auth\n\n`, appName)
	fmt.Println("Usage:")
	fmt.Println("  surfana login [flags]")
	fmt.Println("  surfana api [flags] <path>")
	fmt.Println("  surfana whoami [flags]")
	fmt.Println("  surfana logout [flags]")
	fmt.Println("  surfana profiles")
	fmt.Println()
	fmt.Println("Run 'surfana <command> -h' for details.")
}

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	profile := fs.String("profile", defaultProfile, "profile name")
	grafanaURL := fs.String("grafana-url", "", "Grafana base URL")
	issuerURL := fs.String("issuer-url", "", "OIDC issuer URL")
	clientID := fs.String("client-id", "", "OIDC client ID")
	clientSecret := fs.String("client-secret", "", "OIDC client secret")
	audience := fs.String("audience", "", "OIDC audience")
	scope := fs.String("scope", "openid profile email", "space separated scopes")
	method := fs.String("method", "device", "auth method: device or authcode")
	openBrowser := fs.Bool("open-browser", true, "open browser for sign in")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]profileConfig{}
	}

	existing := cfg.Profiles[*profile]
	p := profileConfig{
		GrafanaURL:   chooseNonEmpty(*grafanaURL, existing.GrafanaURL),
		IssuerURL:    chooseNonEmpty(*issuerURL, existing.IssuerURL),
		ClientID:     chooseNonEmpty(*clientID, existing.ClientID),
		ClientSecret: chooseNonEmpty(*clientSecret, existing.ClientSecret),
		Scopes:       splitScopes(chooseNonEmpty(*scope, strings.Join(existing.Scopes, " "))),
		Audience:     chooseNonEmpty(*audience, existing.Audience),
	}

	if p.GrafanaURL == "" || p.IssuerURL == "" || p.ClientID == "" {
		return errors.New("login requires grafana-url, issuer-url, and client-id (or existing profile values)")
	}
	if len(p.Scopes) == 0 {
		p.Scopes = []string{"openid", "profile", "email"}
	}

	meta, err := discoverProviderMetadata(p.IssuerURL)
	if err != nil {
		return err
	}

	ctx := context.Background()
	var tok *storedToken
	switch *method {
	case "device":
		tok, err = loginDeviceFlow(ctx, p, meta, *openBrowser)
	case "authcode":
		tok, err = loginAuthCodeFlow(ctx, p, meta, *openBrowser)
	default:
		return fmt.Errorf("unsupported login method %q", *method)
	}
	if err != nil {
		return err
	}

	cfg.CurrentProfile = *profile
	cfg.Profiles[*profile] = p
	if err := saveConfig(cfg); err != nil {
		return err
	}
	if err := saveToken(*profile, tok); err != nil {
		return err
	}

	fmt.Printf("login succeeded for profile %q\n", *profile)
	return nil
}

func cmdAPI(args []string) error {
	fs := flag.NewFlagSet("api", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profile := fs.String("profile", "", "profile name")
	method := fs.String("X", "GET", "HTTP method")
	body := fs.String("d", "", "request body")
	contentType := fs.String("content-type", "application/json", "request content-type")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("api requires one path argument, e.g. /api/user")
	}
	path := fs.Arg(0)

	cfg, pName, p, err := resolveProfile(*profile)
	if err != nil {
		return err
	}
	_ = cfg

	meta, err := discoverProviderMetadata(p.IssuerURL)
	if err != nil {
		return err
	}

	tok, err := loadToken(pName)
	if err != nil {
		return err
	}

	tok, changed, err := ensureValidToken(context.Background(), p, meta, tok)
	if err != nil {
		return err
	}
	if changed {
		if err := saveToken(pName, tok); err != nil {
			return err
		}
	}

	fullURL, err := joinURLPath(p.GrafanaURL, path)
	if err != nil {
		return err
	}

	var reqBody io.Reader
	if *body != "" {
		reqBody = strings.NewReader(*body)
	}
	req, err := http.NewRequest(strings.ToUpper(*method), fullURL, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("User-Agent", defaultUserAgent)
	if *body != "" {
		req.Header.Set("Content-Type", *contentType)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fmt.Printf("HTTP %d\n", resp.StatusCode)
	if len(respBytes) == 0 {
		return nil
	}

	var pretty bytes.Buffer
	if json.Indent(&pretty, respBytes, "", "  ") == nil {
		fmt.Println(pretty.String())
	} else {
		fmt.Println(string(respBytes))
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("request failed with HTTP %d", resp.StatusCode)
	}

	return nil
}

func cmdWhoAmI(args []string) error {
	fs := flag.NewFlagSet("whoami", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profile := fs.String("profile", "", "profile name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, pName, p, err := resolveProfile(*profile)
	if err != nil {
		return err
	}
	_ = p

	tok, err := loadToken(pName)
	if err != nil {
		return err
	}

	fmt.Printf("profile: %s\n", pName)
	fmt.Printf("grafana: %s\n", cfg.Profiles[pName].GrafanaURL)
	fmt.Printf("token_type: %s\n", tok.TokenType)
	fmt.Printf("expires_at: %s\n", tok.Expiry.Format(time.RFC3339))
	fmt.Printf("has_refresh_token: %t\n", tok.RefreshToken != "")
	return nil
}

func cmdLogout(args []string) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profile := fs.String("profile", "", "profile name")
	if err := fs.Parse(args); err != nil {
		return err
	}

	_, pName, _, err := resolveProfile(*profile)
	if err != nil {
		return err
	}
	if err := os.Remove(tokenPath(pName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Printf("logged out profile %q\n", pName)
	return nil
}

func cmdProfiles(args []string) error {
	if len(args) > 0 {
		return errors.New("profiles does not take arguments")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if len(cfg.Profiles) == 0 {
		fmt.Println("no profiles configured")
		return nil
	}
	names := make([]string, 0, len(cfg.Profiles))
	for name := range cfg.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		marker := " "
		if name == cfg.CurrentProfile {
			marker = "*"
		}
		fmt.Printf("%s %s\n", marker, name)
	}
	return nil
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
	u, err := url.Parse(issuer)
	if err != nil {
		return providerMetadata{}, err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return providerMetadata{}, err
	}
	req.Header.Set("User-Agent", defaultUserAgent)

	resp, err := http.DefaultClient.Do(req)
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
