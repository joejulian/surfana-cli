package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func execute() error {
	v := newViper()
	root := newRootCmd(v)
	return root.Execute()
}

func executeWithArgs(args []string) error {
	v := newViper()
	root := newRootCmd(v)
	root.SetArgs(args)
	return root.Execute()
}

func newViper() *viper.Viper {
	v := viper.New()
	v.SetEnvPrefix("SURFANA")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()
	return v
}

func newRootCmd(v *viper.Viper) *cobra.Command {
	root := &cobra.Command{
		Use:   "surfana",
		Short: "Grafana CLI with OIDC authentication",
		Long:  "Authenticate to Grafana (OIDC/SAML-fronted) and query Grafana APIs from the command line.",
	}

	root.AddCommand(newLoginCmd(v))
	root.AddCommand(newAPICmd(v))
	root.AddCommand(newWhoAmICmd(v))
	root.AddCommand(newLogoutCmd(v))
	root.AddCommand(newProfilesCmd())

	return root
}

func newLoginCmd(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate and store token",
		Long:  "Authenticate to Grafana using OIDC device flow or auth code flow, then persist profile and token locally.",
		Example: "  surfana login --grafana-url https://grafana.example.com\n" +
			"  surfana login --grafana-url https://grafana.example.com --issuer-url https://idp.example.com --client-id cli",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := v.BindPFlags(cmd.Flags()); err != nil {
				return err
			}

			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if cfg.Profiles == nil {
				cfg.Profiles = map[string]profileConfig{}
			}

			profile := v.GetString("profile")
			existing := cfg.Profiles[profile]
			debugEnabled := v.GetBool("debug")
			debugf := func(format string, a ...any) {
				if debugEnabled {
					fmt.Fprintf(os.Stderr, "debug: "+format+"\n", a...)
				}
			}

			p, err := resolveLoginProfile(context.Background(), existing, loginResolveInput{
				GrafanaURL:        v.GetString("grafana-url"),
				IssuerURL:         v.GetString("issuer-url"),
				ClientID:          v.GetString("client-id"),
				ClientSecret:      v.GetString("client-secret"),
				LoginHint:         v.GetString("login-hint"),
				Audience:          v.GetString("audience"),
				Scope:             v.GetString("scope"),
				ScopeProvided:     cmd.Flags().Changed("scope"),
				IssuerProvided:    cmd.Flags().Changed("issuer-url"),
				ClientIDProvided:  cmd.Flags().Changed("client-id"),
				Discover:          v.GetBool("discover"),
				DiscoverTimeout:   v.GetDuration("discover-timeout"),
				DiscoverAllowHTTP: false,
			}, http.DefaultClient, debugf)
			if err != nil {
				return err
			}

			meta, err := discoverProviderMetadata(p.IssuerURL)
			if err != nil {
				return err
			}

			ctx := context.Background()
			var tok *storedToken
			switch v.GetString("method") {
			case "device":
				tok, err = loginDeviceFlow(ctx, p, meta, v.GetBool("open-browser"))
			case "authcode":
				tok, err = loginAuthCodeFlow(ctx, p, meta, v.GetBool("open-browser"))
			default:
				return fmt.Errorf("unsupported login method %q", v.GetString("method"))
			}
			if err != nil {
				return err
			}

			cfg.CurrentProfile = profile
			cfg.Profiles[profile] = p
			if err := saveConfig(cfg); err != nil {
				return err
			}
			if err := saveToken(profile, tok); err != nil {
				return err
			}

			fmt.Printf("login succeeded for profile %q\n", profile)
			return nil
		},
	}

	cmd.Flags().String("profile", defaultProfile, "Profile name")
	cmd.Flags().String("grafana-url", "", "Grafana base URL")
	cmd.Flags().String("issuer-url", "", "OIDC issuer URL (overrides discovery)")
	cmd.Flags().String("client-id", "", "OIDC client ID (overrides discovery)")
	cmd.Flags().String("client-secret", "", "OIDC client secret")
	cmd.Flags().String("login-hint", "", "User identifier hint for IdP (for example: my.email@domain.com)")
	cmd.Flags().String("audience", "", "OIDC audience")
	cmd.Flags().String("scope", "", "Space-separated OIDC scopes (default fallback: openid profile email)")
	cmd.Flags().String("method", "device", "Auth method: device|authcode")
	cmd.Flags().Bool("open-browser", true, "Open browser during auth")
	cmd.Flags().Bool("discover", true, "Auto-discover issuer/client from Grafana login redirects")
	cmd.Flags().Duration("discover-timeout", 10*time.Second, "Timeout for OIDC discovery")
	cmd.Flags().Bool("debug", false, "Print detailed discovery diagnostics")
	_ = cmd.MarkFlagRequired("grafana-url")

	return cmd
}

func newAPICmd(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "api <path>",
		Short:   "Call Grafana API",
		Long:    "Execute authenticated HTTP requests against the configured Grafana instance.",
		Args:    cobra.ExactArgs(1),
		Example: "  surfana api /api/user\n  surfana api -X POST -d '{\"name\":\"x\"}' /api/folders",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := v.BindPFlags(cmd.Flags()); err != nil {
				return err
			}

			cfg, pName, p, err := resolveProfile(v.GetString("profile"))
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

			fullURL, err := joinURLPath(p.GrafanaURL, args[0])
			if err != nil {
				return err
			}

			var reqBody io.Reader
			if v.GetString("data") != "" {
				reqBody = strings.NewReader(v.GetString("data"))
			}
			req, err := http.NewRequest(strings.ToUpper(v.GetString("method")), fullURL, reqBody)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
			req.Header.Set("User-Agent", defaultUserAgent)
			if v.GetString("data") != "" {
				req.Header.Set("Content-Type", v.GetString("content-type"))
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
			if len(respBytes) > 0 {
				var pretty bytes.Buffer
				if json.Indent(&pretty, respBytes, "", "  ") == nil {
					fmt.Println(pretty.String())
				} else {
					fmt.Println(string(respBytes))
				}
			}
			if resp.StatusCode >= 400 {
				return fmt.Errorf("request failed with HTTP %d", resp.StatusCode)
			}
			return nil
		},
	}

	cmd.Flags().String("profile", "", "Profile name (defaults to current profile)")
	cmd.Flags().StringP("method", "X", "GET", "HTTP method")
	cmd.Flags().StringP("data", "d", "", "Request body")
	cmd.Flags().String("content-type", "application/json", "Request body content type")
	return cmd
}

func newWhoAmICmd(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show active profile/token metadata",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := v.BindPFlags(cmd.Flags()); err != nil {
				return err
			}

			cfg, pName, _, err := resolveProfile(v.GetString("profile"))
			if err != nil {
				return err
			}
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
		},
	}
	cmd.Flags().String("profile", "", "Profile name")
	return cmd
}

func newLogoutCmd(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Remove stored token for a profile",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := v.BindPFlags(cmd.Flags()); err != nil {
				return err
			}
			_, pName, _, err := resolveProfile(v.GetString("profile"))
			if err != nil {
				return err
			}
			if err := os.Remove(tokenPath(pName)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			fmt.Printf("logged out profile %q\n", pName)
			return nil
		},
	}
	cmd.Flags().String("profile", "", "Profile name")
	return cmd
}

func newProfilesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "profiles",
		Short: "List configured profiles",
		RunE: func(_ *cobra.Command, _ []string) error {
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
		},
	}
}
