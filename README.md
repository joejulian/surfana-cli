# surfana-cli

`surfana-cli` is a Go command-line utility for authenticating to Grafana environments backed by OIDC/SAML SSO and querying Grafana HTTP APIs.

It supports:
- OIDC device authorization flow (ideal for terminal-first auth)
- OIDC authorization code + PKCE flow (browser + local callback)
- Local token persistence and refresh
- Profile-based configuration

## License

Apache License 2.0. See [LICENSE](./LICENSE).

## CI/CD

GitHub Actions workflows are included for:
- Lint, test, and build on PRs and pushes to `main`
- Conventional Commit-style PR title validation
- Automatic semantic version tags from Conventional Commits on `main`, with GoReleaser publishing on newly created tags
- Tagged release builds for Linux/macOS/Windows via GoReleaser with checksums

## Build

```bash
go build -o surfana ./...
```

## Quick start

1. Log in with discovery-first flow:

```bash
./surfana login \
  --grafana-url https://grafana.example.com
```

2. Manual overrides (if discovery cannot determine everything):

```bash
./surfana login \
  --grafana-url https://grafana.example.com \
  --issuer-url https://idp.example.com \
  --client-id YOUR_CLIENT_ID
```

3. Query Grafana API:

```bash
./surfana api /api/user
```

4. Check session details:

```bash
./surfana whoami
```

## Commands

- `surfana login`
  - Persists profile config and token in `~/.config/surfana/` (or `$XDG_CONFIG_HOME/surfana/`)
  - Flags:
    - `--profile` (default: `default`)
    - `--grafana-url`
    - `--issuer-url`
    - `--client-id`
    - `--client-secret` (optional)
    - `--audience` (optional)
    - `--scope` (default fallback: `openid profile email`)
    - `--method` (`device` or `authcode`, default: `device`)
    - `--open-browser` (default: `true`)
    - `--discover` (default: `true`)
    - `--discover-timeout` (default: `10s`)
    - `--debug` (prints discovery and selection diagnostics)

- `surfana api [flags] <path>`
  - Executes authenticated requests against Grafana
  - Flags:
    - `--profile`
    - `-X` HTTP method (default: `GET`)
    - `-d` request body
    - `--content-type` (default: `application/json`)

- `surfana whoami`
  - Shows active profile/token metadata

- `surfana logout`
  - Removes stored token for the selected profile

- `surfana profiles`
  - Lists configured profiles

## Notes for SAML/OIDC Grafana setups

Grafana SAML/OIDC UI login establishes a browser session. For CLI access, your Grafana deployment must accept bearer tokens issued by your IdP for API auth (commonly via Grafana auth proxy/JWT or equivalent gateway integration).

If your deployment only supports browser cookie sessions, this CLI can still complete OIDC auth but Grafana API bearer calls will be rejected until Grafana-side token acceptance is configured.

## Security

- Config and token files are written with `0600` permissions.
- Tokens are stored plaintext on disk; use OS-level disk encryption or secrets tooling where required by policy.
- OIDC auto-discovery trusts HTTPS endpoints only.

## Troubleshooting Discovery

- If discovery only finds one value, provide the other manually:
  - `--issuer-url https://idp.example.com`
  - `--client-id YOUR_CLIENT_ID`
- Use `--debug` to print discovery steps (visited URLs, redirect chain, selected issuer/client sources).
- Increase `--discover-timeout` for slow auth gateways.
