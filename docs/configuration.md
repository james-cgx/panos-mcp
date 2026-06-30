# Configuration

PAN-OS MCP can run with a single firewall from environment variables, with 1Password Environment injection, or with a multi-firewall `firewalls.json` file.

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `PANOS_HOST` | Firewall or Panorama hostname or IP address. |
| `PANOS_API_KEY` | PAN-OS XML API key. |
| `PANOS_VERIFY_SSL` | Optional. Set to `true`, `1`, `yes`, or `on` to verify the PAN-OS TLS certificate. Defaults to disabled. |
| `PANOS_FIREWALLS_CONFIG` | Optional path to a multi-firewall JSON config file. Defaults to `~/.config/panos-mcp/firewalls.json`. |
| `OP_ENVIRONMENT_ID` | 1Password Environment ID. |
| `OP_SERVICE_ACCOUNT_TOKEN` | 1Password service account token for server-side Environment loading. |
| `OP_CLI_PATH` | Optional path to the local `op` CLI for local 1Password CLI mode. |

When no `firewalls.json` entries are loaded, the server falls back to `PANOS_HOST` and `PANOS_API_KEY`.

## 1Password Service Account Mode

Create a 1Password Environment containing:

```text
PANOS_HOST=fw.example.com
PANOS_API_KEY=your-api-key
```

Start the server with:

```text
OP_ENVIRONMENT_ID=your-1password-environment-id
OP_SERVICE_ACCOUNT_TOKEN=your-1password-service-account-token
```

The server only keeps expected PAN-OS variables in memory: `PANOS_HOST`, `PANOS_API_KEY`, `PANOS_VERIFY_SSL`, and any variable names referenced by `api_key_env` entries in `firewalls.json`.

## 1Password CLI Mode

For local use, set `OP_ENVIRONMENT_ID` without `OP_SERVICE_ACCOUNT_TOKEN`. The server relaunches itself under:

```bash
op run --environment "$OP_ENVIRONMENT_ID" -- panos-mcp
```

This lets the local 1Password CLI inject Environment variables using the signed-in local `op` session. Install the 1Password CLI, sign in, and ensure `op` is on `PATH`, or set `OP_CLI_PATH`.

Unlike service account mode, `op run` injects the full selected Environment into the process environment. Keep that Environment scoped to PAN-OS MCP values.

## Multi-Firewall Mode

Use `panos-keygen` to generate and save API keys:

```bash
pnpm dlx --package github:james-cgx/panos-mcp panos-keygen --host fw-hq.example.com --user admin --name hq-fw
pnpm dlx --package github:james-cgx/panos-mcp panos-keygen --host panorama.example.com --user admin --name panorama
```

The CLI stores API keys in the OS keychain when available and writes non-secret host metadata to `~/.config/panos-mcp/firewalls.json`.

Example `firewalls.json` using 1Password variable references:

```json
{
  "firewalls": [
    {
      "name": "hq-fw",
      "host": "fw-hq.example.com",
      "api_key_env": "PANOS_HQ_FW_API_KEY"
    },
    {
      "name": "panorama",
      "host": "panorama.example.com",
      "api_key_env": "PANOS_PANORAMA_API_KEY",
      "verify_ssl": true
    }
  ]
}
```

When more than one firewall is configured, tools accept a `firewall` parameter. It is required in multi-firewall mode and optional when there is only one configured target.

## Plaintext Migration and Fallback

If an existing `firewalls.json` contains `api_key` fields and the OS keychain is available, startup migrates those keys into the keychain and rewrites the file without plaintext keys.

If no keychain provider is available, API keys can fall back to plaintext in `firewalls.json` with a warning. Restrict file permissions in that case.

## Proxy Support

Set one of these variables when the firewall is reachable only through a proxy:

| Variable | Purpose |
| --- | --- |
| `PANOS_PROXY` | Explicit proxy override. Used even when `NO_PROXY` is set. |
| `HTTPS_PROXY` / `https_proxy` | Standard HTTPS proxy. |
| `HTTP_PROXY` / `http_proxy` | HTTP proxy fallback. |
| `ALL_PROXY` / `all_proxy` | SOCKS or generic proxy fallback. |
| `NO_PROXY` / `no_proxy` | Comma-separated bypass list. `*` disables proxying unless `PANOS_PROXY` is set. |

Supported proxy schemes:

- `http://[user:pass@]host:port`
- `https://[user:pass@]host:port`
- `socks5://[user:pass@]host:port`
- `socks5h://[user:pass@]host:port`
- `socks4://[user@]host:port`
- `socks4a://[user@]host:port`

Use `socks5h` when the firewall hostname only resolves on the proxy side.
