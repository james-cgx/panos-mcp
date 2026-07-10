# PAN-OS MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/james-cgx/panos-mcp)](https://github.com/james-cgx/panos-mcp/stargazers)
[![Tests](https://img.shields.io/badge/tests-185%20passing-brightgreen)](https://github.com/james-cgx/panos-mcp/actions)

PAN-OS MCP is a [Model Context Protocol](https://modelcontextprotocol.io) server for Palo Alto Networks PAN-OS firewalls and Panorama. It lets MCP-capable assistants inspect firewall state, read logs, manage objects and policies, and commit configuration through the PAN-OS XML API.

> Warning: this server can give an AI model access to live network infrastructure. Use read-only API keys where possible, review proposed changes before committing, and test in a lab before using it against production firewalls.

## Features

- 118 tools across 17 modules for system, network, security, NAT, objects, Panorama, logs, VPN, certificates, licenses, and utility operations.
- Read-only inspection plus explicit configuration modification and commit tools.
- Single-firewall and multi-firewall modes.
- 1Password Environment support for API key injection.
- OS keychain support for multi-firewall API keys.
- Zod validation for tool inputs.
- Safety labels on tools: `[READ-ONLY]`, `[MODIFIES CONFIG]`, and `[ADVANCED]`.
- Proxy support for firewalls reachable through HTTP, HTTPS, SOCKS4, or SOCKS5 proxies.

## Requirements

- Node.js 22.19 or newer.
- pnpm 11.9.0 for repository development.
- A PAN-OS firewall or Panorama appliance with XML API access enabled.
- A PAN-OS API key.

## Quick Start

For a single firewall, provide credentials directly through environment variables:

```json
{
  "mcpServers": {
    "panos": {
      "command": "pnpm",
      "args": ["dlx", "github:james-cgx/panos-mcp"],
      "env": {
        "PANOS_HOST": "fw.example.com",
        "PANOS_API_KEY": "your-api-key"
      }
    }
  }
}
```

For 1Password Environment injection, create an Environment containing `PANOS_HOST` and `PANOS_API_KEY`, then provide the Environment ID and service account token:

```json
{
  "mcpServers": {
    "panos": {
      "command": "pnpm",
      "args": ["dlx", "github:james-cgx/panos-mcp"],
      "env": {
        "OP_ENVIRONMENT_ID": "your-1password-environment-id",
        "OP_SERVICE_ACCOUNT_TOKEN": "your-1password-service-account-token"
      }
    }
  }
}
```

For local 1Password CLI injection, install and sign in to the `op` CLI, then provide only the Environment ID. The server will relaunch itself under `op run --environment` so the local 1Password session injects `PANOS_HOST` and `PANOS_API_KEY`:

```json
{
  "mcpServers": {
    "panos": {
      "command": "pnpm",
      "args": ["dlx", "github:james-cgx/panos-mcp"],
      "env": {
        "OP_ENVIRONMENT_ID": "your-1password-environment-id"
      }
    }
  }
}
```

The Desktop Extension (`.mcpb`) supports one firewall configured at install time. For multiple firewalls or Panorama instances, use the CLI configuration described below.

## Configuration

PAN-OS MCP can run with a single firewall from environment variables, with 1Password Environment injection, or with a multi-firewall `firewalls.json` file.

### API Keys

To generate a PAN-OS API key directly from a firewall, use the XML API keygen endpoint:

```bash
curl -k -X GET 'https://<FIREWALL_IP_OR_HOST>/api/?type=keygen&user=<USERNAME>&password=<PASSWORD>'
```

This sends credentials in the request URL and skips TLS certificate verification. Use it only from a trusted management network, and prefer a scoped or read-only API key where possible.

### Environment Variables

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

### 1Password Service Account Mode

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

> Important: variables in the Environment are only used if they are `PANOS_HOST`/`PANOS_API_KEY`/`PANOS_VERIFY_SSL` or referenced by an `api_key_env` entry in `firewalls.json`. Nothing is auto-discovered from variable names alone. If the server starts with zero targets, `list_firewalls` reports the unconfigured state and lists injected-but-unreferenced variable names; for Panorama-managed fleets, see [Bootstrapping Multi-Firewall Mode from Panorama](#bootstrapping-multi-firewall-mode-from-panorama).

### 1Password CLI Mode

For local use, set `OP_ENVIRONMENT_ID` without `OP_SERVICE_ACCOUNT_TOKEN`. The server relaunches itself under:

```bash
op run --environment "$OP_ENVIRONMENT_ID" -- panos-mcp
```

This lets the local 1Password CLI inject Environment variables using the signed-in local `op` session. Install the 1Password CLI, sign in, and ensure `op` is on `PATH`, or set `OP_CLI_PATH`.

When running from a local checkout, you can put the Environment ID in `.op/refs.env` instead of exporting it in your shell:

```env
OP_ENVIRONMENT_ID=your-1password-environment-id
```

`panos-mcp` reads that file at startup and then uses the same `op run --environment` flow. The local `.op/refs.env` file is ignored by git.

Unlike service account mode, `op run` injects the full selected Environment into the process environment. Keep that Environment scoped to PAN-OS MCP values. Injected variables are detected by comparing the environment before and after `op run` (names only), so a variable already exported in the parent shell under the same name is invisible to injected-name detection — avoid exporting variables that duplicate Environment entry names.

> Important: the same referencing rule applies here — injected variables are only used when named `PANOS_HOST`/`PANOS_API_KEY`/`PANOS_VERIFY_SSL` or referenced by an `api_key_env` entry in `firewalls.json`. An Environment full of per-firewall API keys does nothing by itself; see [Bootstrapping Multi-Firewall Mode from Panorama](#bootstrapping-multi-firewall-mode-from-panorama) to wire them up.

### Multi-Firewall Mode

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

### Bootstrapping Multi-Firewall Mode from Panorama

If your firewalls are Panorama-managed and a 1Password Environment already holds one API key per firewall — each variable named after the device hostname with non-alphanumerics replaced by underscores (device `HQ-FW1`, variable `HQ_FW1`) — the `bootstrap_firewalls_from_panorama` tool can populate `firewalls.json` for you:

1. Create a one-entry `firewalls.json` for Panorama (only its address needs to be known up front):

   ```json
   {
     "firewalls": [
       { "name": "panorama", "host": "panorama.example.com", "api_key_env": "PANORAMA_API_KEY" }
     ]
   }
   ```

2. Start the server and call `bootstrap_firewalls_from_panorama` (dry run by default). It queries Panorama's managed devices, matches hostnames to injected variable names, and shows the proposed entries plus anything unmatched in either direction.
3. Re-run with `dry_run: false` to merge the entries into `firewalls.json` (existing entries are never modified or removed) and load them without a restart.
4. Verify with `list_firewalls` and spot-check one target with `get_firewall_info`.

When no target is configured at all, both the startup log and `list_firewalls` report the resolved config path and the injected-but-unreferenced variable names (names only, never values) to point you at this flow.

### Plaintext Migration and Fallback

If an existing `firewalls.json` contains `api_key` fields and the OS keychain is available, startup migrates those keys into the keychain and rewrites the file without plaintext keys.

If no keychain provider is available, API keys can fall back to plaintext in `firewalls.json` with a warning. Restrict file permissions in that case.

### Proxy Support

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

## Development

```bash
pnpm install
pnpm run build
pnpm test
pnpm run start
```

Useful scripts:

```bash
pnpm run dev             # TypeScript watch mode
pnpm run keygen          # Generate and save a firewall API key
pnpm run pack:extension  # Build the Desktop Extension package
pnpm audit --prod        # Audit production dependencies
```

## Documentation

- [Security policy](SECURITY.md) - private vulnerability reporting process.
- [Agent guidance](AGENTS.md) - repository structure and maintenance notes for coding agents.

## Privacy

This server does not collect telemetry or send data to the project authors. API calls go directly from the machine running the MCP server to the configured firewall, Panorama appliance, proxy, or 1Password account when 1Password Environment injection is enabled. Credentials are read from environment variables, 1Password, or local keychain storage depending on configuration.

## License

MIT
