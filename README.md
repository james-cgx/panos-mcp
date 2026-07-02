# PAN-OS MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/james-cgx/panos-mcp)](https://github.com/james-cgx/panos-mcp/stargazers)
[![Tests](https://img.shields.io/badge/tests-133%20passing-brightgreen)](https://github.com/james-cgx/panos-mcp/actions)

PAN-OS MCP is a [Model Context Protocol](https://modelcontextprotocol.io) server for Palo Alto Networks PAN-OS firewalls and Panorama. It lets MCP-capable assistants inspect firewall state, read logs, manage objects and policies, and commit configuration through the PAN-OS XML API.

> Warning: this server can give an AI model access to live network infrastructure. Use read-only API keys where possible, review proposed changes before committing, and test in a lab before using it against production firewalls.

## Features

- 117 tools across 16 modules for system, network, security, NAT, objects, Panorama, logs, VPN, certificates, licenses, and utility operations.
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

When running from a local checkout, you can put the Environment ID in `.op/refs.env` instead of exporting it in your shell:

```env
OP_ENVIRONMENT_ID=your-1password-environment-id
```

`panos-mcp` reads that file at startup and then uses the same `op run --environment` flow. The local `.op/refs.env` file is ignored by git.

The Desktop Extension (`.mcpb`) supports one firewall configured at install time. For multiple firewalls or Panorama instances, use the CLI configuration described in [Configuration](docs/configuration.md).

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

- [Configuration](docs/configuration.md) - environment variables, 1Password, keychain storage, multi-firewall mode, and proxy support.
- [Security policy](SECURITY.md) - private vulnerability reporting process.
- [Agent guidance](AGENTS.md) - repository structure and maintenance notes for coding agents.

## Privacy

This server does not collect telemetry or send data to the project authors. API calls go directly from the machine running the MCP server to the configured firewall, Panorama appliance, proxy, or 1Password account when 1Password Environment injection is enabled. Credentials are read from environment variables, 1Password, or local keychain storage depending on configuration.

## License

MIT
