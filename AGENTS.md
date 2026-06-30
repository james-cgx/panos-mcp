# AGENTS.md

This file provides guidance to Codex when working in this repository.

## Project Overview

PAN-OS MCP is a TypeScript MCP server for Palo Alto Networks PAN-OS firewalls and Panorama. It exposes PAN-OS XML API operations as MCP tools for inspection, configuration changes, commits, logs, and Panorama workflows.

Keep the repository public-safe. Do not commit organization-specific deployment details, firewall names, vault names, service account names, or operational runbooks.

## Build and Development Commands

```bash
pnpm install
pnpm run build
pnpm run dev
pnpm test
pnpm run start
pnpm run pack:extension
pnpm audit --prod
```

The repo is pinned to `pnpm@11.9.0` through `packageManager`. Do not add `package-lock.json`.

## Architecture

- `src/index.ts` creates the MCP server, loads credential/configuration sources, registers tool modules, and starts stdio transport.
- `src/api/client.ts` builds PAN-OS XML API requests, handles commits and polling, and uses proxy dispatchers when configured.
- `src/api/proxy.ts` resolves proxy environment variables and builds HTTP/SOCKS dispatchers.
- `src/config/firewalls.ts` loads single-firewall and multi-firewall configuration, supports 1Password-injected environment values, migrates plaintext keys to the OS keychain, and resolves target firewalls for tools.
- `src/config/onepassword.ts` loads selected 1Password Environment variables through the 1Password SDK.
- `src/config/onepassword-cli.ts` relaunches under `op run --environment` for local CLI injection mode.
- `src/config/keychain.ts` wraps OS keychain access through `@napi-rs/keyring`.
- `src/tools/` contains MCP tool registrations grouped by PAN-OS domain.
- `src/schemas/panos.ts` contains reusable Zod schemas for tool inputs.
- `tests/` contains Vitest coverage for config loading, 1Password integration, proxy behavior, and schema compatibility.
- `scripts/` contains extension bundling and packaging scripts.

## Configuration Surfaces

Supported credential/configuration paths:

- Direct environment variables: `PANOS_HOST`, `PANOS_API_KEY`, and optional `PANOS_VERIFY_SSL`.
- 1Password service account mode: `OP_ENVIRONMENT_ID` plus `OP_SERVICE_ACCOUNT_TOKEN`.
- Local 1Password CLI mode: `OP_ENVIRONMENT_ID` without a service account token.
- Multi-firewall config: `~/.config/panos-mcp/firewalls.json` or `PANOS_FIREWALLS_CONFIG`.
- Proxy support: `PANOS_PROXY`, standard proxy variables, and `NO_PROXY`.

See `docs/configuration.md` for public-safe setup details.

## Maintenance Notes

- Keep secret values out of docs, tests, fixtures, and examples.
- Prefer generic placeholder hostnames and variable names.
- Keep README concise; put detailed public setup docs under `docs/`.
- Run build, tests, and production audit before calling cleanup complete.
