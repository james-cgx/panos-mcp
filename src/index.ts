#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  describeUnconfiguredState,
  getFirewallEntries,
  loadFirewallConfig,
  resolveFirewall,
} from "./config/firewalls.js";
import { isKeychainAvailable } from "./config/keychain.js";
import { loadInjectedEnvironment } from "./config/environment.js";
import { loadOpEnvironmentIdFromRefsFile, maybeRelaunchUnderOpCli } from "./config/onepassword-cli.js";
import { describeProxy } from "./api/proxy.js";

import { registerFirewallTools } from "./tools/firewalls.js";
import { registerBootstrapTools } from "./tools/bootstrap.js";
import { registerSystemTools } from "./tools/system.js";
import { registerNetworkTools } from "./tools/network.js";
import { registerSecurityTools } from "./tools/security.js";
import { registerObjectsTools } from "./tools/objects.js";
import { registerNatTools } from "./tools/nat.js";
import { registerUserIdTools } from "./tools/userid.js";
import { registerAdminTools } from "./tools/admin.js";
import { registerVpnTools } from "./tools/vpn.js";
import { registerPanoramaTools } from "./tools/panorama.js";
import { registerLogsTools } from "./tools/logs.js";
import { registerThreatTools } from "./tools/threat.js";
import { registerCertificatesTools } from "./tools/certificates.js";
import { registerLicensesTools } from "./tools/licenses.js";
import { registerConfigTools } from "./tools/config.js";
import { registerUtilityTools } from "./tools/utility.js";

const server = new McpServer({
  name: "panos-mcp",
  version: "1.3.24",
});

// Wrap all tool handlers to catch unexpected errors cleanly
const _tool = server.tool.bind(server);
(server.tool as any) = function (...args: any[]) {
  const last = args.length - 1;
  const handler = args[last];
  args[last] = async (...hArgs: any[]) => {
    try {
      return await handler(...hArgs);
    } catch (error) {
      return {
        content: [{ type: "text" as const, text: `Error: ${error instanceof Error ? error.message : String(error)}` }],
      };
    }
  };
  return (_tool as (...a: any[]) => any)(...args);
};

// Register all tools
registerFirewallTools(server);
registerBootstrapTools(server);
registerSystemTools(server);
registerNetworkTools(server);
registerSecurityTools(server);
registerObjectsTools(server);
registerNatTools(server);
registerUserIdTools(server);
registerAdminTools(server);
registerVpnTools(server);
registerPanoramaTools(server);
registerLogsTools(server);
registerThreatTools(server);
registerCertificatesTools(server);
registerLicensesTools(server);
registerConfigTools(server);
registerUtilityTools(server);

async function main() {
  loadOpEnvironmentIdFromRefsFile();

  // Local 1Password CLI mode: re-exec under `op run --environment <id>` so the
  // CLI injects the Environment's variables into our env. The wrapped child sets
  // PANOS_OP_WRAPPED and proceeds normally below.
  const relaunch = await maybeRelaunchUnderOpCli();
  if (relaunch.relaunched) {
    process.exit(relaunch.exitCode ?? 0);
  }

  const injectedCount = await loadInjectedEnvironment();
  if (injectedCount > 0) {
    process.stderr.write(
      `[panos-mcp] Loaded ${injectedCount} environment variable(s) from 1Password Environment\n`
    );
  }

  await loadFirewallConfig();
  if (getFirewallEntries().length === 0 && !resolveFirewall()) {
    const state = describeUnconfiguredState();
    process.stderr.write(
      "[panos-mcp] WARNING: No firewall targets are configured — every firewall tool call will fail.\n" +
        `[panos-mcp]   Config file: ${state.config_path} (${state.config_file_exists ? "exists" : "not found"})\n` +
        (state.injected_unreferenced_env_var_names.length > 0
          ? `[panos-mcp]   Injected but unreferenced environment variables: ${state.injected_unreferenced_env_var_names.join(", ")}\n`
          : "") +
        "[panos-mcp]   Configure a target one of three ways:\n" +
        "[panos-mcp]     1. Set PANOS_HOST and PANOS_API_KEY (directly or in the 1Password Environment).\n" +
        `[panos-mcp]     2. Create ${state.config_path} with entries whose api_key_env references injected variable names.\n` +
        `[panos-mcp]        File shape: ${JSON.stringify(state.config_example)}\n` +
        "[panos-mcp]     3. Panorama-managed fleet: add a single Panorama entry, then run the bootstrap_firewalls_from_panorama tool.\n"
    );
  }
  if (!isKeychainAvailable()) {
    process.stderr.write(
      "[panos-mcp] WARNING: System keychain unavailable — API keys are stored in plaintext. " +
      "Install a keychain provider (macOS Keychain, libsecret on Linux, Windows Credential Manager) " +
      "and re-run `panos-mcp keygen` to migrate keys to secure storage.\n"
    );
  }
  const proxy = describeProxy();
  if (proxy) {
    console.error(`PanOS proxy: ${proxy}`);
  }
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
