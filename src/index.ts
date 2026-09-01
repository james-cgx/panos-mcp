#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { startCredentialRetryLoop } from "./config/credential-manager.js";
import { loadOpEnvironmentIdFromRefsFile } from "./config/onepassword-cli.js";
import { describeProxy } from "./api/proxy.js";
import { diagnostic, errorDetails } from "./diagnostics.js";

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

function installProcessDiagnostics(): void {
  process.on("uncaughtException", (error) => {
    diagnostic(`Uncaught exception: ${errorDetails(error)}`);
  });
  process.on("unhandledRejection", (reason) => {
    diagnostic(`Unhandled rejection: ${errorDetails(reason)}`);
  });
  process.on("exit", (code) => {
    diagnostic(`Process exiting with code ${code}`);
  });

  const handleSignal = (signal: NodeJS.Signals) => {
    diagnostic(`Received ${signal}; shutting down`);
    process.exit(0);
  };
  process.on("SIGTERM", () => handleSignal("SIGTERM"));
  process.on("SIGINT", () => handleSignal("SIGINT"));
  if (process.platform !== "win32") {
    try {
      process.on("SIGHUP", () => handleSignal("SIGHUP"));
    } catch (error) {
      diagnostic(`Could not install SIGHUP handler: ${errorDetails(error)}`);
    }
  }
}

async function main() {
  installProcessDiagnostics();
  loadOpEnvironmentIdFromRefsFile();

  const proxy = describeProxy();
  if (proxy) diagnostic(`PanOS proxy: ${proxy}`);

  const transport = new StdioServerTransport();
  // The SDK transport does not always self-close on stdin EOF; treat it as a
  // client disconnect so the server never lingers as an orphan process.
  process.stdin.once("end", () => {
    diagnostic("Stdin ended — client disconnected; shutting down");
    void server
      .close()
      .catch((error) => diagnostic(`Error closing server: ${errorDetails(error)}`))
      .finally(() => process.exit(0));
  });
  await server.connect(transport);
  server.server.onclose = () => diagnostic("Stdio transport closed");

  // Credential/config failures are supervised in the background. They never
  // delay the MCP handshake and never terminate the server process.
  startCredentialRetryLoop();
}

void main().catch((error) => {
  diagnostic(`Startup failed after transport setup: ${errorDetails(error)}`);
});
