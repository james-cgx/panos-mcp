import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  describeUnconfiguredState,
  getFirewallEntries,
  isMultiFirewall,
  resolveFirewall,
  getInjectedEnvironmentNames,
} from "../config/firewalls.js";
import {
  getCredentialStatus,
  reloadCredentials,
} from "../config/credential-manager.js";

export function registerFirewallTools(server: McpServer) {
  server.tool(
    "list_firewalls",
    "[READ-ONLY] Lists all configured firewall targets. Shows names and hosts (never API keys). Indicates whether the 'firewall' parameter is required for other tools. When nothing is configured, reports the config path and the next steps to configure a target.",
    {},
    { title: "List Firewalls", readOnlyHint: true, destructiveHint: false },
    async () => {
      const entries = getFirewallEntries();

      let data: Record<string, unknown>;
      if (entries.length === 0) {
        const envFirewall = resolveFirewall();
        if (envFirewall) {
          data = {
            mode: "environment",
            firewall_param_required: false,
            firewalls: [{ name: envFirewall.name, host: envFirewall.host }],
          };
        } else {
          data = {
            mode: "unconfigured",
            firewall_param_required: false,
            firewalls: [],
            ...describeUnconfiguredState(),
          };
        }
      } else {
        data = {
          mode: entries.length === 1 ? "single" : "multi",
          firewall_param_required: isMultiFirewall(),
          firewalls: entries.map((e) => ({ name: e.name, host: e.host })),
        };
      }

      data.credential_status = getCredentialStatus();

      return {
        content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
      };
    }
  );

  server.tool(
    "reload_credentials",
    "Forces re-resolution of 1Password-injected credentials and reloads firewalls.json without restarting the server. In direct environment mode, reloads firewalls.json and reports the current direct-mode status.",
    {},
    { title: "Reload Credentials", readOnlyHint: false, destructiveHint: false },
    async () => {
      await reloadCredentials();
      const status = getCredentialStatus();
      const names = getInjectedEnvironmentNames();
      const entries = getFirewallEntries();
      const envFirewall = entries.length === 0 ? resolveFirewall() : null;
      const targets = entries.map((entry) => entry.name);
      if (envFirewall) targets.push(envFirewall.name);

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                mode: status.mode,
                resolved: status.resolved,
                injected_variable_count: names.length,
                injected_variable_names: names,
                firewall_targets: targets,
                last_error: status.lastError,
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );
}
