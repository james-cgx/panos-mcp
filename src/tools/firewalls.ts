import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  describeUnconfiguredState,
  getFirewallEntries,
  isMultiFirewall,
  resolveFirewall,
} from "../config/firewalls.js";

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

      return {
        content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
      };
    }
  );
}
