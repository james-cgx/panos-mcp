import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeOpCommand, formatResponse, isApiError, resolveTarget } from "../api/client.js";
import { firewallName } from "../schemas/panos.js";
import {
  getConfigPath,
  getFirewallEntries,
  getUnreferencedInjectedNames,
  loadFirewallConfig,
  mergeEnvKeyedFirewallEntries,
} from "../config/firewalls.js";
import { loadInjectedEnvironment } from "../config/environment.js";

/** Device hostname → environment-variable-name form: uppercase, non-alphanumerics to underscores. */
export function normalizeForMatch(value: string): string {
  return value.toUpperCase().replace(/[^A-Z0-9]/g, "_");
}

export interface ManagedDevice {
  hostname: string;
  host: string;
  serial: string;
  connected: boolean;
}

/** Extracts managed devices from a parsed `show devices all` response. */
export function parseManagedDevices(data: unknown): ManagedDevice[] {
  const raw = (data as { devices?: { entry?: unknown } } | null)?.devices?.entry;
  if (!raw) return [];
  const list = Array.isArray(raw) ? raw : [raw];
  return list
    .map((e: any) => ({
      hostname: e?.hostname === undefined ? "" : String(e.hostname),
      host: e?.["ip-address"] === undefined ? "" : String(e["ip-address"]),
      serial: String(e?.["@_name"] ?? e?.serial ?? ""),
      connected: e?.connected === true || String(e?.connected ?? "").toLowerCase() === "yes",
    }))
    .filter((d) => d.hostname);
}

export interface BootstrapPlan {
  proposed_entries: Array<{ name: string; host: string; api_key_env: string; verify_ssl?: boolean }>;
  unmatched_devices: Array<{ hostname: string; host: string }>;
  unmatched_env_vars: string[];
}

/**
 * Matches device hostnames to candidate environment variable names,
 * case-insensitively, by normalizing both sides with normalizeForMatch. Each
 * variable is consumed by at most one device. Both unmatched directions are
 * reported so nothing is silently dropped — including candidates whose
 * normalized names collide with an earlier candidate.
 */
export function planBootstrap(devices: ManagedDevice[], candidateEnvVars: string[]): BootstrapPlan {
  const varsByNormalizedName = new Map<string, string>();
  const collidingNames: string[] = [];
  for (const name of candidateEnvVars) {
    const normalized = normalizeForMatch(name);
    if (varsByNormalizedName.has(normalized)) collidingNames.push(name);
    else varsByNormalizedName.set(normalized, name);
  }

  const proposed: BootstrapPlan["proposed_entries"] = [];
  const unmatchedDevices: BootstrapPlan["unmatched_devices"] = [];
  for (const device of devices) {
    const envVar = varsByNormalizedName.get(normalizeForMatch(device.hostname));
    if (envVar) {
      varsByNormalizedName.delete(normalizeForMatch(device.hostname));
      proposed.push({
        name: device.hostname,
        host: device.host || device.hostname,
        api_key_env: envVar,
      });
    } else {
      unmatchedDevices.push({ hostname: device.hostname, host: device.host || device.hostname });
    }
  }

  return {
    proposed_entries: proposed,
    unmatched_devices: unmatchedDevices,
    unmatched_env_vars: [...varsByNormalizedName.values(), ...collidingNames].sort(),
  };
}

function jsonResponse(data: unknown): { content: Array<{ type: "text"; text: string }> } {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

const SHADOWING_CAVEAT =
  "Note: in local 1Password CLI mode, an Environment variable whose name already existed in the " +
  "shell environment before launch cannot be detected as injected — unset or rename shell exports " +
  "that duplicate Environment entry names, or add the entry to firewalls.json manually with " +
  "api_key_env (shell-exported values are still read).";

export function registerBootstrapTools(server: McpServer) {
  server.tool(
    "bootstrap_firewalls_from_panorama",
    "[MODIFIES CONFIG] Builds firewalls.json entries for Panorama-managed firewalls by matching device hostnames to injected 1Password environment variable names (hostname normalized: uppercase, non-alphanumerics become underscores; e.g. device 'HQ-FW1' matches variable 'HQ_FW1'). Requires a configured Panorama target: a firewalls.json entry (created any time, even while the server is running — config is re-read on every call; list_firewalls shows the file shape when unconfigured) or the PANOS_HOST/PANOS_API_KEY fallback. Defaults to dry_run=true (preview only). With dry_run=false, merges into the local config file — existing entries are never modified or removed — and reloads targets in-process so no restart is needed.",
    {
      firewall: firewallName,
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the proposed entries without writing the config file (default: true)"),
      connected_only: z
        .boolean()
        .optional()
        .describe("Only include devices currently connected to Panorama (default: true)"),
    },
    { title: "Bootstrap Firewalls From Panorama", readOnlyHint: false, destructiveHint: false },
    async ({ firewall, dry_run, connected_only }) => {
      const dryRun = dry_run ?? true;

      // Pick up config/credentials created after startup: the guided
      // zero-to-configured flow has the user write a one-entry Panorama config
      // while the server is already running. Same idempotent sequence as the
      // post-merge reload below.
      await loadInjectedEnvironment();
      await loadFirewallConfig();

      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);

      // With no config entries, the target came from the PANOS_HOST/
      // PANOS_API_KEY fallback — which stops resolving as soon as entries
      // exist. Persist it alongside the discovered firewalls so the Panorama
      // target survives the bootstrap.
      const usingEnvFallback = getFirewallEntries().length === 0;

      const result = await executeOpCommand("<show><devices><all></all></devices></show>", target);
      if (!result.success) return formatResponse(result);

      const allDevices = parseManagedDevices(result.data);
      const connectedDevices = (connected_only ?? true)
        ? allDevices.filter((d) => d.connected)
        : allDevices;
      const skippedDisconnected = allDevices.length - connectedDevices.length;

      // Devices already present in the config are reported separately instead
      // of as unmatched, so re-running the tool is idempotent and readable.
      const existingNames = new Set(getFirewallEntries().map((e) => normalizeForMatch(e.name)));
      const alreadyConfigured = connectedDevices
        .filter((d) => existingNames.has(normalizeForMatch(d.hostname)))
        .map((d) => d.hostname);
      const devices = connectedDevices.filter(
        (d) => !existingNames.has(normalizeForMatch(d.hostname))
      );

      const candidates = getUnreferencedInjectedNames();
      const plan = planBootstrap(devices, candidates);

      if (usingEnvFallback && plan.proposed_entries.length > 0) {
        plan.proposed_entries.unshift({
          name: "panorama",
          host: target.host,
          api_key_env: "PANOS_API_KEY",
          ...(target.verifySSL ? { verify_ssl: true } : {}),
        });
      }

      const common = {
        config_path: getConfigPath(),
        unmatched_devices: plan.unmatched_devices,
        unmatched_env_vars: plan.unmatched_env_vars,
        ...(alreadyConfigured.length > 0 ? { already_configured: alreadyConfigured } : {}),
        ...(skippedDisconnected > 0 ? { skipped_disconnected_devices: skippedDisconnected } : {}),
      };

      if (dryRun) {
        return jsonResponse({
          dry_run: true,
          proposed_entries: plan.proposed_entries,
          ...common,
          next_steps:
            plan.proposed_entries.length > 0
              ? "Re-run with dry_run=false to merge these entries into the config file and load them."
              : devices.length === 0 && alreadyConfigured.length > 0
                ? "All connected managed devices are already configured — nothing to do."
                : candidates.length === 0
                  ? "No injected-but-unreferenced environment variables were found to match against. In 1Password modes, ensure the Environment contains one API key variable per firewall, named after the device hostname with non-alphanumerics replaced by underscores. " +
                    SHADOWING_CAVEAT
                  : "No managed devices matched the available environment variable names. Check the hostname-to-variable naming convention (uppercase, non-alphanumerics become underscores). " +
                    SHADOWING_CAVEAT,
        });
      }

      const { added, skipped_existing, rejected } = mergeEnvKeyedFirewallEntries(
        plan.proposed_entries
      );
      // Re-load injected credentials so the newly referenced api_key_env values
      // are available in service-account mode, then reload targets. The config
      // write above already succeeded, so a reload failure is reported as
      // partial success rather than masking the write behind a bare error.
      let reloadError: string | undefined;
      try {
        await loadInjectedEnvironment();
        await loadFirewallConfig();
      } catch (error) {
        reloadError = error instanceof Error ? error.message : String(error);
      }

      return jsonResponse({
        dry_run: false,
        added,
        skipped_existing,
        ...(rejected.length > 0 ? { rejected } : {}),
        ...common,
        loaded_firewalls: getFirewallEntries().map((e) => e.name),
        ...(reloadError !== undefined
          ? {
              reload_error: reloadError,
              next_steps:
                "The entries were written to the config file, but reloading credentials/targets failed. " +
                "Re-run with dry_run=false (idempotent: existing entries are skipped and the reload retried), or restart the server.",
            }
          : {
              next_steps:
                "Verify with list_firewalls, then spot-check one new target with get_firewall_info.",
            }),
      });
    }
  );
}
