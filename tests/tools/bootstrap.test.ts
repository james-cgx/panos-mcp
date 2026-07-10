import { describe, it, expect, beforeEach, vi } from "vitest";
import { readFileSync, writeFileSync, unlinkSync, existsSync } from "fs";
import { resolve } from "path";

vi.mock("../../src/config/keychain.js", () => ({
  getKey: vi.fn(),
  setKey: vi.fn(),
  deleteKey: vi.fn(),
  isKeychainAvailable: vi.fn(),
  initKeychain: vi.fn().mockResolvedValue(undefined),
}));

// Only the network call is mocked — resolveTarget stays real so these tests
// exercise genuine target resolution against the loaded config state.
vi.mock("../../src/api/client.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/api/client.js")>();
  return { ...actual, executeOpCommand: vi.fn() };
});

vi.mock("../../src/config/environment.js", () => ({
  loadInjectedEnvironment: vi.fn().mockResolvedValue(0),
}));

import { getKey, isKeychainAvailable } from "../../src/config/keychain.js";
import { executeOpCommand } from "../../src/api/client.js";
import { loadInjectedEnvironment } from "../../src/config/environment.js";
import {
  getFirewallEntries,
  loadFirewallConfig,
  recordInjectedEnvironmentNames,
  resolveFirewall,
  setInjectedEnvironment,
} from "../../src/config/firewalls.js";
import {
  normalizeForMatch,
  parseManagedDevices,
  planBootstrap,
  registerBootstrapTools,
} from "../../src/tools/bootstrap.js";

const tmpConfig = resolve("bootstrap.tools.test.tmp.json");

function cleanup() {
  try { unlinkSync(tmpConfig); } catch {}
}

describe("normalizeForMatch", () => {
  it("uppercases and replaces hyphens with underscores", () => {
    expect(normalizeForMatch("HQ-FW1")).toBe("HQ_FW1");
    expect(normalizeForMatch("hq-fw1")).toBe("HQ_FW1");
  });

  it("replaces every non-alphanumeric character", () => {
    expect(normalizeForMatch("br.fw 2")).toBe("BR_FW_2");
  });

  it("preserves digits", () => {
    expect(normalizeForMatch("fw01-dc3")).toBe("FW01_DC3");
  });
});

describe("parseManagedDevices", () => {
  it("parses an array of device entries", () => {
    const devices = parseManagedDevices({
      devices: {
        entry: [
          { "@_name": "001122334455", hostname: "HQ-FW1", "ip-address": "10.0.0.1", connected: "yes" },
          { "@_name": "001122334466", hostname: "BR-FW2", "ip-address": "10.0.0.2", connected: "no" },
        ],
      },
    });

    expect(devices).toEqual([
      { hostname: "HQ-FW1", host: "10.0.0.1", serial: "001122334455", connected: true },
      { hostname: "BR-FW2", host: "10.0.0.2", serial: "001122334466", connected: false },
    ]);
  });

  it("handles a single device entry parsed as an object", () => {
    const devices = parseManagedDevices({
      devices: { entry: { hostname: "HQ-FW1", "ip-address": "10.0.0.1", connected: "yes" } },
    });

    expect(devices).toHaveLength(1);
    expect(devices[0].hostname).toBe("HQ-FW1");
  });

  it("returns an empty list for empty or missing device data", () => {
    expect(parseManagedDevices({ devices: "" })).toEqual([]);
    expect(parseManagedDevices({})).toEqual([]);
    expect(parseManagedDevices(null)).toEqual([]);
  });

  it("coerces numeric-looking hostnames to strings", () => {
    const devices = parseManagedDevices({
      devices: { entry: { hostname: 12345, "ip-address": "10.0.0.1", connected: "yes" } },
    });

    expect(devices[0].hostname).toBe("12345");
  });
});

describe("planBootstrap", () => {
  const device = (hostname: string, host = "10.0.0.1") => ({
    hostname,
    host,
    serial: "s",
    connected: true,
  });

  it("matches device hostnames to variable names via normalization", () => {
    const plan = planBootstrap([device("HQ-FW1")], ["HQ_FW1"]);

    expect(plan.proposed_entries).toEqual([
      { name: "HQ-FW1", host: "10.0.0.1", api_key_env: "HQ_FW1" },
    ]);
    expect(plan.unmatched_devices).toEqual([]);
    expect(plan.unmatched_env_vars).toEqual([]);
  });

  it("matches case-insensitively and keeps the original variable name", () => {
    const plan = planBootstrap([device("HQ-FW1")], ["hq_fw1"]);

    expect(plan.proposed_entries[0].api_key_env).toBe("hq_fw1");
  });

  it("reports both unmatched directions", () => {
    const plan = planBootstrap([device("HQ-FW1"), device("LONELY-FW", "10.0.0.9")], ["HQ_FW1", "SPARE_KEY"]);

    expect(plan.proposed_entries).toHaveLength(1);
    expect(plan.unmatched_devices).toEqual([{ hostname: "LONELY-FW", host: "10.0.0.9" }]);
    expect(plan.unmatched_env_vars).toEqual(["SPARE_KEY"]);
  });

  it("consumes each variable at most once", () => {
    const plan = planBootstrap([device("HQ-FW1", "10.0.0.1"), device("HQ-FW1", "10.0.0.2")], ["HQ_FW1"]);

    expect(plan.proposed_entries).toHaveLength(1);
    expect(plan.unmatched_devices).toEqual([{ hostname: "HQ-FW1", host: "10.0.0.2" }]);
  });

  it("falls back to the hostname when a device has no IP address", () => {
    const plan = planBootstrap([{ hostname: "HQ-FW1", host: "", serial: "s", connected: true }], ["HQ_FW1"]);

    expect(plan.proposed_entries[0].host).toBe("HQ-FW1");
  });

  it("reports normalization-collision losers instead of silently dropping them", () => {
    const plan = planBootstrap([device("HQ-FW1")], ["HQ_FW1", "hq_fw1"]);

    expect(plan.proposed_entries[0].api_key_env).toBe("HQ_FW1");
    expect(plan.unmatched_env_vars).toEqual(["hq_fw1"]);
  });
});

type ToolHandler = (args: {
  firewall?: string;
  dry_run?: boolean;
  connected_only?: boolean;
}) => Promise<{ content: Array<{ type: "text"; text: string }> }>;

function getBootstrapHandler(): ToolHandler {
  let handler: ToolHandler | undefined;
  const fakeServer = {
    tool: (...args: unknown[]) => {
      handler = args[args.length - 1] as ToolHandler;
    },
  };
  registerBootstrapTools(fakeServer as any);
  if (!handler) throw new Error("bootstrap_firewalls_from_panorama was not registered");
  return handler;
}

describe("bootstrap_firewalls_from_panorama tool", () => {
  beforeEach(async () => {
    cleanup();
    vi.clearAllMocks();
    vi.mocked(isKeychainAvailable).mockReturnValue(true);
    vi.mocked(getKey).mockResolvedValue(null);
    process.env.PANOS_FIREWALLS_CONFIG = tmpConfig;
    delete process.env.PANOS_HOST;
    delete process.env.PANOS_API_KEY;
    delete process.env.HQ_FW1;
    delete process.env.BR_FW2;

    writeFileSync(
      tmpConfig,
      JSON.stringify({
        firewalls: [{ name: "panorama", host: "panorama.example.com", api_key_env: "PANORAMA_KEY" }],
      })
    );
    setInjectedEnvironment(new Map([["PANORAMA_KEY", "p-key"]]));
    recordInjectedEnvironmentNames(["HQ_FW1", "BR_FW2", "SPARE_KEY"]);
    await loadFirewallConfig();

    vi.mocked(executeOpCommand).mockResolvedValue({
      success: true,
      data: {
        devices: {
          entry: [
            { hostname: "HQ-FW1", "ip-address": "10.0.0.1", connected: "yes" },
            { hostname: "BR-FW2", "ip-address": "10.0.0.2", connected: "no" },
            { hostname: "OTHER-FW", "ip-address": "10.0.0.3", connected: "yes" },
          ],
        },
      },
    });
  });

  async function call(args: Parameters<ToolHandler>[0] = {}) {
    const result = await getBootstrapHandler()(args);
    return JSON.parse(result.content[0].text);
  }

  it("defaults to a dry run that proposes matches without writing", async () => {
    const data = await call({ firewall: "panorama" });

    expect(data.dry_run).toBe(true);
    expect(data.proposed_entries).toEqual([
      { name: "HQ-FW1", host: "10.0.0.1", api_key_env: "HQ_FW1" },
    ]);
    expect(data.skipped_disconnected_devices).toBe(1);
    expect(data.unmatched_devices).toEqual([{ hostname: "OTHER-FW", host: "10.0.0.3" }]);
    expect(data.unmatched_env_vars).toEqual(["BR_FW2", "SPARE_KEY"]);

    const config = JSON.parse(readFileSync(tmpConfig, "utf-8"));
    expect(config.firewalls).toHaveLength(1);
  });

  it("includes disconnected devices when connected_only is false", async () => {
    const data = await call({ firewall: "panorama", connected_only: false });

    expect(data.proposed_entries.map((e: { name: string }) => e.name)).toEqual([
      "HQ-FW1",
      "BR-FW2",
    ]);
    expect(data.skipped_disconnected_devices).toBeUndefined();
  });

  it("merges into the config and reloads targets with dry_run=false", async () => {
    process.env.HQ_FW1 = "hq-key";

    const data = await call({ firewall: "panorama", dry_run: false });

    expect(data.dry_run).toBe(false);
    expect(data.added).toEqual(["HQ-FW1"]);
    expect(data.skipped_existing).toEqual([]);
    expect(data.loaded_firewalls).toEqual(["panorama", "HQ-FW1"]);

    const config = JSON.parse(readFileSync(tmpConfig, "utf-8"));
    expect(config.firewalls).toEqual([
      { name: "panorama", host: "panorama.example.com", api_key_env: "PANORAMA_KEY" },
      { name: "HQ-FW1", host: "10.0.0.1", api_key_env: "HQ_FW1" },
    ]);

    expect(vi.mocked(loadInjectedEnvironment)).toHaveBeenCalled();
    expect(getFirewallEntries().map((e) => e.name)).toEqual(["panorama", "HQ-FW1"]);
    expect(resolveFirewall("HQ-FW1")).toEqual({
      name: "HQ-FW1",
      host: "10.0.0.1",
      api_key: "hq-key",
      verify_ssl: false,
    });
  });

  it("is idempotent: a re-run reports configured devices instead of re-adding them", async () => {
    process.env.HQ_FW1 = "hq-key";
    await call({ firewall: "panorama", dry_run: false });

    const data = await call({ firewall: "panorama", dry_run: false });

    expect(data.added).toEqual([]);
    expect(data.already_configured).toEqual(["HQ-FW1"]);
    const config = JSON.parse(readFileSync(tmpConfig, "utf-8"));
    expect(config.firewalls).toHaveLength(2);
  });

  it("explains when no candidate variables exist", async () => {
    setInjectedEnvironment(new Map([["PANORAMA_KEY", "p-key"]]));
    await loadFirewallConfig();

    const data = await call({ firewall: "panorama" });

    expect(data.proposed_entries).toEqual([]);
    expect(data.next_steps).toContain("No injected-but-unreferenced environment variables");
  });

  it("propagates Panorama API errors", async () => {
    vi.mocked(executeOpCommand).mockResolvedValue({ success: false, error: "PanOS API Error: boom" });

    const result = await getBootstrapHandler()({ firewall: "panorama" });

    expect(result.content[0].text).toContain("PanOS API Error: boom");
    expect(existsSync(tmpConfig)).toBe(true);
  });

  it("resolves a Panorama entry created after startup without a restart", async () => {
    cleanup();
    await loadFirewallConfig();
    expect(getFirewallEntries()).toHaveLength(0);

    // The one-entry Panorama config is created while the server is running.
    writeFileSync(
      tmpConfig,
      JSON.stringify({
        firewalls: [{ name: "panorama", host: "panorama.example.com", api_key_env: "PANORAMA_KEY" }],
      })
    );

    const data = await call({ firewall: "panorama" });

    expect(data.dry_run).toBe(true);
    expect(data.proposed_entries).toEqual([
      { name: "HQ-FW1", host: "10.0.0.1", api_key_env: "HQ_FW1" },
    ]);
    expect(getFirewallEntries().map((e) => e.name)).toEqual(["panorama"]);
  });

  it("persists the env-fallback Panorama target instead of silently dropping it", async () => {
    cleanup();
    process.env.PANOS_HOST = "panorama.example.com";
    process.env.PANOS_API_KEY = "env-p-key";
    process.env.HQ_FW1 = "hq-key";
    setInjectedEnvironment(new Map());
    recordInjectedEnvironmentNames(["HQ_FW1"]);
    await loadFirewallConfig();

    const preview = await call({});
    expect(preview.proposed_entries[0]).toEqual({
      name: "panorama",
      host: "panorama.example.com",
      api_key_env: "PANOS_API_KEY",
    });

    const data = await call({ dry_run: false });
    expect(data.added).toEqual(["panorama", "HQ-FW1"]);
    expect(resolveFirewall("panorama")).toEqual({
      name: "panorama",
      host: "panorama.example.com",
      api_key: "env-p-key",
      verify_ssl: false,
    });
  });

  it("reports partial success when the post-write reload fails", async () => {
    process.env.HQ_FW1 = "hq-key";
    vi.mocked(loadInjectedEnvironment)
      .mockResolvedValueOnce(0)
      .mockRejectedValueOnce(new Error("[panos-mcp] Failed to load 1Password Environment: timeout"));

    const data = await call({ firewall: "panorama", dry_run: false });

    expect(data.added).toEqual(["HQ-FW1"]);
    expect(data.reload_error).toContain("Failed to load 1Password Environment");
    expect(data.next_steps).toContain("written to the config file");
    const config = JSON.parse(readFileSync(tmpConfig, "utf-8"));
    expect(config.firewalls).toHaveLength(2);
  });
});
