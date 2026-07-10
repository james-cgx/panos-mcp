import { describe, it, expect, beforeEach, vi } from "vitest";
import { writeFileSync, unlinkSync } from "fs";
import { resolve } from "path";

vi.mock("../../src/config/keychain.js", () => ({
  getKey: vi.fn(),
  setKey: vi.fn(),
  deleteKey: vi.fn(),
  isKeychainAvailable: vi.fn(),
  initKeychain: vi.fn().mockResolvedValue(undefined),
}));

import { getKey, isKeychainAvailable } from "../../src/config/keychain.js";
import {
  loadFirewallConfig,
  recordInjectedEnvironmentNames,
  setInjectedEnvironment,
} from "../../src/config/firewalls.js";
import { registerFirewallTools } from "../../src/tools/firewalls.js";

const tmpConfig = resolve("firewalls.tools.test.tmp.json");

function cleanup() {
  try { unlinkSync(tmpConfig); } catch {}
}

type ToolHandler = () => Promise<{ content: Array<{ type: "text"; text: string }> }>;

function getListFirewallsHandler(): ToolHandler {
  let handler: ToolHandler | undefined;
  const fakeServer = {
    tool: (...args: unknown[]) => {
      handler = args[args.length - 1] as ToolHandler;
    },
  };
  registerFirewallTools(fakeServer as any);
  if (!handler) throw new Error("list_firewalls was not registered");
  return handler;
}

async function callListFirewalls() {
  const result = await getListFirewallsHandler()();
  return { raw: result.content[0].text, data: JSON.parse(result.content[0].text) };
}

describe("list_firewalls tool", () => {
  let keychainStore: Map<string, string>;

  beforeEach(() => {
    cleanup();
    vi.clearAllMocks();
    keychainStore = new Map();
    vi.mocked(isKeychainAvailable).mockReturnValue(true);
    vi.mocked(getKey).mockImplementation(async (name) => keychainStore.get(name) ?? null);
    process.env.PANOS_FIREWALLS_CONFIG = tmpConfig;
    delete process.env.PANOS_HOST;
    delete process.env.PANOS_API_KEY;
    delete process.env.PANOS_VERIFY_SSL;
    setInjectedEnvironment(new Map());
  });

  it("reports an actionable unconfigured state when no target resolves", async () => {
    await loadFirewallConfig();
    setInjectedEnvironment(new Map([["PANORAMA_KEY", "secret-panorama-key"]]));
    recordInjectedEnvironmentNames(["HQ_FW1"]);

    const { raw, data } = await callListFirewalls();

    expect(data.mode).toBe("unconfigured");
    expect(data.firewall_param_required).toBe(false);
    expect(data.firewalls).toEqual([]);
    expect(data.config_path).toBe(tmpConfig);
    expect(data.config_file_exists).toBe(false);
    expect(data.injected_unreferenced_env_var_names).toEqual(["HQ_FW1", "PANORAMA_KEY"]);
    expect(data.config_example).toEqual({
      firewalls: [{ name: "HQ-FW1", host: "hq-fw1.example.com", api_key_env: "HQ_FW1" }],
    });
    expect(data.next_steps).toContain("bootstrap_firewalls_from_panorama");
    expect(raw).not.toContain("secret-panorama-key");
  });

  it("reports environment mode when env vars provide a target", async () => {
    process.env.PANOS_HOST = "fw.example.com";
    process.env.PANOS_API_KEY = "env-secret-key";
    await loadFirewallConfig();

    const { raw, data } = await callListFirewalls();

    expect(data.mode).toBe("environment");
    expect(data.firewall_param_required).toBe(false);
    expect(data.firewalls).toEqual([{ name: "env", host: "fw.example.com" }]);
    expect(raw).not.toContain("env-secret-key");
  });

  it("reports single mode for one configured entry", async () => {
    keychainStore.set("fw1", "key1");
    writeFileSync(tmpConfig, JSON.stringify({ firewalls: [{ name: "fw1", host: "10.0.1.1" }] }));
    await loadFirewallConfig();

    const { data } = await callListFirewalls();

    expect(data.mode).toBe("single");
    expect(data.firewall_param_required).toBe(false);
    expect(data.firewalls).toEqual([{ name: "fw1", host: "10.0.1.1" }]);
  });

  it("reports multi mode and requires the firewall parameter", async () => {
    keychainStore.set("fw1", "key1");
    keychainStore.set("fw2", "key2");
    writeFileSync(
      tmpConfig,
      JSON.stringify({
        firewalls: [
          { name: "fw1", host: "10.0.1.1" },
          { name: "fw2", host: "10.0.2.2" },
        ],
      })
    );
    await loadFirewallConfig();

    const { data } = await callListFirewalls();

    expect(data.mode).toBe("multi");
    expect(data.firewall_param_required).toBe(true);
    expect(data.firewalls).toHaveLength(2);
  });
});
