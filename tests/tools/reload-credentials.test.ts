import { afterAll, describe, expect, it } from "vitest";
import { unlinkSync, writeFileSync } from "fs";
import { resolve } from "path";
import { registerFirewallTools } from "../../src/tools/firewalls.js";

const configPath = resolve("reload-credentials.test.tmp.json");
const originalEnv = { ...process.env };

afterAll(() => {
  try { unlinkSync(configPath); } catch {}
  for (const name of Object.keys(process.env)) {
    if (!(name in originalEnv)) delete process.env[name];
  }
  Object.assign(process.env, originalEnv);
});

describe("reload_credentials tool", () => {
  it("returns names and target metadata without values", async () => {
    writeFileSync(
      configPath,
      JSON.stringify({
        firewalls: [{ name: "HQ-FW1", host: "hq-fw1.example.com", api_key_env: "HQ_FW1" }],
      })
    );
    process.env.PANOS_FIREWALLS_CONFIG = configPath;
    process.env.OP_ENVIRONMENT_ID = "wrapped-environment-id";
    delete process.env.OP_SERVICE_ACCOUNT_TOKEN;
    process.env.PANOS_OP_WRAPPED = "1";
    delete process.env.HQ_FW1;
    process.env.PANOS_PRE_OP_ENV_NAMES = Object.keys(process.env).join("\n");
    process.env.HQ_FW1 = "example-secret-value";

    let handler: (() => Promise<any>) | undefined;
    const server = {
      tool: (...args: any[]) => {
        if (args[0] === "reload_credentials") handler = args.at(-1);
      },
    };
    registerFirewallTools(server as any);
    if (!handler) throw new Error("reload_credentials was not registered");

    const response = await handler();
    const raw = response.content[0].text;
    expect(JSON.parse(raw)).toEqual({
      mode: "cli",
      resolved: true,
      injected_variable_count: 1,
      injected_variable_names: ["HQ_FW1"],
      firewall_targets: ["HQ-FW1"],
      last_error: null,
    });
    expect(raw).not.toContain("example-secret-value");
  });
});
