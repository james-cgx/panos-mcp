import { afterEach, describe, expect, it } from "vitest";
import { resolveTarget } from "../../src/api/client.js";

const original = {
  environmentId: process.env.OP_ENVIRONMENT_ID,
  token: process.env.OP_SERVICE_ACCOUNT_TOKEN,
  cliPath: process.env.OP_CLI_PATH,
  wrapped: process.env.PANOS_OP_WRAPPED,
  baseline: process.env.PANOS_PRE_OP_ENV_NAMES,
  host: process.env.PANOS_HOST,
  apiKey: process.env.PANOS_API_KEY,
  configPath: process.env.PANOS_FIREWALLS_CONFIG,
};

afterEach(() => {
  const restore = (name: string, value: string | undefined) => {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  };
  restore("OP_ENVIRONMENT_ID", original.environmentId);
  restore("OP_SERVICE_ACCOUNT_TOKEN", original.token);
  restore("OP_CLI_PATH", original.cliPath);
  restore("PANOS_OP_WRAPPED", original.wrapped);
  restore("PANOS_PRE_OP_ENV_NAMES", original.baseline);
  restore("PANOS_HOST", original.host);
  restore("PANOS_API_KEY", original.apiKey);
  restore("PANOS_FIREWALLS_CONFIG", original.configPath);
});

describe("credential-aware target resolution", () => {
  it("returns a normal friendly result while 1Password is unavailable", async () => {
    process.env.OP_ENVIRONMENT_ID = "unavailable-environment-id";
    delete process.env.OP_SERVICE_ACCOUNT_TOKEN;
    process.env.OP_CLI_PATH = "Z:\\missing\\op.exe";
    delete process.env.PANOS_OP_WRAPPED;
    delete process.env.PANOS_PRE_OP_ENV_NAMES;
    delete process.env.PANOS_HOST;
    delete process.env.PANOS_API_KEY;
    process.env.PANOS_FIREWALLS_CONFIG = "client-credentials.test.missing.json";

    const result = await resolveTarget("HQ-FW1");

    expect(result.success).toBe(false);
    if ("error" in result) {
      expect(result.error).toContain("Credentials unavailable: 1Password is locked or unreachable");
      expect(result.error).toContain("run the reload_credentials tool");
    }
  });
});
