import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  fetch: vi.fn(),
  markCredentialsSuspect: vi.fn(),
}));

vi.mock("undici", async (importOriginal) => ({
  ...(await importOriginal<typeof import("undici")>()),
  fetch: mocks.fetch,
}));

vi.mock("../../src/config/credential-manager.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/config/credential-manager.js")>()),
  markCredentialsSuspect: mocks.markCredentialsSuspect,
}));

import { executeOpCommand, resolveTarget } from "../../src/api/client.js";

const target = {
  host: "firewall.example.com",
  apiKey: "example-api-key",
  verifySSL: false,
};

function response(options: {
  status: number;
  statusText: string;
  body?: string;
}) {
  return new Response(options.body ?? "", {
    status: options.status,
    statusText: options.statusText,
  });
}

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
  vi.clearAllMocks();
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

describe("credential failure detection", () => {
  it("does not refresh credentials for an XML insufficient-rights error", async () => {
    mocks.fetch.mockResolvedValue(
      response({
        status: 200,
        statusText: "OK",
        body: '<response status="error" code="403"><msg><line>Insufficient administrator rights</line></msg></response>',
      })
    );

    const result = await executeOpCommand("<show></show>", target);

    expect(result.success).toBe(false);
    expect(mocks.markCredentialsSuspect).not.toHaveBeenCalled();
  });

  it("refreshes credentials for an explicit XML invalid-credential error", async () => {
    mocks.fetch.mockResolvedValue(
      response({
        status: 200,
        statusText: "OK",
        body: '<response status="error" code="403"><msg><line>Invalid credential</line></msg></response>',
      })
    );

    const result = await executeOpCommand("<show></show>", target);

    expect(result.success).toBe(false);
    expect(mocks.markCredentialsSuspect).toHaveBeenCalledOnce();
  });

  it("refreshes credentials for HTTP 401", async () => {
    mocks.fetch.mockResolvedValue(
      response({ status: 401, statusText: "Unauthorized" })
    );

    const result = await executeOpCommand("<show></show>", target);

    expect(result).toEqual({ success: false, error: "HTTP 401 Unauthorized" });
    expect(mocks.markCredentialsSuspect).toHaveBeenCalledOnce();
  });

  it("does not refresh credentials for HTTP 403 without an invalid-credential body", async () => {
    mocks.fetch.mockResolvedValue(
      response({
        status: 403,
        statusText: "Forbidden",
        body: "Insufficient administrator rights",
      })
    );

    const result = await executeOpCommand("<show></show>", target);

    expect(result).toEqual({ success: false, error: "HTTP 403 Forbidden" });
    expect(mocks.markCredentialsSuspect).not.toHaveBeenCalled();
  });
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
