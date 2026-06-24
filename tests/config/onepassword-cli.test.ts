import { describe, it, expect, vi } from "vitest";
import { isCliInjectionMode, maybeRelaunchUnderOpCli } from "../../src/config/onepassword-cli.js";

const CLI_ENV = { OP_ENVIRONMENT_ID: "env-uuid" };

describe("isCliInjectionMode", () => {
  it("is true with an Environment ID, no token, and no sentinel", () => {
    expect(isCliInjectionMode({ OP_ENVIRONMENT_ID: "env-uuid" })).toBe(true);
  });

  it("is false when a service account token is present (SDK mode)", () => {
    expect(
      isCliInjectionMode({ OP_ENVIRONMENT_ID: "env-uuid", OP_SERVICE_ACCOUNT_TOKEN: "ops_t" })
    ).toBe(false);
  });

  it("is false when already wrapped (sentinel set)", () => {
    expect(isCliInjectionMode({ OP_ENVIRONMENT_ID: "env-uuid", PANOS_OP_WRAPPED: "1" })).toBe(false);
  });

  it("is false with no Environment ID", () => {
    expect(isCliInjectionMode({})).toBe(false);
  });
});

describe("maybeRelaunchUnderOpCli", () => {
  it("does not relaunch outside CLI mode", async () => {
    const spawnImpl = vi.fn();
    const result = await maybeRelaunchUnderOpCli({
      env: { OP_ENVIRONMENT_ID: "env-uuid", OP_SERVICE_ACCOUNT_TOKEN: "ops_t" },
      spawnImpl: spawnImpl as any,
      lookupOpImpl: () => "/usr/bin/op",
    });

    expect(result).toEqual({ relaunched: false });
    expect(spawnImpl).not.toHaveBeenCalled();
  });

  it("does not relaunch when already wrapped", async () => {
    const spawnImpl = vi.fn();
    const result = await maybeRelaunchUnderOpCli({
      env: { OP_ENVIRONMENT_ID: "env-uuid", PANOS_OP_WRAPPED: "1" },
      spawnImpl: spawnImpl as any,
      lookupOpImpl: () => "/usr/bin/op",
    });

    expect(result).toEqual({ relaunched: false });
    expect(spawnImpl).not.toHaveBeenCalled();
  });

  it("re-execs under `op run --environment` with the sentinel set", async () => {
    const spawnImpl = vi.fn().mockResolvedValue(0);

    const result = await maybeRelaunchUnderOpCli({
      env: CLI_ENV,
      lookupOpImpl: () => "/usr/bin/op",
      spawnImpl: spawnImpl as any,
      execPath: "/usr/bin/node",
      entryScript: "/app/dist/index.js",
      argv: ["/usr/bin/node", "/app/dist/index.js", "--flag"],
    });

    expect(result).toEqual({ relaunched: true, exitCode: 0 });
    const [opPath, args, childEnv] = spawnImpl.mock.calls[0];
    expect(opPath).toBe("/usr/bin/op");
    expect(args).toEqual([
      "run",
      "--environment",
      "env-uuid",
      "--",
      "/usr/bin/node",
      "/app/dist/index.js",
      "--flag",
    ]);
    expect(childEnv.PANOS_OP_WRAPPED).toBe("1");
  });

  it("propagates the wrapped child's exit code", async () => {
    const spawnImpl = vi.fn().mockResolvedValue(3);
    const result = await maybeRelaunchUnderOpCli({
      env: CLI_ENV,
      lookupOpImpl: () => "/usr/bin/op",
      spawnImpl: spawnImpl as any,
      execPath: "/usr/bin/node",
      entryScript: "/app/dist/index.js",
      argv: ["/usr/bin/node", "/app/dist/index.js"],
    });

    expect(result).toEqual({ relaunched: true, exitCode: 3 });
  });

  it("throws a clear error when `op` is not found", async () => {
    const spawnImpl = vi.fn();
    await expect(
      maybeRelaunchUnderOpCli({
        env: CLI_ENV,
        lookupOpImpl: () => null,
        spawnImpl: spawnImpl as any,
      })
    ).rejects.toThrow(/op` CLI was not found/);
    expect(spawnImpl).not.toHaveBeenCalled();
  });
});
