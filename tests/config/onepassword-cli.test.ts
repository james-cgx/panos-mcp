import { describe, it, expect, vi } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  loadOpEnvironmentIdFromRefsFile,
  isCliInjectionMode,
  maybeRelaunchUnderOpCli,
  getOpCliInjectedNames,
} from "../../src/config/onepassword-cli.js";

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

describe("loadOpEnvironmentIdFromRefsFile", () => {
  function withTempDir(fn: (dir: string) => void) {
    const dir = mkdtempSync(join(tmpdir(), "panos-mcp-op-"));
    try {
      fn(dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it("loads OP_ENVIRONMENT_ID from .op/refs.env when it is not already set", () => {
    withTempDir((dir) => {
      mkdirSync(join(dir, ".op"));
      writeFileSync(
        join(dir, ".op", "refs.env"),
        "# local 1Password environment\nOP_ENVIRONMENT_ID=\"env-from-file\"\n"
      );
      const env: Record<string, string | undefined> = {};

      const result = loadOpEnvironmentIdFromRefsFile({ env, cwd: dir });

      expect(result).toEqual({ loaded: true, path: join(dir, ".op", "refs.env") });
      expect(env.OP_ENVIRONMENT_ID).toBe("env-from-file");
    });
  });

  it("does not override OP_ENVIRONMENT_ID that was already provided", () => {
    withTempDir((dir) => {
      mkdirSync(join(dir, ".op"));
      writeFileSync(join(dir, ".op", "refs.env"), "OP_ENVIRONMENT_ID=env-from-file\n");
      const env: Record<string, string | undefined> = { OP_ENVIRONMENT_ID: "env-from-env" };

      const result = loadOpEnvironmentIdFromRefsFile({ env, cwd: dir });

      expect(result).toEqual({ loaded: false });
      expect(env.OP_ENVIRONMENT_ID).toBe("env-from-env");
    });
  });

  it("finds repo-local .op/refs.env when launched via dist/index.js from another cwd", () => {
    withTempDir((repoDir) => {
      withTempDir((otherDir) => {
        mkdirSync(join(repoDir, ".op"));
        writeFileSync(join(repoDir, ".op", "refs.env"), "export OP_ENVIRONMENT_ID=env-from-repo\n");
        const env: Record<string, string | undefined> = {};

        const result = loadOpEnvironmentIdFromRefsFile({
          env,
          cwd: otherDir,
          entryScript: join(repoDir, "dist", "index.js"),
        });

        expect(result).toEqual({ loaded: true, path: join(repoDir, ".op", "refs.env") });
        expect(env.OP_ENVIRONMENT_ID).toBe("env-from-repo");
      });
    });
  });

  it("is a no-op when no refs file exists", () => {
    withTempDir((dir) => {
      const env: Record<string, string | undefined> = {};

      const result = loadOpEnvironmentIdFromRefsFile({ env, cwd: dir });

      expect(result).toEqual({ loaded: false });
      expect(env.OP_ENVIRONMENT_ID).toBeUndefined();
    });
  });

  it("skips unreadable refs candidates and keeps looking", () => {
    withTempDir((cwdDir) => {
      withTempDir((repoDir) => {
        mkdirSync(join(cwdDir, ".op", "refs.env"), { recursive: true });
        mkdirSync(join(repoDir, ".op"));
        writeFileSync(join(repoDir, ".op", "refs.env"), "OP_ENVIRONMENT_ID=env-from-repo\n");
        const env: Record<string, string | undefined> = {};

        const result = loadOpEnvironmentIdFromRefsFile({
          env,
          cwd: cwdDir,
          entryScript: join(repoDir, "dist", "index.js"),
        });

        expect(result).toEqual({ loaded: true, path: join(repoDir, ".op", "refs.env") });
        expect(env.OP_ENVIRONMENT_ID).toBe("env-from-repo");
      });
    });
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

  it("passes the parent's env var names as a baseline to the wrapped child", async () => {
    const spawnImpl = vi.fn().mockResolvedValue(0);

    await maybeRelaunchUnderOpCli({
      env: { OP_ENVIRONMENT_ID: "env-uuid", PATH: "/usr/bin", HOME: "/home/me" },
      lookupOpImpl: () => "/usr/bin/op",
      spawnImpl: spawnImpl as any,
      execPath: "/usr/bin/node",
      entryScript: "/app/dist/index.js",
      argv: ["/usr/bin/node", "/app/dist/index.js"],
    });

    const [, , childEnv] = spawnImpl.mock.calls[0];
    const baseline = childEnv.PANOS_PRE_OP_ENV_NAMES.split("\n");
    expect(baseline).toEqual(
      expect.arrayContaining([
        "OP_ENVIRONMENT_ID",
        "PATH",
        "HOME",
        "PANOS_OP_WRAPPED",
        "PANOS_PRE_OP_ENV_NAMES",
      ])
    );
    // Names only — the baseline must not carry values.
    expect(childEnv.PANOS_PRE_OP_ENV_NAMES).not.toContain("/usr/bin");
  });
});

describe("getOpCliInjectedNames", () => {
  const wrappedEnv = {
    PANOS_OP_WRAPPED: "1",
    PANOS_PRE_OP_ENV_NAMES:
      "PATH\nOP_ENVIRONMENT_ID\nPANOS_OP_WRAPPED\nPANOS_PRE_OP_ENV_NAMES",
    PATH: "/usr/bin",
    OP_ENVIRONMENT_ID: "env-uuid",
  };

  it("recovers exactly the variables injected after the baseline, sorted", () => {
    expect(
      getOpCliInjectedNames({ ...wrappedEnv, HQ_FW1: "injected-1", BR_FW2: "injected-2" })
    ).toEqual(["BR_FW2", "HQ_FW1"]);
  });

  it("returns an empty list when op run injected nothing new", () => {
    expect(getOpCliInjectedNames(wrappedEnv)).toEqual([]);
  });

  it("returns null outside the op run wrapper", () => {
    expect(getOpCliInjectedNames({ PATH: "/usr/bin", HQ_FW1: "key" })).toBeNull();
  });

  it("returns null when wrapped without a baseline (older parent)", () => {
    expect(getOpCliInjectedNames({ PANOS_OP_WRAPPED: "1", HQ_FW1: "key" })).toBeNull();
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
