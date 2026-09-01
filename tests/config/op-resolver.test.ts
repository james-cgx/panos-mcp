import { EventEmitter } from "events";
import { describe, expect, it, vi, afterEach } from "vitest";
import { resolveOpCliEnvironment } from "../../src/config/op-resolver.js";

class FakeChild extends EventEmitter {
  stdout = new EventEmitter();
  stderr = new EventEmitter();
  kill = vi.fn(() => true);
}

afterEach(() => {
  vi.useRealTimers();
});

describe("resolveOpCliEnvironment", () => {
  it("captures only newly injected variables and requires unmasked output", async () => {
    const child = new FakeChild();
    const spawnImpl = vi.fn(() => child as any);
    const resolution = resolveOpCliEnvironment({
      env: { OP_ENVIRONMENT_ID: "environment-id", PATH: "/usr/bin", EXISTING: "parent" },
      lookupOpImpl: () => "/usr/bin/op",
      spawnImpl,
      execPath: "/usr/bin/node",
    });

    child.stdout.emit(
      "data",
      JSON.stringify({
        OP_ENVIRONMENT_ID: "environment-id",
        PATH: "/usr/bin",
        EXISTING: "changed-by-op",
        HQ_FW1: "example-secret",
        OP_SESSION_example: "internal-value",
      })
    );
    child.emit("close", 0, null);

    const result = await resolution;
    expect(result).toEqual({ ok: true, environment: new Map([["HQ_FW1", "example-secret"]]) });
    expect(spawnImpl.mock.calls[0][1]).toEqual([
      "run",
      "--environment",
      "environment-id",
      "--no-masking",
      "--",
      "/usr/bin/node",
      "-e",
      expect.stringContaining("JSON.stringify(process.env)"),
    ]);
    expect(spawnImpl.mock.calls[0][2].stdio).toEqual(["ignore", "pipe", "pipe"]);
  });

  it("returns truncated stderr on non-zero exit without exposing dumped values", async () => {
    const child = new FakeChild();
    const resolution = resolveOpCliEnvironment({
      env: { OP_ENVIRONMENT_ID: "environment-id" },
      lookupOpImpl: () => "/usr/bin/op",
      spawnImpl: () => child as any,
    });
    child.stdout.emit("data", JSON.stringify({ HQ_FW1: "example-secret-value" }));
    child.stderr.emit("data", `not signed in ${"x".repeat(700)}`);
    child.emit("close", 1, null);

    const result = await resolution;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("not signed in");
      expect(result.reason.length).toBeLessThan(570);
      expect(result.reason).not.toContain("example-secret-value");
    }
  });

  it("kills a resolver that exceeds the timeout", async () => {
    vi.useFakeTimers();
    const child = new FakeChild();
    const resolution = resolveOpCliEnvironment({
      env: { OP_ENVIRONMENT_ID: "environment-id" },
      lookupOpImpl: () => "/usr/bin/op",
      spawnImpl: () => child as any,
      timeoutMs: 100,
    });

    await vi.advanceTimersByTimeAsync(100);
    await expect(resolution).resolves.toEqual({
      ok: false,
      reason: "1Password CLI timed out after 100ms",
    });
    expect(child.kill).toHaveBeenCalledWith("SIGKILL");
  });

  it("rejects garbage stdout without echoing it", async () => {
    const child = new FakeChild();
    const resolution = resolveOpCliEnvironment({
      env: { OP_ENVIRONMENT_ID: "environment-id" },
      lookupOpImpl: () => "/usr/bin/op",
      spawnImpl: () => child as any,
    });
    child.stdout.emit("data", "garbage example-secret-value");
    child.emit("close", 0, null);

    const result = await resolution;
    expect(result).toEqual({ ok: false, reason: "1Password CLI returned an unreadable environment" });
    if (!result.ok) expect(result.reason).not.toContain("example-secret-value");
  });
});
