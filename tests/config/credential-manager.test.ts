import { afterEach, describe, expect, it, vi } from "vitest";
import { CredentialManager } from "../../src/config/credential-manager.js";

afterEach(() => {
  vi.useRealTimers();
});

describe("CredentialManager", () => {
  it("recovers through the locked-to-unlocked retry backoff", async () => {
    vi.useFakeTimers();
    const resolveCli = vi
      .fn()
      .mockResolvedValueOnce({ ok: false, reason: "not signed in" })
      .mockResolvedValueOnce({ ok: false, reason: "authorization prompt dismissed" })
      .mockResolvedValueOnce({ ok: true, environment: new Map([["PANOS_API_KEY", "example-key"]]) });
    const manager = new CredentialManager({
      env: { OP_ENVIRONMENT_ID: "environment-id" },
      resolveCli,
      loadConfig: vi.fn().mockResolvedValue(undefined),
      log: vi.fn(),
    });

    manager.startRetryLoop();
    await vi.advanceTimersByTimeAsync(0);
    expect(resolveCli).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(resolveCli).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(10_000);

    expect(resolveCli).toHaveBeenCalledTimes(3);
    expect(manager.getStatus().resolved).toBe(true);
    expect(manager.getStatus().lastError).toBeNull();
  });

  it("deduplicates concurrent credential requests", async () => {
    let complete!: (value: any) => void;
    const resolveCli = vi.fn(
      () => new Promise((resolve) => {
        complete = resolve;
      })
    );
    const manager = new CredentialManager({
      env: { OP_ENVIRONMENT_ID: "environment-id" },
      resolveCli,
      loadConfig: vi.fn().mockResolvedValue(undefined),
      log: vi.fn(),
    });

    const first = manager.ensureCredentials();
    const second = manager.ensureCredentials();
    expect(resolveCli).toHaveBeenCalledTimes(1);
    complete({ ok: true, environment: new Map() });

    await expect(Promise.all([first, second])).resolves.toEqual([true, true]);
    expect(resolveCli).toHaveBeenCalledTimes(1);
  });

  it("debounces credential-suspect refreshes", async () => {
    vi.useFakeTimers();
    const resolveCli = vi.fn().mockResolvedValue({ ok: true, environment: new Map() });
    const manager = new CredentialManager({
      env: { OP_ENVIRONMENT_ID: "environment-id" },
      resolveCli,
      loadConfig: vi.fn().mockResolvedValue(undefined),
      log: vi.fn(),
    });
    await manager.ensureCredentials();

    manager.markCredentialsSuspect();
    manager.markCredentialsSuspect();
    manager.markCredentialsSuspect();
    await vi.advanceTimersByTimeAsync(0);

    expect(resolveCli).toHaveBeenCalledTimes(2);
  });
});
