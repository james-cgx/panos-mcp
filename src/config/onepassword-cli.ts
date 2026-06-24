import { spawn } from "child_process";
import { delimiter, join } from "path";
import { accessSync, constants } from "fs";

type EnvLike = Record<string, string | undefined>;

const WRAP_SENTINEL = "PANOS_OP_WRAPPED";

export interface MaybeRelaunchOptions {
  env?: EnvLike;
  /** Resolve the `op` binary path, or null if not found. Injected for tests. */
  lookupOpImpl?: (env: EnvLike) => string | null;
  /** Spawn the wrapper child and resolve with its exit code. Injected for tests. */
  spawnImpl?: (opPath: string, args: string[], childEnv: EnvLike) => Promise<number>;
  execPath?: string;
  entryScript?: string;
  argv?: string[];
}

export interface RelaunchResult {
  relaunched: boolean;
  exitCode?: number;
}

/**
 * Local CLI injection mode: an Environment ID is configured, but no service
 * account token, and we are not already running inside the `op run` wrapper.
 */
export function isCliInjectionMode(env: EnvLike): boolean {
  const environmentId = (env.OP_ENVIRONMENT_ID ?? "").trim();
  const token = (env.OP_SERVICE_ACCOUNT_TOKEN ?? "").trim();
  const wrapped = (env[WRAP_SENTINEL] ?? "").trim();
  return Boolean(environmentId) && !token && !wrapped;
}

function defaultLookupOp(env: EnvLike): string | null {
  const override = (env.OP_CLI_PATH ?? "").trim();
  if (override) {
    try {
      accessSync(override, constants.X_OK);
      return override;
    } catch {
      return null;
    }
  }

  // 1Password ships op.exe on Windows. Avoid .cmd/.bat: Node throws EINVAL when
  // spawning them without shell:true (CVE-2024-27980 hardening).
  const exeNames = process.platform === "win32" ? ["op.exe", "op"] : ["op"];
  const pathDirs = (env.PATH ?? env.Path ?? "").split(delimiter).filter(Boolean);
  for (const dir of pathDirs) {
    for (const exe of exeNames) {
      const candidate = join(dir, exe);
      try {
        accessSync(candidate, constants.X_OK);
        return candidate;
      } catch {
        // keep looking
      }
    }
  }
  return null;
}

function defaultSpawn(opPath: string, args: string[], childEnv: EnvLike): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(opPath, args, { stdio: "inherit", env: childEnv as NodeJS.ProcessEnv });
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (signal) {
        reject(new Error(`op run terminated by signal ${signal}`));
      } else {
        resolve(code ?? 0);
      }
    });
  });
}

/**
 * In local CLI injection mode, re-exec this server under
 * `op run --environment <id> -- <node> <entryScript> <args>` so the 1Password
 * CLI provisions the Environment's variables into the child's environment using
 * the local `op` session. Returns { relaunched: true, exitCode } once the
 * wrapped child exits; the caller should then exit with that code.
 */
export async function maybeRelaunchUnderOpCli(
  options: MaybeRelaunchOptions = {}
): Promise<RelaunchResult> {
  const env = options.env ?? (process.env as EnvLike);
  if (!isCliInjectionMode(env)) return { relaunched: false };

  const lookupOp = options.lookupOpImpl ?? defaultLookupOp;
  const opPath = lookupOp(env);
  if (!opPath) {
    throw new Error(
      "[panos-mcp] OP_ENVIRONMENT_ID is set without OP_SERVICE_ACCOUNT_TOKEN (local 1Password CLI mode), " +
        "but the `op` CLI was not found. Install the 1Password CLI (beta ≥ 2.33.0-beta.02 for " +
        "`op run --environment`), sign in, and ensure `op` is on PATH or set OP_CLI_PATH."
    );
  }

  const environmentId = (env.OP_ENVIRONMENT_ID ?? "").trim();
  const execPath = options.execPath ?? process.execPath;
  const entryScript = options.entryScript ?? (options.argv ?? process.argv)[1];
  const passthroughArgs = (options.argv ?? process.argv).slice(2);

  const args = [
    "run",
    "--environment",
    environmentId,
    "--",
    execPath,
    ...(entryScript ? [entryScript] : []),
    ...passthroughArgs,
  ];

  const spawnChild = options.spawnImpl ?? defaultSpawn;
  const exitCode = await spawnChild(opPath, args, { ...env, [WRAP_SENTINEL]: "1" });
  return { relaunched: true, exitCode };
}
