import { spawn } from "child_process";
import { delimiter, dirname, join, resolve } from "path";
import { accessSync, constants, existsSync, readFileSync } from "fs";

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

export interface LoadOpEnvironmentIdOptions {
  env?: EnvLike;
  cwd?: string;
  entryScript?: string;
}

export type LoadOpEnvironmentIdResult =
  | { loaded: true; path: string }
  | { loaded: false };

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

function candidateRefsEnvPaths(cwd: string, entryScript?: string): string[] {
  const roots = [resolve(cwd)];

  if (entryScript) {
    const scriptPath = resolve(cwd, entryScript);
    const scriptDir = dirname(scriptPath);
    roots.push(scriptDir, dirname(scriptDir));
  }

  return Array.from(new Set(roots)).map((root) => join(root, ".op", "refs.env"));
}

function unquoteEnvValue(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2) {
    const quote = trimmed[0];
    if ((quote === `"` || quote === `'`) && trimmed[trimmed.length - 1] === quote) {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed.replace(/\s+#.*$/, "").trim();
}

function parseOpEnvironmentId(content: string): string | null {
  for (const rawLine of content.replace(/^\uFEFF/, "").split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const line = trimmed.startsWith("export ") ? trimmed.slice("export ".length).trimStart() : trimmed;
    const equals = line.indexOf("=");
    if (equals <= 0) continue;

    const name = line.slice(0, equals).trim();
    if (name !== "OP_ENVIRONMENT_ID") continue;

    const value = unquoteEnvValue(line.slice(equals + 1));
    if (value && !value.startsWith("${")) return value;
  }

  return null;
}

export function loadOpEnvironmentIdFromRefsFile(
  options: LoadOpEnvironmentIdOptions = {}
): LoadOpEnvironmentIdResult {
  const env = options.env ?? (process.env as EnvLike);
  if ((env.OP_ENVIRONMENT_ID ?? "").trim()) return { loaded: false };

  const cwd = options.cwd ?? process.cwd();
  const entryScript = options.entryScript ?? process.argv[1];

  for (const path of candidateRefsEnvPaths(cwd, entryScript)) {
    if (!existsSync(path)) continue;

    const environmentId = parseOpEnvironmentId(readFileSync(path, "utf-8"));
    if (!environmentId) continue;

    env.OP_ENVIRONMENT_ID = environmentId;
    return { loaded: true, path };
  }

  return { loaded: false };
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
