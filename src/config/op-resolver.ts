import { spawn } from "child_process";
import type { Readable } from "stream";
import { defaultLookupOp, type EnvLike } from "./onepassword-cli.js";

const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_STDERR_LENGTH = 500;
const MAX_CAPTURE_BYTES = 10 * 1024 * 1024;

const ONEPASSWORD_INTERNAL_NAMES = new Set([
  "OP_ENVIRONMENT_ID",
  "OP_SERVICE_ACCOUNT_TOKEN",
  "OP_CLI_PATH",
  "OP_BIOMETRIC_UNLOCK_ENABLED",
  "PANOS_OP_WRAPPED",
  "PANOS_PRE_OP_ENV_NAMES",
]);

export function isOnePasswordInternalName(name: string): boolean {
  return ONEPASSWORD_INTERNAL_NAMES.has(name) || name.startsWith("OP_SESSION_");
}

interface SpawnedProcess {
  stdout: Pick<Readable, "on"> | null;
  stderr: Pick<Readable, "on"> | null;
  on(event: "error", listener: (error: Error) => void): this;
  on(event: "close", listener: (code: number | null, signal: NodeJS.Signals | null) => void): this;
  kill(signal?: NodeJS.Signals): boolean;
}

export type OpResolverSpawn = (
  command: string,
  args: string[],
  options: { stdio: ["ignore", "pipe", "pipe"]; env: NodeJS.ProcessEnv }
) => SpawnedProcess;

export interface ResolveOpCliEnvironmentOptions {
  env?: EnvLike;
  environmentId?: string;
  timeoutMs?: number;
  lookupOpImpl?: (env: EnvLike) => string | null;
  spawnImpl?: OpResolverSpawn;
  execPath?: string;
}

export type ResolveOpCliEnvironmentResult =
  | { ok: true; environment: Map<string, string> }
  | { ok: false; reason: string };

const DUMP_SCRIPT = "process.stdout.write(JSON.stringify(process.env))";

function appendCapture(current: string, chunk: unknown): string {
  if (Buffer.byteLength(current) >= MAX_CAPTURE_BYTES) return current;
  const next = Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
  return (current + next).slice(0, MAX_CAPTURE_BYTES);
}

function redactKnownValues(text: string, env: EnvLike, extraValues: Iterable<string> = []): string {
  let safe = text;
  const values = new Set([
    ...Object.values(env).filter((value): value is string => Boolean(value && value.length >= 4)),
    ...[...extraValues].filter((value) => value.length >= 4),
  ]);
  for (const value of values) safe = safe.split(value).join("[REDACTED]");
  return safe.replace(/\s+/g, " ").trim().slice(0, MAX_STDERR_LENGTH);
}

function failureReason(
  summary: string,
  stderr: string,
  env: EnvLike,
  extraValues: Iterable<string> = []
): string {
  const safeStderr = redactKnownValues(stderr, env, extraValues);
  return safeStderr ? `${summary}: ${safeStderr}` : summary;
}

export async function resolveOpCliEnvironment(
  options: ResolveOpCliEnvironmentOptions = {}
): Promise<ResolveOpCliEnvironmentResult> {
  const env = options.env ?? (process.env as EnvLike);
  const environmentId = (options.environmentId ?? env.OP_ENVIRONMENT_ID ?? "").trim();
  if (!environmentId) return { ok: false, reason: "OP_ENVIRONMENT_ID is not configured" };

  const opPath = (options.lookupOpImpl ?? defaultLookupOp)(env);
  if (!opPath) {
    return {
      ok: false,
      reason: "the `op` CLI was not found; install it or set OP_CLI_PATH",
    };
  }

  const args = [
    "run",
    "--environment",
    environmentId,
    "--no-masking",
    "--",
    options.execPath ?? process.execPath,
    "-e",
    DUMP_SCRIPT,
  ];
  const spawnImpl = options.spawnImpl ?? (spawn as unknown as OpResolverSpawn);
  const baseline = new Set(Object.keys(env));

  return await new Promise<ResolveOpCliEnvironmentResult>((resolve) => {
    let child: SpawnedProcess;
    try {
      child = spawnImpl(opPath, args, {
        stdio: ["ignore", "pipe", "pipe"],
        env: env as NodeJS.ProcessEnv,
      });
    } catch (error) {
      return resolve({
        ok: false,
        reason: failureReason(
          `failed to start the 1Password CLI (${error instanceof Error ? error.message : String(error)})`,
          "",
          env
        ),
      });
    }

    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (result: ResolveOpCliEnvironmentResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.stdout?.on("data", (chunk) => {
      stdout = appendCapture(stdout, chunk);
    });
    child.stderr?.on("data", (chunk) => {
      stderr = appendCapture(stderr, chunk);
    });
    child.on("error", (error) => {
      finish({
        ok: false,
        reason: failureReason(`failed to start the 1Password CLI (${error.message})`, stderr, env),
      });
    });
    child.on("close", (code, signal) => {
      let dumped: Record<string, unknown> | null = null;
      try {
        const candidate = JSON.parse(stdout);
        if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) dumped = candidate;
      } catch {
        // A failure reason never includes child stdout because it may contain secrets.
      }
      const dumpedValues = dumped
        ? Object.values(dumped).filter((value): value is string => typeof value === "string")
        : [];

      if (signal || code !== 0) {
        const summary = signal
          ? `1Password CLI terminated by signal ${signal}`
          : `1Password CLI exited with code ${code ?? "unknown"}`;
        return finish({ ok: false, reason: failureReason(summary, stderr, env, dumpedValues) });
      }
      if (!dumped) {
        return finish({
          ok: false,
          reason: failureReason("1Password CLI returned an unreadable environment", stderr, env),
        });
      }

      const environment = new Map<string, string>();
      for (const [name, value] of Object.entries(dumped)) {
        if (
          typeof value === "string" &&
          !baseline.has(name) &&
          !isOnePasswordInternalName(name)
        ) {
          environment.set(name, value);
        }
      }
      finish({ ok: true, environment });
    });

    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        // The process may already have exited.
      }
      finish({
        ok: false,
        reason: failureReason(
          `1Password CLI timed out after ${options.timeoutMs ?? DEFAULT_TIMEOUT_MS}ms`,
          stderr,
          env
        ),
      });
    }, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  });
}
