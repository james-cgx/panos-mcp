import { z } from "zod";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { homedir } from "os";
import { getKey, setKey, isKeychainAvailable, initKeychain } from "./keychain.js";
import { diagnostic } from "../diagnostics.js";

export interface FirewallEntry {
  name: string;
  host: string;
  api_key: string;
  verify_ssl: boolean;
}

const firewallFileEntrySchema = z.object({
  name: z.string().min(1).max(63),
  host: z.string().min(1),
  api_key: z.string().optional(),
  api_key_env: z.string().min(1).optional(),
  verify_ssl: z.boolean().optional(),
});

const firewallConfigSchema = z.object({
  firewalls: z.array(firewallFileEntrySchema).min(1),
});

function sanitizeHost(host: string): string {
  return host.replace(/^https?:\/\//, "").replace(/\/+$/, "").trim();
}

let entries: Array<{ name: string; host: string; verify_ssl: boolean }> = [];
const keyMap = new Map<string, string>();
const injectedEnvironment = new Map<string, string>();

// Names (never values) of variables known to be injected by 1Password in
// either credential mode, and the api_key_env names referenced by the loaded
// config. The difference is surfaced to agents so injected-but-unreferenced
// keys are discoverable instead of silently invisible.
const injectedEnvironmentNames = new Set<string>();
const referencedEnvNames = new Set<string>();

const BUILTIN_ENV_NAMES = new Set(["PANOS_HOST", "PANOS_API_KEY", "PANOS_VERIFY_SSL"]);

// 1Password/wrapper-internal variables, never firewall API keys. An explicit
// denylist rather than an OP_ prefix match: a firewall hostnamed "OP-FW1"
// legitimately produces the candidate variable "OP_FW1".
const ONEPASSWORD_INTERNAL_NAMES = new Set([
  "OP_ENVIRONMENT_ID",
  "OP_SERVICE_ACCOUNT_TOKEN",
  "OP_CLI_PATH",
  "PANOS_OP_WRAPPED",
  "PANOS_PRE_OP_ENV_NAMES",
]);

// Windows environment variable names are case-insensitive, so referenced and
// injected names must be compared folded there; on POSIX case is significant.
function foldEnvName(name: string, platform: NodeJS.Platform): string {
  return platform === "win32" ? name.toUpperCase() : name;
}

// JSON.parse SyntaxError messages embed a snippet of the source text, which
// for firewalls.json can include plaintext api_key material — never let that
// reach tool output or logs.
function parseConfigJson(raw: string, configPath: string): any {
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(
      `Config file at ${configPath} is not valid JSON — fix or remove the file. ` +
        "(Parse details omitted to avoid echoing file contents.)"
    );
  }
}

const defaultConfigPath = join(homedir(), ".config", "panos-mcp", "firewalls.json");

export function getConfigPath(): string {
  return process.env.PANOS_FIREWALLS_CONFIG ?? defaultConfigPath;
}

export function getExpectedEnvironmentVariableNames(): Set<string> {
  const names = new Set(["PANOS_HOST", "PANOS_API_KEY", "PANOS_VERIFY_SSL"]);
  let raw: string;
  try {
    raw = readFileSync(getConfigPath(), "utf-8");
  } catch {
    return names;
  }

  const parsed = firewallConfigSchema.parse(parseConfigJson(raw, getConfigPath()));
  for (const entry of parsed.firewalls) {
    if (entry.api_key_env) names.add(entry.api_key_env);
  }

  return names;
}

export function setInjectedEnvironment(env: ReadonlyMap<string, string>): void {
  injectedEnvironment.clear();
  injectedEnvironmentNames.clear();
  for (const [name, value] of env) {
    injectedEnvironment.set(name, value);
    injectedEnvironmentNames.add(name);
  }
}

/**
 * Records additional variable NAMES known to be 1Password-injected (values are
 * never stored here): names dropped by the service-account allowlist filter,
 * or names recovered from the `op run` baseline diff in local CLI mode.
 */
export function recordInjectedEnvironmentNames(names: Iterable<string>): void {
  for (const name of names) {
    if (name) injectedEnvironmentNames.add(name);
  }
}

export function getInjectedEnvironmentNames(): string[] {
  return [...injectedEnvironmentNames].sort();
}

/**
 * Injected variable names that nothing currently uses: not the built-in
 * PANOS_* variables, not referenced by any api_key_env entry in the loaded
 * config, and not 1Password's own well-known variables. These are the
 * candidate API keys for bootstrap_firewalls_from_panorama.
 */
export function getUnreferencedInjectedNames(
  platform: NodeJS.Platform = process.platform
): string[] {
  const referenced = new Set([...referencedEnvNames].map((n) => foldEnvName(n, platform)));
  return [...injectedEnvironmentNames]
    .filter((name) => {
      const folded = foldEnvName(name, platform);
      return (
        !BUILTIN_ENV_NAMES.has(folded) &&
        !referenced.has(folded) &&
        !ONEPASSWORD_INTERNAL_NAMES.has(folded)
      );
    })
    .sort();
}

export interface UnconfiguredState {
  config_path: string;
  config_file_exists: boolean;
  injected_unreferenced_env_var_names: string[];
  config_example: { firewalls: Array<{ name: string; host: string; api_key_env: string }> };
  next_steps: string;
}

/** Structured description of the zero-target state, for stderr and list_firewalls. */
export function describeUnconfiguredState(): UnconfiguredState {
  const configPath = getConfigPath();
  const names = getUnreferencedInjectedNames();
  return {
    config_path: configPath,
    config_file_exists: existsSync(configPath),
    injected_unreferenced_env_var_names: names,
    config_example: {
      firewalls: [{ name: "HQ-FW1", host: "hq-fw1.example.com", api_key_env: "HQ_FW1" }],
    },
    next_steps:
      "No firewall targets are configured. Either set PANOS_HOST and PANOS_API_KEY, or create " +
      "firewalls.json entries whose api_key_env references injected environment variable names" +
      (names.length > 0 ? " (see injected_unreferenced_env_var_names)" : "") +
      "; config_example shows the exact file shape (a top-level \"firewalls\" array). " +
      "If one of those variables holds a Panorama API key, add a single Panorama entry first, " +
      "then run bootstrap_firewalls_from_panorama to discover and configure the managed firewalls.",
  };
}

function readConfiguredEnv(name: string): string {
  const injected = injectedEnvironment.get(name);
  if (injected !== undefined) return injected.trim();
  return (process.env[name] ?? "").trim();
}

function parseBooleanEnv(value: string): boolean | null {
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return null;
}

function fileEntryWithoutPlaintextKey(entry: {
  name: string;
  host: string;
  api_key_env?: string;
  verify_ssl: boolean;
}): { name: string; host: string; api_key_env?: string; verify_ssl?: boolean } {
  return {
    name: entry.name,
    host: entry.host,
    ...(entry.api_key_env ? { api_key_env: entry.api_key_env } : {}),
    ...(entry.verify_ssl ? { verify_ssl: entry.verify_ssl } : {}),
  };
}

export async function loadFirewallConfig(): Promise<void> {
  entries = [];
  keyMap.clear();
  referencedEnvNames.clear();

  await initKeychain();

  const configPath = getConfigPath();

  let raw: string;
  try {
    raw = readFileSync(configPath, "utf-8");
  } catch {
    return;
  }

  const parsed = firewallConfigSchema.parse(parseConfigJson(raw, configPath));
  const fileEntries = parsed.firewalls.map((e) => ({
    name: e.name,
    host: sanitizeHost(e.host),
    api_key: e.api_key,
    api_key_env: e.api_key_env,
    verify_ssl: e.verify_ssl ?? false,
  }));

  // Auto-migrate plaintext api_key fields to OS keychain
  if (isKeychainAvailable()) {
    const toMigrate = fileEntries.filter((e) => e.api_key);
    if (toMigrate.length > 0) {
      try {
        for (const e of toMigrate) {
          await setKey(e.name, e.api_key!);
        }
        const cleaned = { firewalls: fileEntries.map(fileEntryWithoutPlaintextKey) };
        writeFileSync(configPath, JSON.stringify(cleaned, null, 2) + "\n");
        diagnostic(`Migrated ${toMigrate.length} API key(s) to system keychain`);
      } catch (err) {
        diagnostic(`ERROR: Migration failed — ${String(err)}. Keys remain in plaintext.`);
      }
    }
  }

  entries = fileEntries.map(({ name, host, verify_ssl }) => ({ name, host, verify_ssl }));

  // Load keys into memory
  for (const e of entries) {
    const fileEntry = fileEntries.find((f) => f.name === e.name);
    if (fileEntry?.api_key_env) {
      referencedEnvNames.add(fileEntry.api_key_env);
      const key = readConfiguredEnv(fileEntry.api_key_env);
      if (key) {
        keyMap.set(e.name, key);
      } else {
        diagnostic(
          `WARNING: Environment variable "${fileEntry.api_key_env}" for firewall "${e.name}" is not set — it will be unavailable`
        );
      }
      continue;
    }

    if (isKeychainAvailable()) {
      const key = (await getKey(e.name)) ?? fileEntry?.api_key ?? null;
      if (key) {
        keyMap.set(e.name, key);
      } else {
        diagnostic(`WARNING: No keychain entry for firewall "${e.name}" — it will be unavailable`);
      }
    } else {
      // Fallback: read api_key directly from file entry
      const fileEntry = fileEntries.find((f) => f.name === e.name);
      if (fileEntry?.api_key) keyMap.set(e.name, fileEntry.api_key);
    }
  }
}

export function resolveFirewall(name?: string): FirewallEntry | null {
  if (name) {
    const e = entries.find((e) => e.name === name);
    if (!e) return null;
    const key = keyMap.get(e.name);
    if (!key) return null;
    return { ...e, api_key: key };
  }

  if (entries.length === 1) {
    const e = entries[0];
    const key = keyMap.get(e.name);
    if (!key) return null;
    return { ...e, api_key: key };
  }

  if (entries.length > 1) return null;

  // No config entries — fall back to env vars
  const host = sanitizeHost(readConfiguredEnv("PANOS_HOST"));
  const api_key = readConfiguredEnv("PANOS_API_KEY");
  const verify_ssl = parseBooleanEnv(readConfiguredEnv("PANOS_VERIFY_SSL")) ?? false;
  if (host && api_key) return { name: "env", host, api_key, verify_ssl };

  return null;
}

export function isMultiFirewall(): boolean {
  return entries.length > 1;
}

export function getFirewallEntries(): Array<{ name: string; host: string; verify_ssl: boolean }> {
  return entries;
}

export interface EnvKeyedFirewallEntry {
  name: string;
  host: string;
  api_key_env: string;
  verify_ssl?: boolean;
}

/**
 * Appends api_key_env-based entries to the config file. Existing entries are
 * never modified or removed; a new entry whose name collides with an existing
 * one is skipped and reported, and an entry that would fail config-schema
 * validation on the next load is rejected and reported rather than written
 * (a single invalid entry would otherwise prevent every future startup).
 * Callers should re-run loadFirewallConfig() afterwards to make the new
 * targets live.
 */
export function mergeEnvKeyedFirewallEntries(
  newEntries: EnvKeyedFirewallEntry[]
): {
  added: string[];
  skipped_existing: string[];
  rejected: Array<{ name: string; issue: string }>;
} {
  const configPath = getConfigPath();
  mkdirSync(dirname(configPath), { recursive: true, mode: 0o700 });

  let raw: string | null;
  try {
    raw = readFileSync(configPath, "utf-8");
  } catch {
    raw = null;
  }

  let config: { firewalls: Array<Record<string, unknown>> };
  if (raw === null) {
    config = { firewalls: [] };
  } else {
    config = parseConfigJson(raw, configPath);
    if (!Array.isArray(config?.firewalls)) {
      throw new Error(
        `Existing config at ${configPath} does not contain a "firewalls" array — refusing to overwrite it`
      );
    }
  }

  const added: string[] = [];
  const skipped: string[] = [];
  const rejected: Array<{ name: string; issue: string }> = [];
  for (const entry of newEntries) {
    const candidate = {
      name: entry.name,
      host: sanitizeHost(entry.host),
      api_key_env: entry.api_key_env,
      ...(entry.verify_ssl ? { verify_ssl: true } : {}),
    };
    const check = firewallFileEntrySchema.safeParse(candidate);
    if (!check.success) {
      rejected.push({
        name: entry.name,
        issue: check.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "),
      });
      continue;
    }
    if (config.firewalls.some((e) => e.name === candidate.name)) {
      skipped.push(candidate.name);
      continue;
    }
    config.firewalls.push(candidate);
    added.push(candidate.name);
  }

  if (added.length > 0) {
    writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
  }

  return { added, skipped_existing: skipped, rejected };
}

export async function saveFirewallEntry(entry: FirewallEntry): Promise<void> {
  await initKeychain();
  entry = { ...entry, host: sanitizeHost(entry.host), verify_ssl: entry.verify_ssl ?? false };
  const configPath = getConfigPath();
  mkdirSync(dirname(configPath), { recursive: true, mode: 0o700 });

  let config: {
    firewalls: Array<{ name: string; host: string; api_key?: string; verify_ssl?: boolean }>;
  };
  try {
    const raw = readFileSync(configPath, "utf-8");
    config = JSON.parse(raw);
    if (!Array.isArray(config.firewalls)) config = { firewalls: [] };
  } catch {
    config = { firewalls: [] };
  }

  const verifySsl = entry.verify_ssl ? { verify_ssl: true } : {};

  if (isKeychainAvailable()) {
    await setKey(entry.name, entry.api_key);
    const fileEntry = { name: entry.name, host: entry.host, ...verifySsl };
    const idx = config.firewalls.findIndex((e) => e.name === entry.name);
    if (idx >= 0) config.firewalls[idx] = fileEntry;
    else config.firewalls.push(fileEntry);
  } else {
    const fileEntry = { name: entry.name, host: entry.host, api_key: entry.api_key, ...verifySsl };
    const idx = config.firewalls.findIndex((e) => e.name === entry.name);
    if (idx >= 0) config.firewalls[idx] = fileEntry;
    else config.firewalls.push(fileEntry);
  }

  writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });

  // Update in-memory state directly (avoids re-reading file and keychain)
  const memIdx = entries.findIndex((e) => e.name === entry.name);
  if (memIdx >= 0) entries[memIdx] = { name: entry.name, host: entry.host, verify_ssl: entry.verify_ssl };
  else entries.push({ name: entry.name, host: entry.host, verify_ssl: entry.verify_ssl });
  keyMap.set(entry.name, entry.api_key);
}
