import { diagnostic, setDiagnosticSecrets } from "../diagnostics.js";
import {
  describeUnconfiguredState,
  getExpectedEnvironmentVariableNames,
  getFirewallEntries,
  loadFirewallConfig,
  recordInjectedEnvironmentNames,
  resolveFirewall,
  setInjectedEnvironment,
} from "./firewalls.js";
import { isOnePasswordInternalName, resolveOpCliEnvironment } from "./op-resolver.js";
import { getOpCliInjectedNames, type EnvLike } from "./onepassword-cli.js";
import { loadOnePasswordEnvironment } from "./onepassword.js";

export type CredentialMode = "direct" | "cli" | "service-account";

export interface CredentialStatus {
  mode: CredentialMode;
  resolved: boolean;
  lastError: string | null;
  lastAttemptAt: string | null;
  attemptCount: number;
}

interface CredentialManagerDependencies {
  env?: EnvLike;
  resolveCli?: typeof resolveOpCliEnvironment;
  loadServiceAccount?: typeof loadOnePasswordEnvironment;
  loadConfig?: typeof loadFirewallConfig;
  log?: (message: string) => void;
}

const RETRY_DELAYS_MS = [5_000, 10_000, 30_000, 60_000];

function credentialMode(env: EnvLike): CredentialMode {
  if (!(env.OP_ENVIRONMENT_ID ?? "").trim()) return "direct";
  return (env.OP_SERVICE_ACCOUNT_TOKEN ?? "").trim() ? "service-account" : "cli";
}

function configurationFingerprint(env: EnvLike): string {
  return [
    (env.OP_ENVIRONMENT_ID ?? "").trim(),
    (env.OP_SERVICE_ACCOUNT_TOKEN ?? "").trim(),
    (env.PANOS_OP_WRAPPED ?? "").trim(),
  ].join("\n");
}

function safeError(error: unknown, env: EnvLike): string {
  let message = error instanceof Error ? error.message : String(error);
  const token = (env.OP_SERVICE_ACCOUNT_TOKEN ?? "").trim();
  if (token) message = message.split(token).join("[REDACTED]");
  return message.replace(/\s+/g, " ").trim().slice(0, 500);
}

export class CredentialManager {
  private readonly env: EnvLike;
  private readonly resolveCli: typeof resolveOpCliEnvironment;
  private readonly loadServiceAccount: typeof loadOnePasswordEnvironment;
  private readonly loadConfig: typeof loadFirewallConfig;
  private readonly log: (message: string) => void;
  private state: CredentialStatus;
  private inFlight: Promise<boolean> | null = null;
  private retryLoop: Promise<void> | null = null;
  private retryIndex = 0;
  private wakeRetry: (() => void) | null = null;
  private suspectRefreshScheduled = false;
  private fingerprint: string;

  constructor(dependencies: CredentialManagerDependencies = {}) {
    this.env = dependencies.env ?? (process.env as EnvLike);
    this.resolveCli = dependencies.resolveCli ?? resolveOpCliEnvironment;
    this.loadServiceAccount = dependencies.loadServiceAccount ?? loadOnePasswordEnvironment;
    this.loadConfig = dependencies.loadConfig ?? loadFirewallConfig;
    this.log = dependencies.log ?? diagnostic;
    this.fingerprint = configurationFingerprint(this.env);
    this.state = {
      mode: credentialMode(this.env),
      resolved: false,
      lastError: null,
      lastAttemptAt: null,
      attemptCount: 0,
    };
  }

  getStatus(): CredentialStatus {
    const mode = credentialMode(this.env);
    const fingerprint = configurationFingerprint(this.env);
    if (fingerprint !== this.fingerprint) {
      this.fingerprint = fingerprint;
      this.state = { ...this.state, mode, resolved: false, lastError: null };
    }
    return { ...this.state };
  }

  isOnePasswordConfigured(): boolean {
    return credentialMode(this.env) !== "direct";
  }

  private async performResolution(): Promise<boolean> {
    this.fingerprint = configurationFingerprint(this.env);
    this.state.mode = credentialMode(this.env);
    this.state.lastAttemptAt = new Date().toISOString();
    this.state.attemptCount += 1;

    try {
      let environment = new Map<string, string>();
      const additionalNames: string[] = [];
      const wrappedNames = getOpCliInjectedNames(this.env);

      if (wrappedNames !== null) {
        for (const name of wrappedNames) {
          const value = this.env[name];
          if (value !== undefined && !isOnePasswordInternalName(name)) {
            environment.set(name, value);
          }
        }
      } else if (this.state.mode === "cli") {
        const result = await this.resolveCli({ env: this.env });
        if (!result.ok) throw new Error(result.reason);
        environment = result.environment;
      } else if (this.state.mode === "service-account") {
        environment = await this.loadServiceAccount({
          env: this.env,
          allowedNames: getExpectedEnvironmentVariableNames(),
          onSkippedName: (name) => additionalNames.push(name),
        });
      }

      setInjectedEnvironment(environment);
      setDiagnosticSecrets(environment.values());
      recordInjectedEnvironmentNames(additionalNames);
      await this.loadConfig();
      this.state.resolved = true;
      this.state.lastError = null;
      this.retryIndex = 0;

      const targetCount = getFirewallEntries().length || (resolveFirewall() ? 1 : 0);
      this.log(
        `Credentials resolved: ${environment.size} variable(s); ${targetCount} firewall target(s) configured`
      );
      if (targetCount === 0) this.logUnconfiguredState();
      return true;
    } catch (error) {
      this.state.resolved = false;
      this.state.lastError = safeError(error, this.env);
      if (this.state.mode !== "direct") {
        setInjectedEnvironment(new Map());
        setDiagnosticSecrets([]);
        try {
          await this.loadConfig();
        } catch {
          // Preserve the credential error; config diagnostics are emitted on a successful reload.
        }
      }
      return false;
    }
  }

  private resolveSingleFlight(): Promise<boolean> {
    if (this.inFlight) return this.inFlight;
    this.inFlight = this.performResolution().finally(() => {
      this.inFlight = null;
    });
    return this.inFlight;
  }

  async ensureCredentials(): Promise<boolean> {
    if (this.state.resolved) return true;
    return this.resolveSingleFlight();
  }

  async reloadCredentials(): Promise<boolean> {
    this.resetBackoff();
    return this.resolveSingleFlight();
  }

  startRetryLoop(): void {
    if (this.retryLoop) return;
    this.retryLoop = this.runRetryLoop()
      .catch((error) => this.log(`Credential retry loop failed unexpectedly: ${safeError(error, this.env)}`))
      .finally(() => {
        this.retryLoop = null;
        this.suspectRefreshScheduled = false;
      });
  }

  private async runRetryLoop(): Promise<void> {
    let attempt = 0;
    while (!this.state.resolved) {
      attempt += 1;
      if (await this.resolveSingleFlight()) return;

      const delay = RETRY_DELAYS_MS[Math.min(this.retryIndex, RETRY_DELAYS_MS.length - 1)];
      this.retryIndex += 1;
      this.log(
        `Credential resolution failed (attempt ${attempt}): ${this.state.lastError ?? "unknown error"} — retrying in ${delay / 1000}s`
      );
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, delay);
        this.wakeRetry = () => {
          clearTimeout(timer);
          resolve();
        };
      });
      this.wakeRetry = null;
    }
  }

  resetBackoff(): void {
    this.retryIndex = 0;
    this.wakeRetry?.();
    this.wakeRetry = null;
  }

  markCredentialsSuspect(): void {
    if (!this.isOnePasswordConfigured() || this.suspectRefreshScheduled) return;
    this.suspectRefreshScheduled = true;
    queueMicrotask(() => {
      this.state.resolved = false;
      this.resetBackoff();
      this.startRetryLoop();
    });
  }

  private logUnconfiguredState(): void {
    const state = describeUnconfiguredState();
    this.log("WARNING: No firewall targets are configured — every firewall tool call will fail.");
    this.log(`  Config file: ${state.config_path} (${state.config_file_exists ? "exists" : "not found"})`);
    if (state.injected_unreferenced_env_var_names.length > 0) {
      this.log(
        `  Injected but unreferenced environment variables: ${state.injected_unreferenced_env_var_names.join(", ")}`
      );
    }
    this.log("  Configure a target one of three ways:");
    this.log("    1. Set PANOS_HOST and PANOS_API_KEY (directly or in the 1Password Environment).");
    this.log(
      `    2. Create ${state.config_path} with entries whose api_key_env references injected variable names.`
    );
    this.log(`       File shape: ${JSON.stringify(state.config_example)}`);
    this.log(
      "    3. Panorama-managed fleet: add a single Panorama entry, then run the bootstrap_firewalls_from_panorama tool."
    );
  }
}

export const credentialManager = new CredentialManager();

export function getCredentialStatus(): CredentialStatus {
  return credentialManager.getStatus();
}

export function ensureCredentials(): Promise<boolean> {
  return credentialManager.ensureCredentials();
}

export function reloadCredentials(): Promise<boolean> {
  return credentialManager.reloadCredentials();
}

export function startCredentialRetryLoop(): void {
  credentialManager.startRetryLoop();
}

export function markCredentialsSuspect(): void {
  credentialManager.markCredentialsSuspect();
}
