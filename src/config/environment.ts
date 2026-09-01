import { reloadCredentials } from "./credential-manager.js";
import { getInjectedEnvironmentNames } from "./firewalls.js";

/**
 * Loads 1Password-injected credentials and records injected variable NAMES for
 * both credential modes. Called at startup, and again by
 * bootstrap_firewalls_from_panorama after it writes new api_key_env references
 * so their values become available without a server restart. Returns the
 * number of variables retained in memory.
 */
export async function loadInjectedEnvironment(): Promise<number> {
  await reloadCredentials();
  return getInjectedEnvironmentNames().length;
}
