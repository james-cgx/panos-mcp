import { loadOnePasswordEnvironment } from "./onepassword.js";
import { getOpCliInjectedNames } from "./onepassword-cli.js";
import {
  getExpectedEnvironmentVariableNames,
  recordInjectedEnvironmentNames,
  setInjectedEnvironment,
} from "./firewalls.js";

/**
 * Loads 1Password-injected credentials and records injected variable NAMES for
 * both credential modes. Called at startup, and again by
 * bootstrap_firewalls_from_panorama after it writes new api_key_env references
 * so their values become available without a server restart. Returns the
 * number of variables retained in memory.
 */
export async function loadInjectedEnvironment(): Promise<number> {
  const skippedNames: string[] = [];
  const environment = await loadOnePasswordEnvironment({
    allowedNames: getExpectedEnvironmentVariableNames(),
    onSkippedName: (name) => skippedNames.push(name),
  });
  setInjectedEnvironment(environment);
  recordInjectedEnvironmentNames(skippedNames);

  const cliInjectedNames = getOpCliInjectedNames();
  if (cliInjectedNames) recordInjectedEnvironmentNames(cliInjectedNames);

  return environment.size;
}
