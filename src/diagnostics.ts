const diagnosticSecrets = new Set<string>();

export function setDiagnosticSecrets(values: Iterable<string>): void {
  diagnosticSecrets.clear();
  for (const value of values) {
    if (value) diagnosticSecrets.add(value);
  }
}

function redact(message: string): string {
  let redacted = message;
  const processSecrets = Object.entries(process.env)
    .filter(([name, value]) => value && /(?:KEY|TOKEN|PASSWORD|SECRET)/i.test(name))
    .map(([, value]) => value!);
  for (const secret of [...diagnosticSecrets, ...processSecrets]) {
    redacted = redacted.split(secret).join("[REDACTED]");
  }
  return redacted;
}

export function diagnostic(message: string): void {
  const timestamp = new Date().toISOString();
  for (const line of redact(message).split(/\r?\n/)) {
    process.stderr.write(`[panos-mcp] ${timestamp} ${line}\n`);
  }
}

export function errorDetails(error: unknown): string {
  if (error instanceof Error) {
    return error.stack ?? error.message;
  }
  return String(error);
}
