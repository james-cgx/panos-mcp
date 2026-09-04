import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const tempDir = mkdtempSync(join(tmpdir(), "panos-mcp-handshake-"));
const entry = resolve("dist/index.js");
const env = {
  ...process.env,
  PANOS_HOST: "firewall.example.com",
  PANOS_API_KEY: "handshake-placeholder-key",
  PANOS_FIREWALLS_CONFIG: join(tempDir, "firewalls.json"),
};
delete env.OP_ENVIRONMENT_ID;
delete env.OP_SERVICE_ACCOUNT_TOKEN;
delete env.PANOS_OP_WRAPPED;
delete env.PANOS_PRE_OP_ENV_NAMES;

let child;
try {
  child = spawn(process.execPath, [entry], {
    cwd: process.cwd(),
    env,
    stdio: ["pipe", "pipe", "pipe"],
  });
} catch (error) {
  process.stderr.write(`failed to spawn MCP server: ${error.message}\n`);
  rmSync(tempDir, { recursive: true, force: true });
  process.exit(1);
}

// Direct mode keeps this dependency-free handshake deterministic. Locked-op
// recovery is covered by the resolver and credential-manager Vitest suites.
child.on("error", (error) => {
  process.stderr.write(`failed to spawn MCP server: ${error.message}\n`);
  rmSync(tempDir, { recursive: true, force: true });
  process.exit(1);
});
child.stdin.on("error", () => {
  // A prior child failure already provides the actionable diagnostic.
});

let stderr = "";
child.stderr.on("data", (chunk) => {
  stderr = (stderr + chunk.toString("utf8")).slice(-8_000);
});

const pending = new Map();
let stdoutBuffer = "";
child.stdout.on("data", (chunk) => {
  stdoutBuffer += chunk.toString("utf8");
  while (stdoutBuffer.includes("\n")) {
    const newline = stdoutBuffer.indexOf("\n");
    const line = stdoutBuffer.slice(0, newline).replace(/\r$/, "");
    stdoutBuffer = stdoutBuffer.slice(newline + 1);
    if (!line) continue;
    let message;
    try {
      message = JSON.parse(line);
    } catch (error) {
      fail(`server stdout contained a non-JSON MCP frame: ${error.message}`);
      return;
    }
    if (message.id !== undefined && pending.has(message.id)) {
      pending.get(message.id)(message);
      pending.delete(message.id);
    }
  }
});

function send(message) {
  child.stdin.write(`${JSON.stringify(message)}\n`);
}

function request(id, method, params = {}) {
  return new Promise((resolveRequest, reject) => {
    const timeout = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`timed out waiting for ${method}`));
    }, 15_000);
    pending.set(id, (message) => {
      clearTimeout(timeout);
      if (message.error) reject(new Error(`${method} failed: ${JSON.stringify(message.error)}`));
      else resolveRequest(message.result);
    });
    send({ jsonrpc: "2.0", id, method, params });
  });
}

function fail(message) {
  process.stderr.write(`${message}\n${stderr}`);
  child.kill("SIGTERM");
  rmSync(tempDir, { recursive: true, force: true });
  process.exitCode = 1;
  setTimeout(() => process.exit(1), 250);
}

try {
  await request(1, "initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "panos-mcp-handshake-test", version: "1.0.0" },
  });
  send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
  const result = await request(2, "tools/list");
  const names = result.tools.map((tool) => tool.name);
  if (!names.includes("reload_credentials")) {
    throw new Error("reload_credentials was not present in tools/list");
  }
  process.stdout.write(`MCP handshake passed: ${names.length} tools (reload_credentials present)\n`);
  child.kill("SIGTERM");
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}
