// The adapter's flags for a node reached over mutual TLS (node-integration.md §3, §11.4,
// ADR-0038): `--connect-tls` with this client's certificate and key, the server CA, the
// expected name and an optional pinned key in place of `--socket`, never both, every
// setting checked before the adapter is spawned, and the CLI's flags mapped onto them.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { Adapter, adapterNodeArgs } from "../ward-node.mjs";

const CLI = fileURLToPath(new URL("../control-plane.mjs", import.meta.url));
const PIN = `sha256:${"ab".repeat(32)}`;
const TLS = {
  address: "node-4.ward.test:7443",
  cert: "/etc/ward-control-plane/client.pem",
  key: "/etc/ward-control-plane/client-key.pem",
  serverCa: "/etc/ward-control-plane/node-ca.pem",
  serverName: "node-4.ward.test",
};
// A stand-in adapter that reports the arguments it was started with, then exits.
const ECHO = [process.execPath, "-e", "process.stdout.write(JSON.stringify({schema:1,event:'argv',argv:process.argv.slice(1)})+'\\n')", "--"];

test("a socket is --socket and TLS settings are --connect-tls and the TLS flags", () => {
  assert.deepEqual(adapterNodeArgs({ socket: "/run/ward-node/node.sock" }), ["--socket", "/run/ward-node/node.sock"]);
  assert.deepEqual(adapterNodeArgs({ tls: TLS }), [
    "--connect-tls", TLS.address,
    "--tls-cert", TLS.cert,
    "--tls-key", TLS.key,
    "--tls-server-ca", TLS.serverCa,
    "--tls-server-name", TLS.serverName,
  ]);
  assert.deepEqual(adapterNodeArgs({ tls: { ...TLS, serverPin: PIN } }).slice(-2), ["--tls-server-pin", PIN]);
});

test("both, neither, a missing TLS setting and a malformed pin are refused", () => {
  assert.throws(() => adapterNodeArgs({ socket: "/run/ward-node/node.sock", tls: TLS }), /not both/);
  assert.throws(() => adapterNodeArgs({}), /socket path or its TLS settings/);
  assert.throws(() => adapterNodeArgs({ tls: null }), /an object/);
  for (const field of Object.keys(TLS)) {
    const { [field]: _, ...missing } = TLS;
    assert.throws(() => adapterNodeArgs({ tls: missing }), new RegExp(`need ${field}`));
    assert.throws(() => adapterNodeArgs({ tls: { ...TLS, [field]: "" } }), new RegExp(`need ${field}`));
  }
  for (const pin of ["", "sha256:00", `sha256:${"AB".repeat(32)}`, `sha1:${"ab".repeat(32)}`, 7]) {
    assert.throws(() => adapterNodeArgs({ tls: { ...TLS, serverPin: pin } }), /serverPin/);
  }
});

test("the adapter process is started with the TLS flags in place of --socket", async () => {
  const adapter = new Adapter({ command: ECHO, tls: { ...TLS, serverPin: PIN }, timeoutMs: 120000 });
  const event = await adapter.next();
  assert.equal(event.event, "argv");
  assert.deepEqual(event.argv, [...adapterNodeArgs({ tls: { ...TLS, serverPin: PIN } }), "--timeout-ms", "120000"]);
  assert.ok(!event.argv.includes("--socket"));
  assert.throws(() => new Adapter({ command: ECHO, socket: "/s", tls: TLS }), /not both/);
});

test("the CLI maps its TLS flags onto the adapter and refuses a mixture", () => {
  const run = (...args) => spawnSync(process.execPath, [CLI, "capabilities", "--adapter", ECHO[0], ...args], { encoding: "utf8" });
  const both = run("--socket", "/s", "--connect-tls", TLS.address);
  assert.equal(both.status, 2, both.stderr);
  assert.match(both.stderr, /exclusive/);
  const stray = run("--socket", "/s", "--tls-cert", TLS.cert);
  assert.equal(stray.status, 2, stray.stderr);
  assert.match(stray.stderr, /--tls-cert needs --connect-tls/);
  const partial = run("--connect-tls", TLS.address, "--tls-cert", TLS.cert);
  assert.equal(partial.status, 2, partial.stderr);
  assert.match(partial.stderr, /--tls-key is required/);
});
