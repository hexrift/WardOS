// A fake OpenBao and a fake upstream for the brokered-credentials acceptance
// (node-integration.md §6.8, ADR-0034), both plain HTTP on 127.0.0.1 ephemeral ports, as
// ward-node's own tests/node_credentials_cli.rs runs them:
//
//   node fake-credential-services.mjs --dir <dir> --token <provider token> --leased <value>
//
// The provider answers `POST /v1/auth/token/create/<role>` from a request carrying the
// provider token (`X-Vault-Token`) with the token `<value>-<n>` and the accessor
// `node-js-accessor-<n>` for the n-th lease, and `POST /v1/auth/token/revoke-accessor` with
// 204; anything else is refused. The upstream answers every request 200
// `{"artifact":"built"}`. Once both listen, `<dir>/ready.json` holds
// `{"provider":<port>,"upstream":<port>}`; `<dir>/state.json` holds what they saw,
// `{"issued":[request bodies],"revoked":[accessors],"heads":[request line and headers]}`,
// rewritten whole (temporary file, rename) on every request, so a reader never sees half
// of it. SIGTERM or SIGINT ends both.
import { renameSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: { dir: { type: "string" }, token: { type: "string" }, leased: { type: "string" } },
  strict: true,
});
for (const name of ["dir", "token", "leased"]) {
  if (!values[name]) {
    process.stderr.write(`fake-credential-services: --${name} is required\n`);
    process.exit(2);
  }
}

const state = { issued: [], revoked: [], heads: [] };

function writeWhole(name, object) {
  const path = join(values.dir, name);
  writeFileSync(`${path}.${process.pid}`, JSON.stringify(object));
  renameSync(`${path}.${process.pid}`, path);
}

function reply(response, status, body) {
  const text = body === null ? "" : JSON.stringify(body);
  response.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text), Connection: "close" });
  response.end(text);
}

function withBody(request, handle) {
  const chunks = [];
  request.on("data", (chunk) => chunks.push(chunk));
  request.on("end", () => handle(Buffer.concat(chunks)));
}

const provider = createServer((request, response) =>
  withBody(request, (raw) => {
    if (request.headers["x-vault-token"] !== values.token) return reply(response, 403, { errors: ["permission denied"] });
    let body = null;
    try {
      body = JSON.parse(raw.toString("utf8"));
    } catch {
      return reply(response, 400, { errors: ["not json"] });
    }
    if (request.method === "POST" && request.url.startsWith("/v1/auth/token/create/")) {
      state.issued.push(body);
      const n = state.issued.length;
      writeWhole("state.json", state);
      return reply(response, 200, {
        auth: {
          client_token: `${values.leased}-${n}`,
          accessor: `node-js-accessor-${n}`,
          lease_duration: Number.parseInt(String(body.ttl ?? "0"), 10) || 0,
          token_policies: body.policies ?? [],
        },
      });
    }
    if (request.method === "POST" && request.url === "/v1/auth/token/revoke-accessor") {
      state.revoked.push(String(body.accessor ?? ""));
      writeWhole("state.json", state);
      return reply(response, 204, null);
    }
    return reply(response, 404, { errors: [] });
  }),
);

const upstream = createServer((request, response) =>
  withBody(request, () => {
    const headers = [];
    for (let i = 0; i < request.rawHeaders.length; i += 2) headers.push(`${request.rawHeaders[i].toLowerCase()}: ${request.rawHeaders[i + 1]}`);
    state.heads.push([`${request.method} ${request.url} HTTP/${request.httpVersion}`, ...headers.sort()].join("\n"));
    writeWhole("state.json", state);
    reply(response, 200, { artifact: "built" });
  }),
);

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}

writeWhole("state.json", state);
const ports = { provider: await listen(provider), upstream: await listen(upstream) };
writeWhole("ready.json", ports);
for (const signal of ["SIGTERM", "SIGINT"]) process.on(signal, () => process.exit(0));
