#!/usr/bin/env node
"use strict";

// Registers the calling lab repository with CyberCTF. The lab's own files (.ctf/metadata.json and
// the generated .isoloom tree) are UNTRUSTED input: everything read from them is validated and
// nothing is ever interpolated into a shell command or a query string (the GraphQL call is fully
// parameterised, the request bodies are built as native objects). The identity of what gets
// published (repository, commit) comes from the trusted GitHub context, and the slug is pinned to
// the repository name, so a repo can only ever (re)publish its own lab.

const fs = require("fs");
const path = require("path");

const ALLOWED_PROVIDERS = new Set([
  "virtualbox", "vmware_desktop", "parallels", "hyperv", "libvirt", "vmware_esxi",
  "proxmox", "aws", "azure", "gcp", "digitalocean", "linode", "oci", "hosted",
]);
const ALLOWED_ARCHS = new Set(["x86_64", "aarch64"]);
const CONTROL_CHARS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/; // no NUL/ESC/etc in any field

function fail(msg) {
  console.error(`::error::publish-lab: ${msg}`);
  process.exit(1);
}
function mask(v) {
  if (v) console.log(`::add-mask::${v}`);
}
function input(name, { required = false, def = "" } = {}) {
  const v = (process.env[`INPUT_${name.toUpperCase()}`] ?? "").trim();
  if (!v && required) fail(`input '${name}' is required`);
  return v || def;
}

// A plain string field: a real string, no control characters, within bounds.
function str(v, field, { min = 1, max = 2000 } = {}) {
  if (typeof v !== "string") fail(`${field} must be a string`);
  if (CONTROL_CHARS.test(v)) fail(`${field} contains control characters`);
  if (v.length < min || v.length > max) fail(`${field} length must be ${min}..${max}`);
  return v;
}
// An enum-style token (category, evidence kind, capability): upper snake case, bounded.
function token(v, field, { max = 48 } = {}) {
  const s = String(v).toUpperCase();
  if (!/^[A-Z][A-Z0-9_]*$/.test(s) || s.length > max) fail(`${field} is not a valid token`);
  return s;
}

// --- trusted context: who and what we are publishing (never from the lab's metadata) ---
const repository = process.env.GITHUB_REPOSITORY || "";
const commit = process.env.GITHUB_SHA || "";
if (!/^[\w.-]+\/[\w.-]+$/.test(repository)) fail("GITHUB_REPOSITORY is missing or malformed");
if (!/^[0-9a-f]{40}$/.test(commit)) fail("GITHUB_SHA is missing or malformed");
const [owner, repoName] = repository.split("/");
const allowedOwner = input("allowed_owner", { def: "CyberCTF" });
if (owner.toLowerCase() !== allowedOwner.toLowerCase()) {
  fail(`refusing to publish: ${repository} is not under ${allowedOwner}`);
}

// --- credentials and endpoints: masked so they never surface in (public) Actions logs ---
const clientId = input("client_id", { required: true });
const clientSecret = input("client_secret", { required: true });
const backendUrl = input("backend_url", { def: "https://cyberbackend.com" }).replace(/\/+$/, "");
const tokenUrl = input("token_url", { def: "https://www.cyberauth.co/api/auth/oauth2/token" });
mask(clientSecret);
mask(backendUrl);
mask(tokenUrl);
if (!/^https:\/\//.test(backendUrl) || !/^https:\/\//.test(tokenUrl)) fail("endpoints must be https");

// --- the lab's metadata: untrusted, validated field by field ---
const META = ".ctf/metadata.json";
let rawMeta;
try {
  const st = fs.statSync(META);
  if (!st.isFile()) fail(`${META} is not a file`);
  if (st.size > 64 * 1024) fail(`${META} is too large`);
  rawMeta = fs.readFileSync(META, "utf8");
} catch {
  fail(`missing ${META}`);
}
let meta;
try {
  meta = JSON.parse(rawMeta);
} catch {
  fail(`${META} is not valid JSON`);
}
if (meta === null || typeof meta !== "object" || Array.isArray(meta)) fail("metadata must be a JSON object");

// The slug is pinned to the repository name: a lab can only publish itself, never overwrite
// another lab's slug (publishLab upserts by slug).
if (meta.slug !== undefined && meta.slug !== repoName) {
  fail(`metadata slug '${String(meta.slug).slice(0, 64)}' must equal the repository name '${repoName}'`);
}
if (!/^[a-z][a-z0-9-]{1,63}$/.test(repoName)) fail(`repository name '${repoName}' is not a valid slug`);
const slug = repoName;

const title = str(meta.title, "title", { max: 200 });
const description = str(meta.description, "description", { max: 4000 });
const question = str(meta.question, "question", { max: 1000 });
const category = token(meta.category, "category");
const difficulty = Number(meta.difficulty);
if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > 5) fail("difficulty must be an integer 1..5");
const evidenceKind = token(meta.evidence_kind, "evidence_kind");
const evidenceParams = meta.evidence_params === undefined ? {} : meta.evidence_params;
if (typeof evidenceParams !== "object" || evidenceParams === null || Array.isArray(evidenceParams)) {
  fail("evidence_params must be an object");
}

let capabilities = [];
if (meta.capabilities !== undefined) {
  if (!Array.isArray(meta.capabilities)) fail("capabilities must be an array");
  if (meta.capabilities.length > 32) fail("too many capabilities");
  capabilities = meta.capabilities.map((c, i) => token(c, `capabilities[${i}]`));
}

// --- runtime and providers: derived from the generated tree, strictly allowlisted ---
const isFile = (p) => {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
};
const isDir = (p) => {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
};

const runtime = isFile(".isoloom/docker/compose.yml") ? "DOCKER" : "VM";

const derived = new Set();
if (isFile(".isoloom/vagrant/Vagrantfile")) {
  ["virtualbox", "vmware_desktop", "parallels", "hyperv", "libvirt", "vmware_esxi"].forEach((p) => derived.add(p));
}
if (isDir(".isoloom/proxmox") || isDir(".isoloom/docker-vm/proxmox")) derived.add("proxmox");
for (const base of [".isoloom/cloud-docker", ".isoloom/cloud-vm"]) {
  let entries = [];
  try {
    entries = fs.readdirSync(base);
  } catch {
    entries = [];
  }
  for (const e of entries) {
    if (ALLOWED_PROVIDERS.has(e) && isDir(path.join(base, e))) derived.add(e); // unknown dir names ignored
  }
}
if (isFile(".isoloom/docker/compose.yml")) derived.add("hosted");

// metadata.providers may only NARROW the derived set, never add a target Isoloom did not produce.
let providers = [...derived];
if (meta.providers !== undefined) {
  if (!Array.isArray(meta.providers)) fail("providers must be an array");
  const narrow = new Set(meta.providers.filter((p) => ALLOWED_PROVIDERS.has(p)));
  providers = providers.filter((p) => narrow.has(p));
}
providers = providers.filter((p) => ALLOWED_PROVIDERS.has(p)).sort();
if (providers.length === 0) fail("no supported providers found under .isoloom (run `isoloom generate` first)");

let architectures;
if (meta.architectures !== undefined) {
  if (!Array.isArray(meta.architectures)) fail("architectures must be an array");
  architectures = meta.architectures.filter((a) => ALLOWED_ARCHS.has(a));
  if (architectures.length === 0) fail("no valid architectures");
} else {
  architectures = runtime === "DOCKER" ? ["x86_64", "aarch64"] : ["x86_64"];
}

// --- publish: client-credentials token, then one parameterised GraphQL mutation ---
const PUBLISH_LAB = "mutation ($input: PublishLabInput!) { publishLab(input: $input) { labId state } }";

async function main() {
  const tokenRes = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: "Basic " + Buffer.from(`${clientId}:${clientSecret}`).toString("base64"),
    },
    body: new URLSearchParams({ grant_type: "client_credentials", scope: "labs:publish", resource: backendUrl }),
  });
  const tokenBody = await tokenRes.json().catch(() => ({}));
  const token = tokenBody.access_token;
  if (!tokenRes.ok || typeof token !== "string") fail(`token request failed: ${tokenRes.status}`);
  mask(token);

  const labInput = {
    slug, title, description, category, difficulty,
    evidenceKind, evidenceParams: JSON.stringify(evidenceParams),
    capabilities, question, runtime, repository, commit, providers, architectures,
  };
  const res = await fetch(`${backendUrl}/graphql`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/graphql-response+json",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ query: PUBLISH_LAB, variables: { input: labInput } }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || body.errors) fail(`publishLab failed: ${JSON.stringify(body.errors ?? { status: res.status })}`);
  const out = body.data && body.data.publishLab;
  if (!out) fail("publishLab returned no data");
  console.log(`Published ${slug} [${runtime}]: ${out.state} (${out.labId})`);
  console.log(`Providers: ${providers.join(", ")}`);
}

main().catch((e) => fail(String((e && e.message) || e)));
