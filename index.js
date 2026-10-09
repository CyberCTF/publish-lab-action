#!/usr/bin/env node
"use strict";

// Registers the calling lab repository with CyberCTF. The lab's own files (.ctf/metadata.json and
// the generated .isoloom tree) are UNTRUSTED input: everything read from them is validated and
// nothing is ever interpolated into a shell command or a query string (the GraphQL call is fully
// parameterised, the request bodies are built as native objects). The identity of what gets
// published (repository, commit) comes from the trusted GitHub context, and the slug is pinned to
// the repository name, so a repo can only ever (re)publish its own lab.

const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

const CLOUD_PROVIDERS = new Set(["aws", "azure", "gcp"]);
const ALLOWED_PROVIDERS = new Set([
  "virtualbox", "vmware_desktop", "parallels", "hyperv", "libvirt", "qemu", "vmware_esxi",
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
// An enum-style token (category, evidence kind): upper snake case, bounded.
function token(v, field, { max = 48 } = {}) {
  const s = String(v).toUpperCase();
  if (!/^[A-Z][A-Z0-9_]*$/.test(s) || s.length > max) fail(`${field} is not a valid token`);
  return s;
}
// A kebab-case slug (capabilities): lowercase letters, digits and hyphens.
function kebab(v, field, { max = 64 } = {}) {
  const s = String(v);
  if (!/^[a-z][a-z0-9-]*$/.test(s) || s.length > max) fail(`${field} must be kebab-case (lowercase letters, digits, hyphens)`);
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
// Endpoints come from inputs (org secrets), never hardcoded, so this public action carries none.
const backendUrl = input("backend_url", { required: true }).replace(/\/+$/, "");
const tokenUrl = input("token_url", { required: true });
const publish = input("publish", { def: "true" }) !== "false";
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
if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > 3) fail("difficulty must be an integer 1..3 (the catalogue's scale)");
const evidenceKind = token(meta.evidence_kind, "evidence_kind");
const evidenceParams = meta.evidence_params === undefined ? {} : meta.evidence_params;
if (typeof evidenceParams !== "object" || evidenceParams === null || Array.isArray(evidenceParams)) {
  fail("evidence_params must be an object");
}

let capabilities = [];
if (meta.capabilities !== undefined) {
  if (!Array.isArray(meta.capabilities)) fail("capabilities must be an array");
  if (meta.capabilities.length > 32) fail("too many capabilities");
  capabilities = meta.capabilities.map((c, i) => kebab(c, `capabilities[${i}]`));
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

// Cloud services (Isoloom's cloud-services target): a Terraform module applied into the
// player's own cloud account, the cloud named in the resolved spec.
const cloudServices = isFile(".isoloom/cloud-services/up.sh");
const runtime = cloudServices ? "CLOUD" : isFile(".isoloom/docker/compose.yml") ? "DOCKER" : "VM";

const derived = new Set();
if (cloudServices) {
  let cloud;
  try {
    cloud = JSON.parse(fs.readFileSync(".isoloom/resolved.json", "utf8")).cloud;
  } catch {
    fail("cannot read .isoloom/resolved.json (regenerate with Isoloom 0.10 or later)");
  }
  if (!cloud || !CLOUD_PROVIDERS.has(cloud.provider)) fail("resolved.json names no supported cloud (aws, azure, gcp)");
  derived.add(cloud.provider);
}
if (isFile(".isoloom/vagrant/Vagrantfile")) {
  ["virtualbox", "vmware_desktop", "parallels", "hyperv", "libvirt", "vmware_esxi"].forEach((p) => derived.add(p));
  // QEMU (an x86 lab emulated on an Apple Silicon Mac): only from an Isoloom that generates it
  // (0.10+: the Vagrantfile reads HOST_ARCH), and only when every VM got its network there.
  // QEMU links exactly two VMs per network without root; Isoloom writes a "No private network
  // on QEMU" comment on a VM it can't link, and such a lab must not be offered on QEMU.
  const vagrantfile = fs.readFileSync(".isoloom/vagrant/Vagrantfile", "utf8");
  if (/^HOST_ARCH = /m.test(vagrantfile) && !vagrantfile.includes("# No private network on QEMU:")) derived.add("qemu");
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
if (!cloudServices && isFile(".isoloom/docker/compose.yml")) derived.add("hosted");

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
  architectures = runtime === "VM" ? ["x86_64"] : ["x86_64", "aarch64"];
}

// --- objectives (.ctf/objectives.json, optional): untrusted, validated field by field ---
// A lab's challenges and their guided steps. `dev` values (the lab's development flags) are
// for the lab only and never sent; a static flag is sent as its sha256 only.
const OBJECTIVES = ".ctf/objectives.json";
let objectives;
if (isFile(OBJECTIVES)) {
  if (fs.statSync(OBJECTIVES).size > 512 * 1024) fail(`${OBJECTIVES} is too large`);
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(OBJECTIVES, "utf8"));
  } catch {
    fail(`${OBJECTIVES} is not valid JSON`);
  }
  const list = raw && !Array.isArray(raw) ? raw.objectives : raw;
  if (!Array.isArray(list) || list.length === 0) fail("objectives must be a non-empty array");
  if (list.length > 300) fail("too many objectives");
  let total = 0;
  const objective = (o, where, depth) => {
    if (o === null || typeof o !== "object" || Array.isArray(o)) fail(`${where} must be an object`);
    if (++total > 1000) fail("too many objectives and steps");
    const out = { key: kebab(o.key, `${where}.key`), title: str(o.title, `${where}.title`, { max: 200 }) };
    if (o.prompt !== undefined) out.prompt = str(o.prompt, `${where}.prompt`, { max: 4000 });
    const c = o.check;
    if (c === null || typeof c !== "object" || Array.isArray(c)) fail(`${where}.check must be an object`);
    const check = {};
    const kinds = ["evidence", "flag", "flag_sha256", "answer", "answer_regex"].filter((k) => c[k] !== undefined);
    if (kinds.length !== 1 && !(kinds.length === 2 && kinds.includes("answer") && kinds.includes("answer_regex"))) {
      fail(`${where}.check needs exactly one of evidence, flag, flag_sha256, answer (answer_regex may join answer)`);
    }
    if (c.evidence !== undefined) {
      check.evidence = token(c.evidence, `${where}.check.evidence`);
      if (c.evidence_params !== undefined) {
        if (c.evidence_params === null || typeof c.evidence_params !== "object" || Array.isArray(c.evidence_params)) {
          fail(`${where}.check.evidence_params must be an object`);
        }
        check.evidenceParams = JSON.stringify(c.evidence_params);
      }
      if (c.format !== undefined) check.format = str(c.format, `${where}.check.format`, { max: 100 });
    }
    if (c.flag !== undefined) {
      check.flagSha256 = crypto.createHash("sha256").update(str(c.flag, `${where}.check.flag`, { max: 500 }).trim()).digest("hex");
    }
    if (c.flag_sha256 !== undefined) {
      const h = String(c.flag_sha256).toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(h)) fail(`${where}.check.flag_sha256 must be 64 hex characters`);
      check.flagSha256 = h;
    }
    if (c.answer !== undefined) {
      if (!Array.isArray(c.answer) || c.answer.length === 0 || c.answer.length > 50) fail(`${where}.check.answer must be 1..50 values`);
      check.answer = c.answer.map((a, i) => str(String(a), `${where}.check.answer[${i}]`, { max: 500 }));
    }
    if (c.answer_regex !== undefined) check.answerRegex = str(c.answer_regex, `${where}.check.answer_regex`, { max: 200 });
    out.check = check;
    if (o.hints !== undefined) {
      if (!Array.isArray(o.hints) || o.hints.length > 20) fail(`${where}.hints must be an array of at most 20`);
      out.hints = o.hints.map((h, i) => str(h, `${where}.hints[${i}]`, { max: 2000 }));
    }
    if (o.points !== undefined) {
      if (!Number.isInteger(o.points) || o.points < 0 || o.points > 10000) fail(`${where}.points must be an integer 0..10000`);
      out.points = o.points;
    }
    if (o.optional !== undefined) out.optional = o.optional === true;
    if (o.capabilities !== undefined) {
      if (!Array.isArray(o.capabilities) || o.capabilities.length > 32) fail(`${where}.capabilities must be an array of at most 32`);
      out.capabilities = [...new Set(o.capabilities.map((x, i) => kebab(x, `${where}.capabilities[${i}]`, { max: 128 })))];
    }
    if (o.steps !== undefined) {
      if (depth > 0) fail(`${where}.steps: steps can't have steps`);
      if (!Array.isArray(o.steps) || o.steps.length > 30) fail(`${where}.steps must be an array of at most 30`);
      out.steps = o.steps.map((x, i) => objective(x, `${where}.steps[${i}]`, depth + 1));
    }
    return out;
  };
  objectives = list.map((o, i) => objective(o, `objectives[${i}]`, 0));
  const keys = [];
  for (const o of objectives) keys.push(o.key, ...(o.steps || []).map((x) => x.key));
  if (new Set(keys).size !== keys.length) fail("objective keys must be unique in the lab (steps included)");
}

// --- publish: client-credentials token, then one parameterised GraphQL mutation ---
const PUBLISH_LAB =
  "mutation ($input: PublishLabInput!, $publish: Boolean) { publishLab(input: $input, publish: $publish) { labId state } }";

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
    ...(objectives ? { objectives } : {}),
  };
  const res = await fetch(`${backendUrl}/graphql`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/graphql-response+json",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ query: PUBLISH_LAB, variables: { input: labInput, publish } }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || body.errors) {
    // Forbidden means the token carries no publisher role: say what it does carry (its public
    // claims only, never the token), so a scope or client mismatch shows up in the log.
    if ((body.errors || []).some((e) => e && e.extensions && e.extensions.code === "FORBIDDEN")) {
      try {
        const claims = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
        console.log(`token claims: azp=${claims.azp} scope="${claims.scope ?? ""}" aud=${JSON.stringify(claims.aud)} iss=${claims.iss}`);
        console.log(`token claim names: ${Object.keys(claims).sort().join(", ")}; sub ${claims.sub ? (claims.sub === claims.azp ? "= azp" : "present, differs from azp") : "absent"}`);
      } catch {
        console.log("token claims: not a JWT");
      }
    }
    fail(`publishLab failed: ${JSON.stringify(body.errors ?? { status: res.status })}`);
  }
  const out = body.data && body.data.publishLab;
  if (!out) fail("publishLab returned no data");
  console.log(`Published ${slug} [${runtime}]: ${out.state} (${out.labId})`);
  console.log(`Providers: ${providers.join(", ")}`);
  if (objectives) console.log(`Objectives: ${objectives.map((o) => o.key + (o.steps ? ` (${o.steps.length} steps)` : "")).join(", ")}`);
}

main().catch((e) => fail(String((e && e.message) || e)));
