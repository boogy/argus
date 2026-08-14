// Shared argus transport for TypeScript plugin hosts (opencode, pi.dev).
//
// This file is not installed on its own. `argus install` writes one plugin
// file per host, built by concatenating this transport with that host's
// adapter half — see `shim_source()` in `src/harness/opencode.rs`. A plugin
// host loads exactly one file, and a relative import between two installed
// files is one more thing that can break silently in someone else's editor.
//
// Fire-and-forget throughout; never blocks and never fails the user's session.
// Fast path: one persistent connection to the daemon's local socket using the
// shim's frame format (newline-delimited Envelope JSON). Fallback: spawn the
// shim binary, which handles spooling and daemon autospawn.
import { spawn } from "node:child_process";
import { closeSync, openSync, readSync } from "node:fs";
import { createConnection, type Socket } from "node:net";

let sock: Socket | null = null;
let sockBroken = false;

// Bytes handed to the socket that have not been flushed yet. A stream accepts
// writes while it is still connecting and while the kernel buffer is full, so
// without a cap a daemon that stops reading turns into unbounded memory growth
// inside the user's editor. One mebibyte is thousands of events; past it, new
// events take the spawn fallback, which spools.
let pending = 0;
const MAX_PENDING = 1 << 20;

// FNV-1a over the data directory, matching `endpoint_discriminator` in
// src/paths.rs. The Windows pipe namespace is machine-global and flat, so the
// name has to carry something per-user or every account on the box shares one
// endpoint. Case-folded and stripped of a trailing separator because this side
// reads %LOCALAPPDATA% while the Rust side resolves SHGetKnownFolderPath: same
// directory, not necessarily the same spelling.
//
// Pinned on the Rust side by `the_discriminator_is_pinned_to_a_known_value`;
// `C:\Users\alice\AppData\Local\argus` must hash to a82d74d39a3ee778. Change
// one implementation and the plugin's fast path silently stops finding the
// daemon (it still works — it just falls back to spawning the shim per event).
function discriminator(dir: string): string {
  const key = dir.toLowerCase().replace(/[\\/]+$/, "");
  let hash = 0xcbf29ce484222325n;
  for (const byte of Buffer.from(key, "utf8")) {
    hash = BigInt.asUintN(64, (hash ^ BigInt(byte)) * 0x100000001b3n);
  }
  return hash.toString(16).padStart(16, "0");
}

function dataDir(): string {
  if (process.env.ARGUS_DATA_DIR) return process.env.ARGUS_DATA_DIR;
  if (process.platform === "win32")
    return `${process.env.LOCALAPPDATA}\\argus`;
  if (process.platform === "darwin")
    return `${process.env.HOME}/Library/Application Support/argus`;
  return `${process.env.XDG_DATA_HOME ?? `${process.env.HOME}/.local/share`}/argus`;
}

function socketPath(): string {
  if (process.env.ARGUS_SOCKET) return process.env.ARGUS_SOCKET;
  if (process.platform === "win32")
    return `\\\\.\\pipe\\argus-${discriminator(dataDir())}`;
  return `${dataDir()}/argus.sock`;
}

/// Returns whether the frame was accepted by the socket — *not* whether it has
/// reached the daemon. A caller that treats "not yet flushed" as failure sends
/// the same event twice.
function sendViaSocket(frame: string): boolean {
  if (sockBroken) return false;
  const size = Buffer.byteLength(frame, "utf8");
  // Checked before writing, so the fallback takes an event we have not also
  // queued. Diverting an event is one envelope; queueing it and diverting it
  // is two.
  if (pending + size > MAX_PENDING) return false;
  try {
    if (!sock) {
      sock = createConnection(socketPath());
      // Never keep the host process's event loop alive on exit.
      sock.unref();
      sock.on("error", () => {
        sock?.destroy();
        sock = null;
        sockBroken = true;
        // Whatever was queued died with the socket; keeping the count would
        // wedge the fast path shut for the rest of the session.
        pending = 0;
        // Retry the fast path after a cool-down; fallback covers the gap.
        setTimeout(() => (sockBroken = false), 5000).unref?.();
      });
    }
    pending += size;
    // `write()` returning false means the stream is over its high-water mark,
    // not that the frame was refused — it is queued and goes out on drain.
    // Returning that boolean to the caller made it spawn the shim for an event
    // the socket was already carrying: one event, two envelopes, every time
    // the buffer filled or the connection was still being established. The
    // completion callback is the per-frame form of the `drain` event and is
    // what releases the byte count here.
    sock.write(frame, () => {
      pending -= size;
    });
    return true;
  } catch {
    sock = null;
    pending = 0;
    return false;
  }
}

function sendViaSpawn(source: string, payload: string): void {
  try {
    const bin = process.env.ARGUS_BIN ?? "argus";
    const child = spawn(bin, ["hook", "--source", source], {
      stdio: ["pipe", "ignore", "ignore"],
      detached: true,
    });
    child.on("error", () => {});
    child.stdin.on("error", () => {});
    child.stdin.write(payload);
    child.stdin.end();
    child.unref();
  } catch {
    // Observability must never break the tool.
  }
}

// Which cloud identity the host agent is holding. The Rust half of this lives
// in `src/cloudid.rs` and the two lists are pinned to each other by
// `the_plugin_reads_the_same_environment_the_shim_does` — an identifier added
// on one side and not the other is a build failure, not a silent gap.
//
// It has to be duplicated here because the fast path never runs the shim: the
// plugin writes the envelope itself, so an identity read only in Rust would be
// present on the spawn fallback and missing on every ordinary event.
//
// Identifiers are captured by value and are all public — each one already
// appears in the provider's own audit log. Credentials are recorded by NAME
// only and their values are never read.
// argus:identifiers:begin
const IDENTIFIERS: [string, string][] = [
  ["AWS_PROFILE", "aws.profile"],
  ["AWS_DEFAULT_PROFILE", "aws.profile"],
  ["AWS_REGION", "aws.region"],
  ["AWS_DEFAULT_REGION", "aws.region"],
  ["AWS_ROLE_ARN", "aws.role_arn"],
  ["AWS_ROLE_SESSION_NAME", "aws.role_session_name"],
  ["AWS_ACCOUNT_ID", "aws.account_id"],
  ["AWS_ACCESS_KEY_ID", "aws.access_key_id"],
  ["AWS_WEB_IDENTITY_TOKEN_FILE", "aws.web_identity_token_file"],
  ["AWS_CONTAINER_CREDENTIALS_FULL_URI", "aws.container_creds_uri"],
  ["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "aws.container_creds_uri"],
  ["AZURE_TENANT_ID", "azure.tenant_id"],
  ["AZURE_CLIENT_ID", "azure.client_id"],
  ["AZURE_SUBSCRIPTION_ID", "azure.subscription_id"],
  ["AZURE_FEDERATED_TOKEN_FILE", "azure.federated_token_file"],
  ["ARM_TENANT_ID", "azure.tenant_id"],
  ["ARM_CLIENT_ID", "azure.client_id"],
  ["ARM_SUBSCRIPTION_ID", "azure.subscription_id"],
  ["GOOGLE_CLOUD_PROJECT", "gcp.project"],
  ["GCLOUD_PROJECT", "gcp.project"],
  ["CLOUDSDK_CORE_PROJECT", "gcp.project"],
  ["GOOGLE_CLOUD_QUOTA_PROJECT", "gcp.quota_project"],
  ["CLOUDSDK_CORE_ACCOUNT", "gcp.account"],
  ["GOOGLE_APPLICATION_CREDENTIALS", "gcp.credentials_file"],
  ["KUBECONFIG", "k8s.kubeconfig"],
  ["KUBERNETES_SERVICE_HOST", "k8s.api_host"],
  ["KUBE_CONTEXT", "k8s.context"],
  ["VAULT_ADDR", "vault.addr"],
  ["VAULT_NAMESPACE", "vault.namespace"],
  ["CLOUDFLARE_ACCOUNT_ID", "cloudflare.account_id"],
  ["DIGITALOCEAN_CONTEXT", "digitalocean.context"],
  ["DOPPLER_PROJECT", "doppler.project"],
  ["GITHUB_REPOSITORY", "github.repository"],
  ["GH_HOST", "github.host"],
  ["GITHUB_ACTOR", "github.actor"],
];
// argus:identifiers:end
// argus:markers:begin
const CREDENTIAL_MARKERS = [
  "TOKEN",
  "SECRET",
  "PASSWORD",
  "PASSWD",
  "API_KEY",
  "APIKEY",
  "ACCESS_KEY",
  "PRIVATE_KEY",
  "CREDENTIALS",
  "SESSION_KEY",
];
// argus:markers:end

// The identifying settings read out of the files those variables point at —
// `~/.aws/config`, which is where a profile's role actually lives, and the
// gcloud application-default credentials. Pinned to `AWS_PROFILE_KEYS` and
// `GCP_ADC_KEYS` in src/cloudid.rs by the same test. Never `~/.aws/credentials`,
// and never a key from an ADC document that is not on this list.
// argus:aws-profile:begin
const AWS_PROFILE_KEYS: [string, string][] = [
  ["role_arn", "aws.role_arn"],
  ["role_session_name", "aws.role_session_name"],
  ["sso_account_id", "aws.account_id"],
  ["sso_role_name", "aws.sso_role_name"],
  ["region", "aws.region"],
];
// argus:aws-profile:end
// argus:gcp-adc:begin
const GCP_ADC_KEYS: [string, string][] = [
  ["client_email", "gcp.account"],
  ["project_id", "gcp.project"],
  ["quota_project_id", "gcp.quota_project"],
  ["type", "gcp.credentials_type"],
];
// argus:gcp-adc:end

// Matches MAX_IDENTITY_FILE_BYTES in src/cloudid.rs.
const MAX_IDENTITY_FILE_BYTES = 256 * 1024;

function readCapped(path: string): string | null {
  let fd: number | null = null;
  try {
    fd = openSync(path, "r");
    const buf = Buffer.alloc(MAX_IDENTITY_FILE_BYTES);
    const read = readSync(fd, buf, 0, MAX_IDENTITY_FILE_BYTES, 0);
    return buf.subarray(0, read).toString("utf8");
  } catch {
    // A file that is absent, unreadable, or a directory is silence.
    return null;
  } finally {
    if (fd !== null) try { closeSync(fd); } catch {}
  }
}

function awsProfileAttrs(text: string, profile: string): [string, string][] {
  const wanted = profile === "default" ? "default" : `profile ${profile}`;
  const found: [string, string][] = [];
  let inSection = false;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line.startsWith("#") || line.startsWith(";")) continue;
    if (line.startsWith("[") && line.endsWith("]")) {
      inSection = line.slice(1, -1).split(/\s+/).join(" ") === wanted;
      continue;
    }
    if (!inSection) continue;
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    if (!value) continue;
    const hit = AWS_PROFILE_KEYS.find(([k]) => k === key);
    if (hit && !found.some(([a]) => a === hit[1])) found.push([hit[1], value]);
  }
  return found;
}

function gcpAdcAttrs(text: string): [string, string][] {
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(text);
  } catch {
    return [];
  }
  if (!doc || typeof doc !== "object") return [];
  const found: [string, string][] = [];
  for (const [key, attribute] of GCP_ADC_KEYS) {
    const value = doc[key];
    // Strings only: a field that is an object is not an identity.
    if (typeof value === "string" && value) found.push([attribute, value]);
  }
  return found;
}

function homeDir(): string {
  return (
    process.env.ARGUS_HOME ||
    process.env.HOME ||
    process.env.USERPROFILE ||
    "."
  );
}

function awsConfigPath(home: string): string {
  return process.env.AWS_CONFIG_FILE || `${home}/.aws/config`;
}

function gcpAdcPath(home: string): string {
  const adc = "application_default_credentials.json";
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS)
    return process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (process.env.CLOUDSDK_CONFIG)
    return `${process.env.CLOUDSDK_CONFIG}/${adc}`;
  if (process.platform === "win32" && process.env.APPDATA)
    return `${process.env.APPDATA}\\gcloud\\${adc}`;
  return `${home}/.config/gcloud/${adc}`;
}

// The environment always wins: a variable is what this process was told, a file
// is only what an SDK would resolve from it.
function enrichFromFiles(id: CloudIdentity): void {
  const home = homeDir();
  const awsConfig = readCapped(awsConfigPath(home));
  if (awsConfig !== null) {
    const profile = id.attributes["aws.profile"] ?? "default";
    for (const [attribute, value] of awsProfileAttrs(awsConfig, profile))
      if (!(attribute in id.attributes)) id.attributes[attribute] = value;
  }
  const adc = readCapped(gcpAdcPath(home));
  if (adc !== null)
    for (const [attribute, value] of gcpAdcAttrs(adc))
      if (!(attribute in id.attributes)) id.attributes[attribute] = value;
}

type CloudIdentity = {
  attributes: Record<string, string>;
  credentials: string[];
};
let identity: CloudIdentity | null = null;

// Computed once per host process: a plugin host is long-lived and its
// environment was fixed when the agent started it, so recomputing per event
// would walk the whole environment thousands of times for the same answer.
function cloudIdentity(): CloudIdentity {
  if (identity) return identity;
  const env = process.env;
  const id: CloudIdentity = { attributes: {}, credentials: [] };
  const claimed = new Set(IDENTIFIERS.map(([name]) => name));
  // In the allowlist's declared order rather than the environment's, so an
  // alias never displaces the variable the SDK itself prefers.
  for (const [name, attribute] of IDENTIFIERS) {
    const value = env[name];
    // An exported-but-empty variable is not an identity: `AWS_PROFILE=` means
    // no profile is set, and recording it would report one that is not.
    if (value && !(attribute in id.attributes)) id.attributes[attribute] = value;
  }
  // Sorted, to match the Rust side and so one environment does not look like
  // two because the host enumerated it differently.
  for (const name of Object.keys(env).sort()) {
    if (claimed.has(name) || !env[name]) continue;
    const upper = name.toUpperCase();
    if (CREDENTIAL_MARKERS.some((m) => upper.includes(m)))
      id.credentials.push(name);
  }
  // Its own guard, not `send`'s: the whole body of `send` is one try/catch, so
  // a filesystem error thrown here would drop the event rather than lose an
  // attribute. Reading the files is best-effort; reporting the event is not.
  try {
    enrichFromFiles(id);
  } catch {
    // an identity from the environment alone is still an identity
  }
  identity = id;
  return id;
}

export function send(source: string, payload: Record<string, unknown>): void {
  try {
    const raw = JSON.stringify(payload);
    const frame =
      JSON.stringify({
        source,
        received_at: new Date().toISOString(),
        cloud_identity: cloudIdentity(),
        payload,
      }) + "\n";
    if (!sendViaSocket(frame)) sendViaSpawn(source, raw);
  } catch {
    // never throw into the host tool
  }
}
