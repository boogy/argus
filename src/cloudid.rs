//! Which cloud identity an agent was holding when it acted.
//!
//! Everything else argus records answers "what did the agent do". This answers
//! "as whom" — the AWS role it had assumed, the Azure subscription, the GCP
//! project, the Kubernetes cluster. An agent that ran `terraform apply` is one
//! fact; an agent that ran it as `arn:aws:iam::…:role/prod-admin` is the fact
//! an incident is actually reconstructed from, and nothing in a hook payload
//! carries it. The environment does, because the hook shim is spawned by the
//! agent and inherits it.
//!
//! # What is and is not read
//!
//! Two disjoint kinds of variable, and the split is the whole design:
//!
//! * **Identifiers** — an explicit allowlist, captured *by value*. Every one
//!   is something that already appears in the provider's own audit log: a role
//!   ARN, an account id, a project, a profile name, an access key id. Knowing
//!   them tells you who the agent was; none of them authenticates as anyone.
//! * **Credentials** — everything whose *name* says it holds secret material.
//!   Only the name is recorded, and the value is never read at all. The fact
//!   worth having is "this session had a `GITHUB_TOKEN` in scope", and that
//!   costs nothing to know.
//!
//! Anything matching neither is ignored. An agent's environment on a
//! developer's machine holds their whole shell, and a monitoring tool that
//! shipped it wholesale would be the largest thing it had to defend.
//!
//! The allowlist is deliberately not exhaustive — it cannot be, and a
//! catch-all heuristic over values is exactly what must not exist here. A
//! provider it does not know yet is a missing attribute, never a leaked one.
//!
//! # The files behind the variables
//!
//! `AWS_PROFILE=prod` says which profile, not which role: that lives in
//! `~/.aws/config` under `[profile prod]`, and gcloud's application-default
//! credentials name the service account the same way. Those two files are read
//! as well, under the same rule — the identifying fields, never a credential.
//! `~/.aws/credentials`, the file holding the secret access key, is never
//! opened at all. The reads are bounded and silent on failure, because they
//! happen in the hook shim while the agent waits.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// `(variable, attribute)`. Several variables map to one attribute where a
/// provider offers aliases; first hit in this order wins, which follows each
/// SDK's own precedence (`AWS_PROFILE` over `AWS_DEFAULT_PROFILE`, and so on).
const IDENTIFIERS: &[(&str, &str)] = &[
    // ---- AWS -------------------------------------------------------------
    ("AWS_PROFILE", "aws.profile"),
    ("AWS_DEFAULT_PROFILE", "aws.profile"),
    // `aws-vault exec prod` names the profile here and nowhere else.
    ("AWS_VAULT", "aws.profile"),
    ("AWS_REGION", "aws.region"),
    ("AWS_DEFAULT_REGION", "aws.region"),
    ("AWS_ROLE_ARN", "aws.role_arn"),
    ("AWS_ROLE_SESSION_NAME", "aws.role_session_name"),
    ("AWS_ACCOUNT_ID", "aws.account_id"),
    // The public half of the key pair. It is what CloudTrail records against
    // every call, so it is the join key between an argus event and the
    // provider's own log — and it authenticates nothing without the secret,
    // which this module never reads.
    ("AWS_ACCESS_KEY_ID", "aws.access_key_id"),
    // When the session keys above stop working — a timestamp, not a secret.
    // `aws-vault exec` and `aws configure export-credentials` set the first;
    // older aws-vault the second.
    ("AWS_CREDENTIAL_EXPIRATION", "aws.credentials_expire_at"),
    ("AWS_SESSION_EXPIRATION", "aws.credentials_expire_at"),
    // A path, not a token. Whether the agent was using web identity
    // federation at all is the fact; the file's contents are not read.
    ("AWS_WEB_IDENTITY_TOKEN_FILE", "aws.web_identity_token_file"),
    (
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "aws.container_creds_uri",
    ),
    (
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "aws.container_creds_uri",
    ),
    // ---- Azure -----------------------------------------------------------
    ("AZURE_TENANT_ID", "azure.tenant_id"),
    ("AZURE_CLIENT_ID", "azure.client_id"),
    ("AZURE_SUBSCRIPTION_ID", "azure.subscription_id"),
    ("AZURE_FEDERATED_TOKEN_FILE", "azure.federated_token_file"),
    // Terraform's azurerm provider reads its own spellings, and an agent
    // running terraform is exactly the case this exists for.
    ("ARM_TENANT_ID", "azure.tenant_id"),
    ("ARM_CLIENT_ID", "azure.client_id"),
    ("ARM_SUBSCRIPTION_ID", "azure.subscription_id"),
    // ---- Google Cloud ----------------------------------------------------
    ("GOOGLE_CLOUD_PROJECT", "gcp.project"),
    ("GCLOUD_PROJECT", "gcp.project"),
    ("CLOUDSDK_CORE_PROJECT", "gcp.project"),
    ("GOOGLE_CLOUD_QUOTA_PROJECT", "gcp.quota_project"),
    ("CLOUDSDK_CORE_ACCOUNT", "gcp.account"),
    // The application-default credentials *path*. Its contents are a private
    // key; the path says which identity file was in play.
    ("GOOGLE_APPLICATION_CREDENTIALS", "gcp.credentials_file"),
    // ---- Kubernetes ------------------------------------------------------
    ("KUBECONFIG", "k8s.kubeconfig"),
    ("KUBERNETES_SERVICE_HOST", "k8s.api_host"),
    ("KUBE_CONTEXT", "k8s.context"),
    // ---- HashiCorp Vault -------------------------------------------------
    ("VAULT_ADDR", "vault.addr"),
    ("VAULT_NAMESPACE", "vault.namespace"),
    // ---- Other providers an agent commonly holds -------------------------
    ("CLOUDFLARE_ACCOUNT_ID", "cloudflare.account_id"),
    ("DIGITALOCEAN_CONTEXT", "digitalocean.context"),
    ("DOPPLER_PROJECT", "doppler.project"),
    ("GITHUB_REPOSITORY", "github.repository"),
    ("GH_HOST", "github.host"),
    ("GITHUB_ACTOR", "github.actor"),
];

/// Substrings that make a variable name a claim to hold secret material.
///
/// Matched case-insensitively against the name and nothing else. Deliberately
/// specific rather than broad: a bare `AUTH` would classify `SSH_AUTH_SOCK`
/// (a socket path) as a credential, and a bare `KEY` would catch every
/// `*_KEY_ID` and every keyboard setting. The cost of a miss here is one
/// unnamed credential; the cost of matching everything is a list nobody reads.
const CREDENTIAL_MARKERS: &[&str] = &[
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

/// Who the agent was, and what it was carrying, at one moment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudIdentity {
    /// Non-secret identifiers, keyed by the attribute name they export under.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
    /// Names of variables holding credential material, sorted. Names only —
    /// no value from this list is ever read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<String>,
}

impl CloudIdentity {
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty() && self.credentials.is_empty()
    }
}

/// Classify one variable name. Split out so the policy can be asserted per
/// name, without building an environment for each case.
fn is_credential_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    CREDENTIAL_MARKERS.iter().any(|m| upper.contains(m))
}

/// Read an identity out of an environment.
///
/// Takes the variables rather than reading the process's own, so the classifier
/// is testable against an environment no test has to install into the process
/// it is running in — these tests would otherwise have to mutate global state
/// and could not describe a machine other than the one running them.
///
/// Empty values are skipped throughout: `AWS_PROFILE=` is a variable a shell
/// exported and left blank, and recording it as an identity would be reporting
/// a profile that is not set.
pub fn from_vars<K, V>(vars: impl IntoIterator<Item = (K, V)>) -> CloudIdentity
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    // Collected first, and walked in the allowlist's order rather than the
    // environment's: `std::env::vars` has no defined order, so resolving
    // aliases as they arrive would pick `AWS_PROFILE` or `AWS_DEFAULT_PROFILE`
    // differently on different machines — or on the same one twice.
    let env: BTreeMap<String, String> = vars
        .into_iter()
        .map(|(k, v)| (k.as_ref().to_string(), v.as_ref().to_string()))
        .filter(|(_, v)| !v.is_empty())
        .collect();

    let mut id = CloudIdentity::default();
    for (var, attribute) in IDENTIFIERS {
        if let Some(value) = env.get(*var) {
            id.attributes
                .entry((*attribute).to_string())
                .or_insert_with(|| value.clone());
        }
    }
    // Sorted, because `env` is: a list that reorders between two events makes
    // the same environment look like two.
    for name in env.keys() {
        // The allowlist wins outright, so a name that is both an identifier
        // and marker-matching — `AWS_ACCESS_KEY_ID` is the case that matters —
        // is recorded as what it is rather than reduced to a name.
        if IDENTIFIERS.iter().any(|(var, _)| var == name) {
            continue;
        }
        if is_credential_name(name) {
            id.credentials.push(name.clone());
        }
    }
    id
}

/// Identifying settings of one AWS shared-config profile.
///
/// `AWS_PROFILE=prod` says which profile, not which role — the role lives in
/// `~/.aws/config` under `[profile prod]`, and an agent that assumed it through
/// a profile would otherwise be recorded with no role at all. Same rule as the
/// environment allowlist: every key here is one the provider logs against the
/// call it authorizes.
///
/// The *config* file only. `~/.aws/credentials` is the file holding
/// `aws_secret_access_key`, and nothing in argus opens it.
// argus:aws-profile:begin
const AWS_PROFILE_KEYS: &[(&str, &str)] = &[
    ("role_arn", "aws.role_arn"),
    ("role_session_name", "aws.role_session_name"),
    ("sso_account_id", "aws.account_id"),
    // The permission set the SSO login grants — "which role in that account",
    // for the profiles that name a role no other way.
    ("sso_role_name", "aws.sso_role_name"),
    ("region", "aws.region"),
];
// argus:aws-profile:end

/// Identifying fields of a Google application-default-credentials file.
///
/// The file also holds a private key or a refresh token. They are not on this
/// list, so they are not read out of the parsed document and cannot reach an
/// event — see [`gcp_adc_attrs`], which copies these keys and nothing else.
// argus:gcp-adc:begin
const GCP_ADC_KEYS: &[(&str, &str)] = &[
    ("client_email", "gcp.account"),
    ("project_id", "gcp.project"),
    ("quota_project_id", "gcp.quota_project"),
    // `service_account`, `authorized_user`, `external_account`: whether the
    // agent was acting as a robot, as a person, or through federation.
    ("type", "gcp.credentials_type"),
];
// argus:gcp-adc:end

/// Ceiling on an identity file. A shared config is a few kilobytes and an ADC
/// document is a few hundred bytes; anything past this is not one of them, and
/// the read happens on the hook path where the agent is waiting.
const MAX_IDENTITY_FILE_BYTES: u64 = 256 * 1024;

fn read_capped(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut buf = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_IDENTITY_FILE_BYTES)
        .read_to_end(&mut buf)
        .ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// The `key = value` settings of one section of an AWS shared config, in
/// file order, blank values dropped.
///
/// A deliberately small INI reader rather than a dependency: the file's own
/// format is `[profile name]` for every profile but `[default]`, nested
/// settings are indented under a parent key, and both `#` and `;` start a
/// comment. Callers look up named keys only — including never a nested one —
/// so the parse cannot be widened by what a file happens to contain.
fn ini_section<'a>(text: &'a str, wanted: &str) -> Vec<(&'a str, &'a str)> {
    let mut in_section = false;
    let mut found = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            // Section names are whitespace-normalised: `[profile  prod]` and
            // `[profile prod]` are the same profile to the SDK.
            in_section = name.split_whitespace().collect::<Vec<_>>().join(" ") == wanted;
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if !value.is_empty() {
            found.push((key, value));
        }
    }
    found
}

fn profile_section(profile: &str) -> String {
    if profile == "default" {
        "default".to_string()
    } else {
        format!("profile {profile}")
    }
}

/// Pull one profile's identifying settings out of an AWS shared config.
fn aws_profile_attrs(text: &str, profile: &str) -> Vec<(&'static str, String)> {
    let mut found: Vec<(&'static str, String)> = Vec::new();
    for (key, value) in ini_section(text, &profile_section(profile)) {
        if let Some((_, attribute)) = AWS_PROFILE_KEYS.iter().find(|(k, _)| *k == key)
            && !found.iter().any(|(a, _)| *a == *attribute)
        {
            // First occurrence wins, matching the SDK: a key repeated inside
            // one section is not two identities.
            found.push((attribute, value.to_string()));
        }
    }
    found
}

/// The IAM Identity Center start URL a profile logs in through, if it is an
/// SSO profile at all: its own `sso_start_url` (legacy), or the one of the
/// `[sso-session name]` its `sso_session` points at.
fn sso_start_url(text: &str, profile: &str) -> Option<String> {
    let first = |section: &[(&str, &str)], key: &str| {
        section
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    };
    let section = ini_section(text, &profile_section(profile));
    match first(&section, "sso_session") {
        Some(session) => first(
            &ini_section(text, &format!("sso-session {session}")),
            "sso_start_url",
        ),
        None => first(&section, "sso_start_url"),
    }
}

/// The two fields of an SSO token cache entry this module needs. Every other
/// field — `accessToken`, `refreshToken`, `clientSecret` — is not named here,
/// so serde skips over it without ever building a value for it.
#[derive(Deserialize)]
struct SsoCacheEntry {
    #[serde(rename = "startUrl")]
    start_url: Option<String>,
    #[serde(rename = "expiresAt")]
    expires_at: Option<String>,
}

/// Ceiling on the files looked at in the SSO cache. A developer has one entry
/// per start URL and a client registration or two; this only bounds the walk.
const MAX_SSO_CACHE_ENTRIES: usize = 64;

/// When the cached SSO login for `start_url` stops working, if one exists and
/// has not already.
///
/// The cache files are named by a SHA-1 of the session name or the URL; the
/// directory is walked and each entry matched on its own `startUrl` instead,
/// which needs no hash and finds both spellings. Only the access token's
/// expiry is checked: a lapsed one that an `sso-session` could still refresh
/// silently reads as not working until the next AWS call refreshes the file.
fn sso_login_expiry(
    cache_dir: &Path,
    start_url: &str,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    std::fs::read_dir(cache_dir)
        .ok()?
        .filter_map(Result::ok)
        .take(MAX_SSO_CACHE_ENTRIES)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter_map(|p| serde_json::from_str::<SsoCacheEntry>(&read_capped(&p)?).ok())
        .filter(|e| e.start_url.as_deref() == Some(start_url))
        .filter_map(|e| parse_expiry(&e.expires_at?))
        .filter(|at| *at > now)
        .max()
}

/// RFC 3339, plus the `2019-01-01T00:00:00UTC` spelling older CLIs wrote.
fn parse_expiry(raw: &str) -> Option<DateTime<Utc>> {
    let raw = raw
        .strip_suffix("UTC")
        .map_or(raw.to_string(), |r| format!("{r}Z"));
    DateTime::parse_from_rfc3339(&raw)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// How the agent's environment hands an SDK AWS credentials directly, if it
/// does — the first stops of the SDK's chain, ahead of any profile. Read off
/// what [`from_vars`] already collected: the secret by name only.
fn env_credentials_source(id: &CloudIdentity) -> Option<&'static str> {
    if id.attributes.contains_key("aws.access_key_id")
        && id.credentials.iter().any(|c| c == "AWS_SECRET_ACCESS_KEY")
    {
        Some("env")
    } else if id.attributes.contains_key("aws.web_identity_token_file") {
        Some("web_identity")
    } else if id.attributes.contains_key("aws.container_creds_uri") {
        Some("container")
    } else {
        None
    }
}

/// Pull the identifying fields out of an ADC document.
fn gcp_adc_attrs(text: &str) -> Vec<(&'static str, String)> {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(text) else {
        return vec![];
    };
    GCP_ADC_KEYS
        .iter()
        .filter_map(|(key, attribute)| {
            // `as_str` and not `to_string`: a field that is an object — the
            // `service_account_impersonation` block, say — is not an identity
            // and must not be flattened into one.
            let value = doc.get(*key)?.as_str()?;
            (!value.is_empty()).then(|| (*attribute, value.to_string()))
        })
        .collect()
}

/// Fill in what the environment named but did not say.
///
/// The environment always wins: a variable is what the agent's own process was
/// told, while a file is what an SDK *would* resolve from it. Where both
/// answer, the first is the stronger claim.
///
/// AWS settings from the shared config are only reported alongside a
/// credential the agent could actually sign with, recorded as
/// `aws.credentials_source`. A profile is not a credential: `[default]` naming
/// an account says nothing about whether the agent held a login to it, and
/// reporting it anyway puts every developer with a configured profile in every
/// account it names.
fn enrich_from_files(
    id: &mut CloudIdentity,
    aws_config: Option<&Path>,
    sso_cache: Option<&Path>,
    gcp_adc: Option<&Path>,
    now: DateTime<Utc>,
) {
    enrich_aws(id, aws_config, sso_cache, now);
    if let Some(path) = gcp_adc
        && let Some(text) = read_capped(path)
    {
        for (attribute, value) in gcp_adc_attrs(&text) {
            id.attributes.entry(attribute.to_string()).or_insert(value);
        }
    }
}

fn enrich_aws(
    id: &mut CloudIdentity,
    aws_config: Option<&Path>,
    sso_cache: Option<&Path>,
    now: DateTime<Utc>,
) {
    let config = aws_config.and_then(read_capped);
    let named = id.attributes.get("aws.profile").cloned();
    let fill = |id: &mut CloudIdentity, attrs: Vec<(&'static str, String)>| {
        for (attribute, value) in attrs {
            id.attributes.entry(attribute.to_string()).or_insert(value);
        }
    };

    if let Some(source) = env_credentials_source(id) {
        // Present but lapsed is not working, and the SDK will not fall back to
        // a profile behind it either: the env keys win the chain and fail.
        let lapsed = id
            .attributes
            .get("aws.credentials_expire_at")
            .and_then(|raw| parse_expiry(raw))
            .is_some_and(|at| at <= now);
        if lapsed {
            return;
        }
        id.attributes
            .insert("aws.credentials_source".into(), source.into());
        // A *named* profile says which role these keys were minted for —
        // `aws-vault exec prod` sets `AWS_VAULT=prod`. `[default]` says no
        // such thing about keys that came from somewhere else.
        if let (Some(profile), Some(text)) = (named, config.as_deref()) {
            fill(id, aws_profile_attrs(text, &profile));
        }
        return;
    }

    // `default` when nothing named a profile, because that is the profile an
    // SDK in this environment would use.
    let profile = named.clone().unwrap_or_else(|| "default".into());
    let Some(text) = config.as_deref() else {
        return;
    };
    if let Some(expires) = sso_cache
        .zip(sso_start_url(text, &profile))
        .and_then(|(cache, url)| sso_login_expiry(cache, &url, now))
    {
        fill(id, aws_profile_attrs(text, &profile));
        id.attributes
            .insert("aws.credentials_source".into(), "sso".into());
        id.attributes
            .entry("aws.credentials_expire_at".into())
            .or_insert_with(|| expires.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        return;
    }
    // A `credential_process` (aws-vault's `export`, most often) mints keys on
    // demand, so there is nothing on disk to confirm — the claim is weaker:
    // "this profile gets credentials without asking anyone". Only for a
    // profile the environment *named*: that someone chose it for this
    // session is the evidence, and `[default]` carries none.
    if named.is_some()
        && ini_section(text, &profile_section(&profile))
            .iter()
            .any(|(k, _)| *k == "credential_process")
    {
        fill(id, aws_profile_attrs(text, &profile));
        id.attributes
            .insert("aws.credentials_source".into(), "credential_process".into());
    }
    // Static keys in `~/.aws/credentials`, an assumed role's CLI cache: none
    // can be confirmed without opening a secret, so none is claimed.
}

/// How a shell command chose an AWS profile for itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileVia {
    /// `aws --profile prod`, `aws-vault exec prod`: outranks every variable.
    Explicit,
    /// `AWS_PROFILE=prod terraform plan`, `export AWS_PROFILE=prod`: loses to
    /// env keys, exactly as `AWS_PROFILE` does in the agent's own environment.
    Variable,
}

/// `aws-vault` flags that take a separate value, so the profile is not
/// mistaken for one. `--flag=value` needs no entry.
// ponytail: the common flags only; an unlisted one shifts the profile by one
// token, so add it here when a real command shows it.
const AWS_VAULT_VALUE_FLAGS: &[&str] = &[
    "-d",
    "--duration",
    "-t",
    "--mfa-token",
    "--region",
    "--prompt",
    "--backend",
    "--keychain",
    "--config",
];

/// The AWS profiles a shell command selects, in order.
///
/// The environment says which profile the agent's process *could* use; a
/// command that names one says which profile this call *did* ask for — the
/// only evidence there is for a profile whose credentials come from a
/// `credential_process`, an aws-vault keychain or anything else with no file
/// to check. Same restraint as [`crate::adapters::net::command_hosts`]: three
/// spellings, each unambiguous, and nothing guessed from the rest.
fn command_profiles(command: &str) -> Vec<(String, ProfileVia)> {
    let mut out = Vec::new();
    let mut seg: Vec<&str> = Vec::new();
    for raw in command.split_whitespace() {
        let token = raw.trim_matches(|c: char| "'\"`".contains(c));
        if crate::adapters::net::COMMAND_SEPARATORS.contains(&token) {
            segment_profiles(&seg, &mut out);
            seg.clear();
        } else {
            seg.push(token);
        }
    }
    segment_profiles(&seg, &mut out);
    out
}

fn segment_profiles(seg: &[&str], out: &mut Vec<(String, ProfileVia)>) {
    let mut rest = seg.iter().copied();
    let mut push = |p: &str, via| {
        if !p.is_empty() {
            out.push((p.to_string(), via));
        }
    };
    // Leading assignments and wrappers, up to the program itself.
    let program = loop {
        let Some(token) = rest.next() else { return };
        if let Some(p) = token.strip_prefix("AWS_PROFILE=") {
            push(p, ProfileVia::Variable);
            continue;
        }
        let bare = token
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(token)
            .trim_end_matches(".exe");
        if token.contains('=') || ["sudo", "env", "time", "export"].contains(&bare) {
            continue;
        }
        break bare;
    };
    let args: Vec<&str> = rest.collect();
    match program {
        "aws" => {
            let mut it = args.iter();
            while let Some(a) = it.next() {
                if let Some(p) = a.strip_prefix("--profile=") {
                    push(p, ProfileVia::Explicit);
                } else if *a == "--profile"
                    && let Some(p) = it.next()
                {
                    push(p, ProfileVia::Explicit);
                }
            }
        }
        "aws-vault" => {
            // `aws-vault [global flags] exec|export|login [flags] PROFILE [-- cmd]`.
            let Some(sub) = args
                .iter()
                .position(|a| ["exec", "export", "login"].contains(a))
            else {
                return;
            };
            let mut it = args[sub + 1..].iter();
            while let Some(a) = it.next() {
                if *a == "--" {
                    break;
                }
                if AWS_VAULT_VALUE_FLAGS.contains(a) {
                    it.next();
                } else if !a.starts_with('-') {
                    push(a, ProfileVia::Explicit);
                    break;
                }
            }
            // Whatever runs after `--` is a command of its own, and may name a
            // profile too.
            if let Some(dash) = args.iter().position(|a| *a == "--") {
                segment_profiles(&args[dash + 1..], out);
            }
        }
        _ => {}
    }
}

/// Re-point one tool call's AWS identity at the profile its command named.
///
/// The environment's AWS attributes describe a different credential from the
/// one the call asked for, so they are replaced rather than merged: an event
/// that said "env keys for staging" and "--profile prod" at once would answer
/// the incident question both ways. Several distinct profiles in one command
/// are all named, but none is resolved — which account a given half of the
/// pipeline acted in is not something the record can say.
///
/// `aws.credentials_source = command` claims what the agent asked for, not that
/// the call succeeded; the tool result beside it says that.
pub fn apply_command_profiles(id: &mut CloudIdentity, commands: &[String]) {
    apply_command_profiles_from(id, commands, &aws_config_path(&crate::install::home()));
}

fn apply_command_profiles_from(id: &mut CloudIdentity, commands: &[String], aws_config: &Path) {
    let env_keys = id
        .attributes
        .get("aws.credentials_source")
        .map(String::as_str)
        == Some("env");
    let mut chosen: Vec<String> = Vec::new();
    for (profile, via) in commands.iter().flat_map(|c| command_profiles(c)) {
        if via == ProfileVia::Variable && env_keys {
            continue;
        }
        if !chosen.contains(&profile) {
            chosen.push(profile);
        }
    }
    if chosen.is_empty() {
        return;
    }
    id.attributes.retain(|k, _| !k.starts_with("aws."));
    if let [profile] = chosen.as_slice()
        && let Some(text) = read_capped(aws_config)
    {
        for (attribute, value) in aws_profile_attrs(&text, profile) {
            id.attributes.insert(attribute.to_string(), value);
        }
    }
    id.attributes.insert("aws.profile".into(), chosen.join(","));
    id.attributes
        .insert("aws.credentials_source".into(), "command".into());
}

/// Where the AWS SDKs look for the shared config, in their own order.
fn aws_config_path(home: &Path) -> PathBuf {
    std::env::var_os("AWS_CONFIG_FILE")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".aws").join("config"))
}

/// Where gcloud writes application-default credentials.
///
/// `GOOGLE_APPLICATION_CREDENTIALS` first because every Google SDK honours it,
/// then `CLOUDSDK_CONFIG`, then the well-known location — the file `gcloud auth
/// application-default login` writes, which is what an agent on a developer's
/// machine is actually holding.
fn gcp_adc_path(home: &Path) -> PathBuf {
    const ADC: &str = "application_default_credentials.json";
    if let Some(explicit) = std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
    {
        return explicit;
    }
    if let Some(dir) = std::env::var_os("CLOUDSDK_CONFIG").filter(|v| !v.is_empty()) {
        return PathBuf::from(dir).join(ADC);
    }
    if cfg!(windows)
        && let Some(appdata) = std::env::var_os("APPDATA")
    {
        return PathBuf::from(appdata).join("gcloud").join(ADC);
    }
    home.join(".config").join("gcloud").join(ADC)
}

/// The identity of the process this is called in.
///
/// Called from the hook shim, which the host agent spawned and which therefore
/// holds the agent's environment. Nothing calls it in the daemon: the daemon
/// is a long-lived process started from somewhere else entirely, and its
/// environment describes whoever started it rather than any agent.
///
/// Two file reads at most, both short and both on a path an SDK in this same
/// environment would read. A machine with neither file pays two failed opens
/// per hook, against a process spawn that already cost milliseconds.
pub fn current() -> CloudIdentity {
    let mut id = from_vars(std::env::vars());
    let home = crate::install::home();
    enrich_from_files(
        &mut id,
        Some(&aws_config_path(&home)),
        // Fixed by the SDKs: `AWS_CONFIG_FILE` does not move it.
        Some(&home.join(".aws").join("sso").join("cache")),
        Some(&gcp_adc_path(&home)),
        Utc::now(),
    );
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(pairs: &[(&str, &str)]) -> CloudIdentity {
        from_vars(pairs.iter().copied())
    }

    #[test]
    fn a_secret_value_is_never_carried_off_the_machine() {
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let id = ids(&[
            ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
            ("AWS_SECRET_ACCESS_KEY", secret),
            ("AWS_SESSION_TOKEN", "FwoGZXIvYXdzEDESAMPLE"),
            ("GITHUB_TOKEN", "ghp_reallysecret"),
            ("AZURE_CLIENT_SECRET", "azure-secret"),
        ]);
        let rendered = serde_json::to_string(&id).unwrap();
        for leaked in [
            secret,
            "FwoGZXIvYXdzEDESAMPLE",
            "ghp_reallysecret",
            "azure-secret",
        ] {
            assert!(
                !rendered.contains(leaked),
                "a credential value reached the wire: {rendered}"
            );
        }
        // Named, so an investigation knows what the session had in scope.
        assert_eq!(
            id.credentials,
            vec![
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AZURE_CLIENT_SECRET",
                "GITHUB_TOKEN"
            ]
        );
        // And the public half of the AWS pair is kept: it is the join key to
        // CloudTrail, and it is on the allowlist despite matching ACCESS_KEY.
        assert_eq!(
            id.attributes.get("aws.access_key_id").map(String::as_str),
            Some("AKIAIOSFODNN7EXAMPLE")
        );
    }

    /// Allowlist entries whose *name* matches a credential marker while their
    /// *value* is not secret material. Each is here because the value is
    /// already public — a key id the provider logs against every call, a path,
    /// or a metadata endpoint — and each one had to be argued for individually.
    /// Anything not on this list that matches a marker is a mistake.
    const NAMED_LIKE_A_SECRET_BUT_PUBLIC: &[&str] = &[
        // The public half of a key pair; CloudTrail records it on every call.
        "AWS_ACCESS_KEY_ID",
        // Filesystem paths to a token, not the token.
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AZURE_FEDERATED_TOKEN_FILE",
        "GOOGLE_APPLICATION_CREDENTIALS",
        // The address of the container credential endpoint. The bearer token
        // for it lives in AWS_CONTAINER_AUTHORIZATION_TOKEN, which is not on
        // the allowlist and so is recorded by name only.
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    ];

    #[test]
    fn every_allowlisted_identifier_is_public_by_name() {
        // The allowlist is the one place a value escapes, so nothing on it may
        // be a variable whose name says it is secret unless it was reviewed
        // and named above. This is the check that catches a future entry added
        // for convenience without that review.
        for (var, _) in IDENTIFIERS {
            if NAMED_LIKE_A_SECRET_BUT_PUBLIC.contains(var) {
                continue;
            }
            assert!(
                !is_credential_name(var),
                "{var} is captured by value but named like a secret"
            );
        }
        // And the exception list may not rot into a blanket suppression: every
        // entry on it must still be an allowlisted identifier that actually
        // trips the marker check.
        for var in NAMED_LIKE_A_SECRET_BUT_PUBLIC {
            assert!(
                IDENTIFIERS.iter().any(|(v, _)| v == var),
                "{var} is exempted but is not on the allowlist"
            );
            assert!(
                is_credential_name(var),
                "{var} needs no exemption; remove it"
            );
        }
    }

    /// The opencode and pi plugins write the envelope themselves and only
    /// spawn the shim as a fallback, so the identity has to be read in
    /// TypeScript too — see the block in `plugins/shared/transport.ts`. Two
    /// copies of a policy is one copy that rots, and the failure mode is
    /// invisible: events keep flowing, from two tools, without the attribute.
    /// So the copies are pinned to each other here.
    #[test]
    fn the_plugin_reads_the_same_environment_the_shim_does() {
        const TRANSPORT: &str = include_str!("../plugins/shared/transport.ts");

        fn block<'a>(name: &str) -> &'a str {
            let after = TRANSPORT
                .split_once(&format!("// argus:{name}:begin"))
                .unwrap_or_else(|| panic!("the {name} block is not marked in transport.ts"))
                .1;
            after
                .split_once(&format!("// argus:{name}:end"))
                .unwrap_or_else(|| panic!("the {name} block is not closed in transport.ts"))
                .0
        }
        // Every quoted string on the line, which is what a `["VAR", "attr"],`
        // entry and a bare `"MARKER",` entry both reduce to.
        fn quoted(line: &str) -> Vec<&str> {
            line.split('"').skip(1).step_by(2).collect()
        }

        fn pairs<'a>(name: &str) -> Vec<(&'a str, &'a str)> {
            block(name)
                .lines()
                .map(quoted)
                .filter(|q| !q.is_empty())
                .map(|q| {
                    assert_eq!(q.len(), 2, "{q:?} is not a (variable, attribute) pair");
                    (q[0], q[1])
                })
                .collect()
        }

        let ts_ids = pairs("identifiers");
        assert_eq!(
            ts_ids,
            IDENTIFIERS.to_vec(),
            "the plugin's allowlist has drifted from the shim's; opencode and pi \
             would report a different identity from every other tool"
        );

        let ts_markers: Vec<&str> = block("markers").lines().flat_map(quoted).collect();
        assert_eq!(ts_markers, CREDENTIAL_MARKERS.to_vec());

        // The file half, pinned the same way and for the same reason: a key
        // added on one side only means opencode and pi resolve a different
        // identity from the same `~/.aws/config`.
        assert_eq!(
            pairs("aws-profile"),
            AWS_PROFILE_KEYS.to_vec(),
            "the plugin reads different settings out of the shared config"
        );
        assert_eq!(
            pairs("gcp-adc"),
            GCP_ADC_KEYS.to_vec(),
            "the plugin reads different fields out of the ADC document"
        );
    }

    #[test]
    fn who_the_agent_was_survives_the_round_trip() {
        let id = ids(&[
            ("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/prod-admin"),
            ("AWS_ACCOUNT_ID", "123456789012"),
            ("AWS_REGION", "eu-west-1"),
            ("AZURE_SUBSCRIPTION_ID", "0000-1111"),
            ("GOOGLE_CLOUD_PROJECT", "my-project"),
            ("KUBERNETES_SERVICE_HOST", "10.0.0.1"),
            ("VAULT_ADDR", "https://vault.internal:8200"),
        ]);
        assert_eq!(
            id.attributes.get("aws.role_arn").map(String::as_str),
            Some("arn:aws:iam::123456789012:role/prod-admin")
        );
        assert_eq!(id.attributes.len(), 7, "{:?}", id.attributes);
        let back: CloudIdentity =
            serde_json::from_str(&serde_json::to_string(&id).unwrap()).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn an_ordinary_shell_contributes_nothing() {
        let id = ids(&[
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/home/dev"),
            ("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock"),
            ("EDITOR", "vim"),
            ("LC_ALL", "en_US.UTF-8"),
            ("XDG_SESSION_TYPE", "wayland"),
        ]);
        assert!(
            id.is_empty(),
            "an unremarkable environment produced identity: {id:?}"
        );
    }

    #[test]
    fn an_exported_but_empty_variable_is_not_an_identity() {
        let id = ids(&[
            ("AWS_PROFILE", ""),
            ("GITHUB_TOKEN", ""),
            ("AWS_REGION", "us-east-1"),
        ]);
        assert_eq!(id.attributes.get("aws.profile"), None, "{id:?}");
        assert!(id.credentials.is_empty(), "{id:?}");
        assert_eq!(id.attributes.len(), 1);
    }

    #[test]
    fn an_alias_does_not_displace_the_variable_the_sdk_prefers() {
        let id = ids(&[
            ("AWS_PROFILE", "prod"),
            ("AWS_DEFAULT_PROFILE", "legacy"),
            ("AWS_DEFAULT_REGION", "us-east-1"),
        ]);
        assert_eq!(
            id.attributes.get("aws.profile").map(String::as_str),
            Some("prod"),
            "the deprecated alias won"
        );
        // …and the alias still answers when it is the only one set.
        assert_eq!(
            id.attributes.get("aws.region").map(String::as_str),
            Some("us-east-1")
        );
    }

    const SHARED_CONFIG: &str = "\
[default]
region = eu-west-1
sso_session = acme

# the profile the agent is using
[profile prod]
role_arn = arn:aws:iam::123456789012:role/prod-admin
sso_start_url = https://prod.awsapps.com/start
sso_account_id = 123456789012
sso_role_name = AdministratorAccess
region = us-east-1
; a nested setting, indented under its parent
s3 =
  addressing_style = path

[profile staging]
role_arn = arn:aws:iam::999999999999:role/staging

[profile vaulted]
credential_process = aws-vault export --format=json vaulted
sso_account_id = 555555555555
region = eu-central-2

[sso-session acme]
sso_start_url = https://acme.awsapps.com/start
";

    /// The clock every liveness test is read against.
    fn now() -> DateTime<Utc> {
        "2026-10-12T12:00:00Z".parse().unwrap()
    }

    const SSO_ACCESS_TOKEN: &str = "aoaAAAAAGdsSSO-access-token-EXAMPLE";

    fn config_file(dir: &std::path::Path, text: &str) -> PathBuf {
        let path = dir.join("config");
        std::fs::write(&path, text).unwrap();
        path
    }

    /// An SSO cache holding one login per `(start_url, expires_at)`, plus the
    /// client registration the CLI keeps beside them, which has no `startUrl`.
    fn sso_cache(dir: &std::path::Path, logins: &[(&str, &str)]) -> PathBuf {
        let cache = dir.join("sso-cache");
        std::fs::create_dir_all(&cache).unwrap();
        for (i, (url, expires)) in logins.iter().enumerate() {
            let entry = serde_json::json!({
                "startUrl": url,
                "region": "eu-west-1",
                "accessToken": SSO_ACCESS_TOKEN,
                "refreshToken": "aorAAAAAGrefresh-EXAMPLE",
                "expiresAt": expires,
            });
            std::fs::write(cache.join(format!("{i:040}.json")), entry.to_string()).unwrap();
        }
        std::fs::write(
            cache.join("botocore-client-id-eu-west-1.json"),
            r#"{"clientId":"id","clientSecret":"client-secret-EXAMPLE","expiresAt":"2099-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        cache
    }

    fn enrich_aws_only(id: &mut CloudIdentity, dir: &std::path::Path, logins: &[(&str, &str)]) {
        let config = config_file(dir, SHARED_CONFIG);
        let cache = sso_cache(dir, logins);
        enrich_from_files(id, Some(&config), Some(&cache), None, now());
    }

    fn attr<'a>(id: &'a CloudIdentity, key: &str) -> Option<&'a str> {
        id.attributes.get(key).map(String::as_str)
    }

    #[test]
    fn a_profile_names_the_role_the_variable_did_not() {
        let dir = tempfile::tempdir().unwrap();
        let mut id = ids(&[("AWS_PROFILE", "prod")]);
        enrich_aws_only(
            &mut id,
            dir.path(),
            &[("https://prod.awsapps.com/start", "2026-10-12T20:00:00Z")],
        );
        assert_eq!(
            attr(&id, "aws.role_arn"),
            Some("arn:aws:iam::123456789012:role/prod-admin"),
            "{:?}",
            id.attributes
        );
        assert_eq!(attr(&id, "aws.account_id"), Some("123456789012"));
        assert_eq!(attr(&id, "aws.sso_role_name"), Some("AdministratorAccess"));
        // The profile the agent named, not the one above it or the one below.
        assert_eq!(attr(&id, "aws.region"), Some("us-east-1"));
        assert_eq!(attr(&id, "aws.credentials_source"), Some("sso"));
        assert_eq!(
            attr(&id, "aws.credentials_expire_at"),
            Some("2026-10-12T20:00:00Z")
        );
    }

    #[test]
    fn no_profile_named_means_the_one_an_sdk_would_use() {
        let dir = tempfile::tempdir().unwrap();
        let mut id = CloudIdentity::default();
        // `[default]` logs in through its `sso-session`, not a URL of its own.
        enrich_aws_only(
            &mut id,
            dir.path(),
            &[("https://acme.awsapps.com/start", "2026-10-12T13:00:00Z")],
        );
        assert_eq!(
            attr(&id, "aws.region"),
            Some("eu-west-1"),
            "an unset AWS_PROFILE is the default profile, not no profile"
        );
        assert_eq!(
            attr(&id, "aws.role_arn"),
            None,
            "a role from some other profile: {:?}",
            id.attributes
        );
        assert_eq!(attr(&id, "aws.credentials_source"), Some("sso"));
    }

    /// The case this gate exists for: a developer whose `[default]` names an
    /// account, with no login to it, was reported as acting in that account
    /// on every event.
    #[test]
    fn a_configured_profile_without_a_login_is_not_an_identity() {
        let dir = tempfile::tempdir().unwrap();
        for logins in [
            // never logged in
            &[][..],
            // logged in, and it lapsed
            &[("https://acme.awsapps.com/start", "2026-10-12T11:59:59Z")][..],
            // logged in, to a different start URL
            &[("https://other.awsapps.com/start", "2026-10-12T20:00:00Z")][..],
        ] {
            let dir = tempfile::tempdir_in(dir.path()).unwrap();
            let mut id = CloudIdentity::default();
            enrich_aws_only(&mut id, dir.path(), logins);
            assert!(id.is_empty(), "{logins:?} -> {:?}", id.attributes);
        }
        // `staging` assumes a role through no login this module can see.
        let mut id = ids(&[("AWS_PROFILE", "staging")]);
        enrich_aws_only(
            &mut id,
            dir.path(),
            &[("https://acme.awsapps.com/start", "2026-10-12T20:00:00Z")],
        );
        assert_eq!(
            id.attributes.len(),
            1,
            "only the variable itself: {:?}",
            id.attributes
        );
    }

    #[test]
    fn a_named_credential_process_profile_is_reported_as_such() {
        let dir = tempfile::tempdir().unwrap();
        let mut id = ids(&[("AWS_PROFILE", "vaulted")]);
        enrich_aws_only(&mut id, dir.path(), &[]);
        assert_eq!(
            attr(&id, "aws.credentials_source"),
            Some("credential_process")
        );
        assert_eq!(attr(&id, "aws.account_id"), Some("555555555555"));
        assert_eq!(attr(&id, "aws.credentials_expire_at"), None);

        // The same profile as `[default]` names nobody's choice, so it is not.
        let config = config_file(
            dir.path(),
            "[default]\ncredential_process = aws-vault export --format=json vaulted\n\
             sso_account_id = 555555555555\n",
        );
        let mut id = CloudIdentity::default();
        enrich_from_files(&mut id, Some(&config), None, None, now());
        assert!(id.is_empty(), "{:?}", id.attributes);
    }

    #[test]
    fn a_command_names_the_profile_it_asked_for() {
        use ProfileVia::*;
        let p = |c: &str| command_profiles(c);
        let one = |name: &str, via| vec![(name.to_string(), via)];
        assert_eq!(p("aws s3 ls --profile prod"), one("prod", Explicit));
        assert_eq!(
            p("/usr/local/bin/aws --profile=prod sts get-caller-identity"),
            one("prod", Explicit)
        );
        assert_eq!(p("aws-vault exec prod -- aws s3 ls"), one("prod", Explicit));
        assert_eq!(
            p("aws-vault exec --duration 1h prod -- terraform plan"),
            one("prod", Explicit)
        );
        assert_eq!(
            p("aws-vault --backend file exec -d=2h prod"),
            one("prod", Explicit)
        );
        assert_eq!(p("AWS_PROFILE=prod terraform apply"), one("prod", Variable));
        assert_eq!(
            p("export AWS_PROFILE=prod && aws s3 ls"),
            one("prod", Variable)
        );
        assert_eq!(
            p("cd infra && 'AWS_PROFILE=prod' aws s3 ls"),
            one("prod", Variable)
        );
        assert_eq!(
            p("aws-vault exec prod -- aws s3 ls --profile staging"),
            vec![("prod".into(), Explicit), ("staging".into(), Explicit)]
        );
        // Words, not selections.
        for c in [
            "aws s3 ls",
            "echo --profile prod",
            "grep AWS_PROFILE=prod .envrc",
            "aws-vault list",
            "aws --profile",
            "AWS_PROFILE= aws s3 ls",
        ] {
            assert_eq!(p(c), vec![], "{c}");
        }
    }

    #[test]
    fn the_command_profile_replaces_the_environments() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_file(dir.path(), SHARED_CONFIG);
        let cmds = |c: &str| vec![c.to_string()];

        // Env keys for staging, and a call that asked for prod instead.
        let mut id = ids(&[
            ("AWS_VAULT", "staging"),
            ("AWS_ACCESS_KEY_ID", "ASIAIOSFODNN7EXAMPLE"),
            ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI"),
        ]);
        enrich_from_files(&mut id, Some(&config), None, None, now());
        apply_command_profiles_from(&mut id, &cmds("aws --profile prod s3 ls"), &config);
        assert_eq!(attr(&id, "aws.credentials_source"), Some("command"));
        assert_eq!(attr(&id, "aws.profile"), Some("prod"));
        assert_eq!(attr(&id, "aws.account_id"), Some("123456789012"));
        assert_eq!(
            attr(&id, "aws.access_key_id"),
            None,
            "staging's key: {:?}",
            id.attributes
        );
        // The secret's name stays: it was still in scope.
        assert!(
            id.credentials
                .contains(&"AWS_SECRET_ACCESS_KEY".to_string())
        );

        // `AWS_PROFILE=` loses to env keys in the SDK, so it loses here.
        let mut id = ids(&[
            ("AWS_ACCESS_KEY_ID", "ASIAIOSFODNN7EXAMPLE"),
            ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI"),
        ]);
        enrich_from_files(&mut id, Some(&config), None, None, now());
        apply_command_profiles_from(&mut id, &cmds("AWS_PROFILE=prod aws s3 ls"), &config);
        assert_eq!(attr(&id, "aws.credentials_source"), Some("env"));

        // …but wins over a profile that was only configured.
        let mut id = CloudIdentity::default();
        apply_command_profiles_from(
            &mut id,
            &cmds("AWS_PROFILE=vaulted terraform plan"),
            &config,
        );
        assert_eq!(attr(&id, "aws.account_id"), Some("555555555555"));
        assert_eq!(attr(&id, "aws.region"), Some("eu-central-2"));

        // Two profiles: both named, neither resolved.
        let mut id = CloudIdentity::default();
        apply_command_profiles_from(
            &mut id,
            &cmds("aws-vault exec prod -- aws s3 ls --profile staging"),
            &config,
        );
        assert_eq!(attr(&id, "aws.profile"), Some("prod,staging"));
        assert_eq!(attr(&id, "aws.account_id"), None);

        // No profile in the command: the environment's identity stands.
        let mut id = ids(&[("AWS_REGION", "eu-west-1")]);
        apply_command_profiles_from(&mut id, &cmds("aws s3 ls"), &config);
        assert_eq!(id, ids(&[("AWS_REGION", "eu-west-1")]));
    }

    #[test]
    fn the_sso_token_stays_in_the_cache_it_came_from() {
        let dir = tempfile::tempdir().unwrap();
        let mut id = ids(&[("AWS_PROFILE", "prod")]);
        enrich_aws_only(
            &mut id,
            dir.path(),
            &[("https://prod.awsapps.com/start", "2026-10-12T20:00:00Z")],
        );
        let rendered = serde_json::to_string(&id).unwrap();
        for leaked in [
            SSO_ACCESS_TOKEN,
            "aorAAAAAGrefresh-EXAMPLE",
            "client-secret-EXAMPLE",
        ] {
            assert!(
                !rendered.contains(leaked),
                "{leaked} reached the wire: {rendered}"
            );
        }
    }

    #[test]
    fn aws_vault_keys_are_working_until_they_expire() {
        let vault = |expires: &str| {
            ids(&[
                ("AWS_VAULT", "staging"),
                ("AWS_ACCESS_KEY_ID", "ASIAIOSFODNN7EXAMPLE"),
                ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI"),
                ("AWS_SESSION_TOKEN", "FwoGZXIvYXdzEDESAMPLE"),
                ("AWS_CREDENTIAL_EXPIRATION", expires),
            ])
        };
        let dir = tempfile::tempdir().unwrap();

        let mut id = vault("2026-10-12T12:30:00Z");
        enrich_aws_only(&mut id, dir.path(), &[]);
        assert_eq!(attr(&id, "aws.credentials_source"), Some("env"));
        // The profile aws-vault named says which role the keys belong to.
        assert_eq!(
            attr(&id, "aws.role_arn"),
            Some("arn:aws:iam::999999999999:role/staging")
        );
        assert_eq!(
            attr(&id, "aws.credentials_expire_at"),
            Some("2026-10-12T12:30:00Z")
        );

        let mut id = vault("2026-10-12T11:30:00Z");
        enrich_aws_only(&mut id, dir.path(), &[]);
        assert_eq!(
            attr(&id, "aws.credentials_source"),
            None,
            "{:?}",
            id.attributes
        );
        assert_eq!(
            attr(&id, "aws.role_arn"),
            None,
            "a lapsed session's role: {:?}",
            id.attributes
        );
    }

    #[test]
    fn env_keys_do_not_borrow_the_default_profile() {
        let dir = tempfile::tempdir().unwrap();
        let mut id = ids(&[
            ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
            ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI"),
        ]);
        // A live `[default]` login too: the SDK still signs with the env keys.
        enrich_aws_only(
            &mut id,
            dir.path(),
            &[("https://acme.awsapps.com/start", "2026-10-12T20:00:00Z")],
        );
        assert_eq!(attr(&id, "aws.credentials_source"), Some("env"));
        assert_eq!(attr(&id, "aws.region"), None, "{:?}", id.attributes);
    }

    #[test]
    fn an_expiry_in_either_spelling_parses() {
        let want: DateTime<Utc> = "2019-01-01T00:00:00Z".parse().unwrap();
        assert_eq!(parse_expiry("2019-01-01T00:00:00Z"), Some(want));
        assert_eq!(parse_expiry("2019-01-01T00:00:00UTC"), Some(want));
        assert_eq!(parse_expiry("2019-01-01T01:00:00+01:00"), Some(want));
        assert_eq!(parse_expiry("next tuesday"), None);
    }

    #[test]
    fn the_environment_outranks_the_file_it_points_at() {
        let dir = tempfile::tempdir().unwrap();
        let mut id = ids(&[
            ("AWS_PROFILE", "prod"),
            (
                "AWS_ROLE_ARN",
                "arn:aws:iam::123456789012:role/actually-assumed",
            ),
        ]);
        enrich_aws_only(
            &mut id,
            dir.path(),
            &[("https://prod.awsapps.com/start", "2026-10-12T20:00:00Z")],
        );
        assert_eq!(
            id.attributes.get("aws.role_arn").map(String::as_str),
            Some("arn:aws:iam::123456789012:role/actually-assumed"),
            "what the file would resolve to displaced what the process was told"
        );
    }

    #[test]
    fn a_private_key_stays_in_the_file_it_came_from() {
        let dir = tempfile::tempdir().unwrap();
        let secret = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BEXAMPLE\n";
        let adc = serde_json::json!({
            "type": "service_account",
            "project_id": "acme-prod",
            "quota_project_id": "acme-billing",
            "client_email": "agent@acme-prod.iam.gserviceaccount.com",
            "client_id": "1234567890",
            "private_key_id": "0123456789abcdef",
            "private_key": secret,
            "refresh_token": "1//refresh-me",
            "client_secret": "gcp-client-secret",
            "service_account_impersonation": { "target_principal": "someone@acme.iam" },
        })
        .to_string();
        let path = dir.path().join("adc.json");
        std::fs::write(&path, &adc).unwrap();

        let mut id = CloudIdentity::default();
        enrich_from_files(&mut id, None, None, Some(&path), now());
        assert_eq!(
            id.attributes.get("gcp.account").map(String::as_str),
            Some("agent@acme-prod.iam.gserviceaccount.com")
        );
        assert_eq!(
            id.attributes.get("gcp.project").map(String::as_str),
            Some("acme-prod")
        );
        assert_eq!(
            id.attributes
                .get("gcp.credentials_type")
                .map(String::as_str),
            Some("service_account")
        );
        let rendered = serde_json::to_string(&id).unwrap();
        for leaked in [
            secret,
            "1//refresh-me",
            "gcp-client-secret",
            "0123456789abcdef",
        ] {
            assert!(
                !rendered.contains(leaked),
                "credential material left the file: {rendered}"
            );
        }
        // Nothing beyond the four identifying fields, so a document that grows
        // a new secret does not grow a new attribute.
        assert_eq!(id.attributes.len(), 4, "{:?}", id.attributes);
    }

    #[test]
    fn an_identity_file_that_is_missing_or_absurd_is_simply_silence() {
        let dir = tempfile::tempdir().unwrap();
        let mut id = CloudIdentity::default();
        enrich_from_files(
            &mut id,
            Some(&dir.path().join("no-such-config")),
            Some(&dir.path().join("no-such-sso-cache")),
            Some(&dir.path().join("no-such-adc.json")),
            now(),
        );
        assert!(id.is_empty(), "{id:?}");

        // A file far past the cap is read only up to it — a role hiding beyond
        // that boundary is a missing attribute, never an unbounded read.
        let mut huge = "[default]\nsso_start_url = https://acme.awsapps.com/start\n".to_string();
        while huge.len() < (MAX_IDENTITY_FILE_BYTES as usize) + 4096 {
            huge.push_str("# padding padding padding padding padding padding\n");
        }
        huge.push_str("role_arn = arn:aws:iam::123456789012:role/beyond-the-cap\n");
        let mut id = CloudIdentity::default();
        let cache = sso_cache(
            dir.path(),
            &[("https://acme.awsapps.com/start", "2026-10-12T20:00:00Z")],
        );
        enrich_from_files(
            &mut id,
            Some(&config_file(dir.path(), &huge)),
            Some(&cache),
            None,
            now(),
        );
        assert_eq!(attr(&id, "aws.credentials_source"), Some("sso"), "{id:?}");
        assert_eq!(attr(&id, "aws.role_arn"), None, "read past the cap: {id:?}");

        // Not JSON at all, and not even UTF-8.
        let path = dir.path().join("junk.json");
        std::fs::write(&path, [0xff, 0xfe, 0x00, 0x01]).unwrap();
        let mut id = CloudIdentity::default();
        enrich_from_files(&mut id, None, None, Some(&path), now());
        assert!(id.is_empty(), "{id:?}");
        // …and the same junk where an SSO login should be.
        std::fs::write(dir.path().join("sso-cache").join("junk.json"), [0xff, 0xfe]).unwrap();
        let mut id = CloudIdentity::default();
        let config = config_file(dir.path(), SHARED_CONFIG);
        enrich_from_files(
            &mut id,
            Some(&config),
            Some(&dir.path().join("sso-cache")),
            None,
            now(),
        );
        assert_eq!(attr(&id, "aws.credentials_source"), Some("sso"), "{id:?}");
    }

    #[test]
    fn the_shim_reads_the_files_a_sibling_sdk_would() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".aws")).unwrap();
        std::fs::write(
            dir.path().join(".aws").join("config"),
            "[default]\nrole_arn = arn:aws:iam::123456789012:role/from-the-home-directory\n\
             sso_start_url = https://home.awsapps.com/start\n",
        )
        .unwrap();
        let cache = dir.path().join(".aws").join("sso").join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(
            cache.join("home.json"),
            r#"{"startUrl":"https://home.awsapps.com/start","expiresAt":"2099-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        unsafe {
            std::env::set_var("ARGUS_HOME", dir.path());
            for var in [
                "AWS_CONFIG_FILE",
                "AWS_PROFILE",
                "AWS_DEFAULT_PROFILE",
                "AWS_VAULT",
                "AWS_ROLE_ARN",
                "AWS_ACCESS_KEY_ID",
                "AWS_WEB_IDENTITY_TOKEN_FILE",
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            ] {
                std::env::remove_var(var);
            }
        }
        let id = current();
        unsafe {
            std::env::remove_var("ARGUS_HOME");
        }
        assert_eq!(
            id.attributes.get("aws.role_arn").map(String::as_str),
            Some("arn:aws:iam::123456789012:role/from-the-home-directory"),
            "{:?}",
            id.attributes
        );
    }

    #[test]
    fn an_explicit_path_wins_over_the_place_the_file_usually_lives() {
        let home = std::path::Path::new("/home/dev");
        unsafe {
            std::env::set_var("AWS_CONFIG_FILE", "/etc/argus/aws-config");
            std::env::set_var("GOOGLE_APPLICATION_CREDENTIALS", "/etc/argus/adc.json");
        }
        assert_eq!(
            aws_config_path(home),
            PathBuf::from("/etc/argus/aws-config")
        );
        assert_eq!(gcp_adc_path(home), PathBuf::from("/etc/argus/adc.json"));

        // An exported-but-empty override is not a path; falling for it would
        // read `/application_default_credentials.json`.
        unsafe {
            std::env::set_var("AWS_CONFIG_FILE", "");
            std::env::set_var("GOOGLE_APPLICATION_CREDENTIALS", "");
            std::env::remove_var("CLOUDSDK_CONFIG");
        }
        assert_eq!(aws_config_path(home), home.join(".aws").join("config"));
        // Not `starts_with(home)`: where gcloud keeps this is platform
        // business — `%APPDATA%\gcloud` on Windows, `~/.config/gcloud`
        // elsewhere — and the empty override is caught either way, since
        // falling for it returns the bare `""`.
        let adc = gcp_adc_path(home);
        assert!(
            adc.ends_with(
                std::path::Path::new("gcloud").join("application_default_credentials.json")
            ),
            "{adc:?}"
        );
        unsafe {
            std::env::remove_var("AWS_CONFIG_FILE");
            std::env::remove_var("GOOGLE_APPLICATION_CREDENTIALS");
        }
    }
}
