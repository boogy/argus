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

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// `(variable, attribute)`. Several variables map to one attribute where a
/// provider offers aliases; first hit in this order wins, which follows each
/// SDK's own precedence (`AWS_PROFILE` over `AWS_DEFAULT_PROFILE`, and so on).
const IDENTIFIERS: &[(&str, &str)] = &[
    // ---- AWS -------------------------------------------------------------
    ("AWS_PROFILE", "aws.profile"),
    ("AWS_DEFAULT_PROFILE", "aws.profile"),
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

/// The identity of the process this is called in.
///
/// Called from the hook shim, which the host agent spawned and which therefore
/// holds the agent's environment. Nothing calls it in the daemon: the daemon
/// is a long-lived process started from somewhere else entirely, and its
/// environment describes whoever started it rather than any agent.
pub fn current() -> CloudIdentity {
    from_vars(std::env::vars())
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

        let ts_ids: Vec<(&str, &str)> = block("identifiers")
            .lines()
            .map(quoted)
            .filter(|q| !q.is_empty())
            .map(|q| {
                assert_eq!(q.len(), 2, "{q:?} is not a (variable, attribute) pair");
                (q[0], q[1])
            })
            .collect();
        assert_eq!(
            ts_ids,
            IDENTIFIERS.to_vec(),
            "the plugin's allowlist has drifted from the shim's; opencode and pi \
             would report a different identity from every other tool"
        );

        let ts_markers: Vec<&str> = block("markers").lines().flat_map(quoted).collect();
        assert_eq!(ts_markers, CREDENTIAL_MARKERS.to_vec());
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
}
