//! Deciding which files may have their contents captured.
//!
//! Separate from the capture itself because the decision is the security
//! boundary and the capture is plumbing. Everything here is pure: a path in, a
//! verdict out, no I/O — so the rule that keeps `.ssh/id_rsa` out of the SIEM
//! can be tested exhaustively without a filesystem, and the same verdict
//! applies whether the bytes came from a hook payload or a disk read.

use crate::config::FileContentsCfg;
use regex::RegexSet;

/// Compiled `include`/`exclude`, built once per config generation.
///
/// Cached alongside the `Redactor` for the same reason: these regexes are
/// matched against every path in every tool call, and recompiling them per
/// event is the kind of cost that only shows up under the load it matters at.
#[derive(Debug)]
pub struct PathFilter {
    /// `None` means "no include list", which is not the same as an empty set:
    /// an empty `RegexSet` matches nothing, and a filter that admits nothing
    /// is an enabled feature that captures nothing.
    include: Option<RegexSet>,
    exclude: RegexSet,
    /// Set when a pattern would not compile. The filter then refuses
    /// everything — see [`PathFilter::allows`].
    broken: bool,
}

/// Windows writes `C:\repo\node_modules\x` and every default `exclude` here is
/// written with forward slashes, so without this the shipped policy silently
/// fails to match on exactly the platform where `--managed` deployments live,
/// and argus captures the files it was configured to skip.
pub fn normalize(path: &str) -> String {
    path.replace('\\', "/")
}

impl PathFilter {
    pub fn new(cfg: &FileContentsCfg) -> Self {
        // Windows paths are case-insensitive, so `\NODE_MODULES\` and
        // `\node_modules\` name one directory and must match one rule. Unix
        // paths are not, and folding case there would exclude files a
        // deployment did not ask to exclude.
        Self::with_case_folding(cfg, cfg!(windows))
    }

    /// Split out so the folding itself is testable on every platform. Built
    /// under `cfg!(windows)` it would only ever be exercised on Windows CI,
    /// which is precisely where nobody looks first.
    fn with_case_folding(cfg: &FileContentsCfg, fold_case: bool) -> Self {
        let build = |pats: &[String]| -> Result<RegexSet, regex::Error> {
            regex::RegexSetBuilder::new(pats)
                .case_insensitive(fold_case)
                .build()
        };
        let mut broken = false;
        let exclude = build(&cfg.exclude).unwrap_or_else(|e| {
            // Fails closed, unlike every other invalid-pattern path in this
            // codebase. A dropped redaction rule scrubs less than asked; a
            // dropped *exclusion* ships the file it names, and the files it
            // names are `.env` and `id_rsa`.
            tracing::error!(
                "file_contents.exclude did not compile, capturing no contents at all: {e}"
            );
            broken = true;
            RegexSet::empty()
        });
        let include = if cfg.include.is_empty() {
            None
        } else {
            Some(build(&cfg.include).unwrap_or_else(|e| {
                tracing::error!("file_contents.include did not compile, capturing nothing: {e}");
                broken = true;
                RegexSet::empty()
            }))
        };
        PathFilter {
            include,
            exclude,
            broken,
        }
    }

    /// Whether this path's *content* may be captured. Metadata is not gated by
    /// it: a file excluded here is still reported as touched.
    pub fn allows(&self, path: &str) -> bool {
        if self.broken {
            return false;
        }
        let p = normalize(path);
        if self.exclude.is_match(&p) {
            return false;
        }
        match &self.include {
            Some(inc) => inc.is_match(&p),
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(include: &[&str], exclude: &[&str]) -> FileContentsCfg {
        FileContentsCfg {
            include: include.iter().map(|s| (*s).to_string()).collect(),
            exclude: exclude.iter().map(|s| (*s).to_string()).collect(),
            ..FileContentsCfg::default()
        }
    }

    /// The shipped policy has to hold on the platform it is least likely to be
    /// tested on. A `C:\repo\node_modules\` path that misses `/node_modules/`
    /// is a config that reads as protective and is not.
    #[test]
    fn the_default_exclusions_match_windows_paths_too() {
        let f = PathFilter::new(&FileContentsCfg::default());
        for path in [
            r"C:\repo\node_modules\pkg\index.js",
            r"C:\Users\dev\.ssh\id_rsa",
            r"C:\repo\.env",
            r"C:\repo\.env.local",
            r"C:\repo\certs\server.pem",
            r"C:\repo\Cargo.lock",
            r"C:\repo\.git\config",
            r"C:\repo\keys\backup.p12",
            r"C:\Users\dev\.ssh\deploy_rsa",
        ] {
            assert!(!f.allows(path), "should be excluded: {path}");
            assert!(
                !f.allows(&path.replace('\\', "/")),
                "should be excluded: {path} (unix form)"
            );
        }
        assert!(f.allows(r"C:\repo\src\main.rs"));
        assert!(f.allows("/repo/src/main.rs"));
    }

    /// `C:\Repo\NODE_MODULES\` and `C:\repo\node_modules\` are one directory,
    /// and the shipped `exclude` list is written in lower case. Without case
    /// folding the default policy misses half the paths on the platform
    /// `--managed` deployments actually run on.
    #[test]
    fn windows_case_folding_is_what_makes_the_default_policy_hold() {
        let d = FileContentsCfg::default();
        let shouty = r"C:\Repo\NODE_MODULES\pkg\Index.js";
        let key = r"C:\Users\Dev\.SSH\ID_RSA";

        let win = PathFilter::with_case_folding(&d, true);
        assert!(!win.allows(shouty), "case-folded match missed: {shouty}");
        assert!(!win.allows(key), "case-folded match missed: {key}");

        // And not folded elsewhere: on Unix those are genuinely different
        // files, and excluding them would be excluding paths nobody named.
        let unix = PathFilter::with_case_folding(&d, false);
        assert!(unix.allows(shouty));
        assert!(unix.allows(key));
        // The lower-case forms are excluded on both.
        assert!(!unix.allows(r"C:\repo\node_modules\pkg\index.js"));
    }

    /// An empty `include` is "everything the excludes allow", not "nothing".
    #[test]
    fn an_empty_include_list_is_not_an_empty_allow_list() {
        let f = PathFilter::new(&cfg(&[], &[]));
        assert!(f.allows("/anything/at/all.rs"));
    }

    #[test]
    fn include_narrows_and_exclude_still_wins() {
        let f = PathFilter::new(&cfg(&["/src/"], &[r"/src/secrets\.rs$"]));
        assert!(f.allows("/repo/src/main.rs"));
        assert!(!f.allows("/repo/docs/readme.md"), "outside include");
        assert!(
            !f.allows("/repo/src/secrets.rs"),
            "a path both included and excluded was meant to be excluded"
        );
    }

    /// Every other invalid pattern in this codebase is warned about and
    /// dropped. An exclusion cannot be: dropping it captures the file it
    /// names, and the files it names are the ones nobody wants captured.
    #[test]
    fn an_uncompilable_exclusion_stops_capture_rather_than_widening_it() {
        let f = PathFilter::new(&cfg(&[], &["[unclosed"]));
        assert!(
            !f.allows("/repo/src/main.rs"),
            "a broken exclude list must fail closed, not open"
        );
    }

    #[test]
    fn an_uncompilable_include_also_fails_closed() {
        let f = PathFilter::new(&cfg(&["(unclosed"], &[]));
        assert!(!f.allows("/repo/src/main.rs"));
    }
}
