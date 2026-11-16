//! Stamps the build's git commit SHA and build time into the binary.
//!
//! Both values are resolved here, at build time, and handed to rustc as
//! environment variables that `src/main.rs` reads with `env!()`. They are
//! therefore compiled into the binary and cannot drift from it: there is no
//! runtime lookup, and nothing shells out to git on the request path.
//!
//! Resolving the SHA has to work in three different places:
//!
//! 1. **Render.** `.dockerignore` keeps `.git/` out of the build context except
//!    for the few metadata files read below, and Render also exposes
//!    `RENDER_GIT_COMMIT` to the build. Either path is enough on its own, which
//!    is the point -- Render's docs are not explicit about whether its own
//!    variables reach a Dockerfile as build args, so this does not rely on it.
//! 2. **CI and the Docker build.** Same as above, minus `RENDER_GIT_COMMIT`.
//!    The CI docker build is what proves the context really does carry the
//!    metadata, because a missing SHA fails this script rather than degrading
//!    to a placeholder.
//! 3. **A local checkout.** The `.git` read works directly; `git rev-parse` is
//!    kept as a last resort for unusual layouts.
//!
//! The git metadata is read as plain files rather than by invoking `git`, so no
//! git binary is needed in the builder image.
//!
//! There is deliberately no "unknown" fallback. A SHA that is absent, or stale
//! by a commit, is worse than a failed build: it silently misreports which code
//! is running, which is the entire thing these fields exist to answer.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("cargo always sets CARGO_MANIFEST_DIR"),
    );

    // Rerun triggers. Emitting any of these replaces cargo's default "rerun if
    // any file in the package changed", which is what we want: editing a source
    // file does not change the commit, and re-stamping on every edit would
    // force a full LTO relink of the crate every time.
    //
    // Freshness of the SHA depends entirely on these being right, so the ref
    // that HEAD points at is registered below as well as HEAD itself.
    println!("cargo:rerun-if-env-changed=RENDER_GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=GIT_COMMIT");

    let commit = resolve_commit(&manifest_dir);
    let commit = match commit {
        Some(sha) => sha,
        None => panic!(
            "could not determine the git commit SHA.\n\
             Tried, in order: $RENDER_GIT_COMMIT, $GIT_COMMIT, the git metadata under \
             {}, and `git rev-parse HEAD`.\n\
             This is a hard error on purpose: reporting a placeholder SHA from /health \
             would defeat the point of the field. If this fired in a Docker build, check \
             that .dockerignore still re-includes .git/HEAD, .git/refs/ and .git/packed-refs.",
            manifest_dir.join(".git").display()
        ),
    };

    assert!(
        is_full_sha(&commit),
        "resolved commit {commit:?} is not a full 40-character hex SHA"
    );

    println!("cargo:rustc-env=GIT_COMMIT={commit}");
    println!("cargo:rustc-env=BUILT_AT={}", rfc3339_utc_now());
}

/// A 40-character lowercase hex SHA-1, and nothing else. Abbreviated SHAs and
/// placeholders such as `unknown` are rejected by the caller.
fn is_full_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn resolve_commit(manifest_dir: &Path) -> Option<String> {
    // Preferred: whatever the platform tells us it deployed. On Render this is
    // authoritative -- it is the commit the deploy was created from.
    for key in ["RENDER_GIT_COMMIT", "GIT_COMMIT"] {
        if let Some(sha) = std::env::var(key).ok().and_then(normalize) {
            return Some(sha);
        }
    }

    if let Some(sha) = read_git_metadata(manifest_dir) {
        return Some(sha);
    }

    // Last resort, for checkouts whose layout the file reader does not cover.
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(manifest_dir)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(normalize)
}

fn normalize(value: String) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    is_full_sha(&value).then_some(value)
}

/// Resolve HEAD by reading `.git` directly, so the builder image needs no git.
///
/// Handles the three shapes that matter: a symbolic HEAD pointing at a loose
/// ref, a symbolic HEAD whose ref only exists in `packed-refs`, and a detached
/// HEAD holding a raw SHA.
fn read_git_metadata(manifest_dir: &Path) -> Option<String> {
    let git_dir = resolve_git_dir(manifest_dir)?;

    let head_path = git_dir.join("HEAD");
    let head = std::fs::read_to_string(&head_path).ok()?;
    track(&head_path);

    let Some(ref_name) = head.trim().strip_prefix("ref: ") else {
        // Detached HEAD: the file holds the SHA itself.
        return normalize(head);
    };
    let ref_name = ref_name.trim();

    // A loose ref file is the common case right after a commit.
    let ref_path = git_dir.join(ref_name);
    track(&ref_path);
    if let Some(sha) = std::fs::read_to_string(&ref_path).ok().and_then(normalize) {
        return Some(sha);
    }

    // Otherwise the ref has been packed.
    let packed_path = git_dir.join("packed-refs");
    track(&packed_path);
    let packed = std::fs::read_to_string(&packed_path).ok()?;
    packed
        .lines()
        .filter(|line| !line.starts_with('#') && !line.starts_with('^'))
        .find_map(|line| {
            let (sha, name) = line.split_once(' ')?;
            (name.trim() == ref_name).then(|| sha.to_string())
        })
        .and_then(normalize)
}

/// `.git` is usually a directory, but is a file containing `gitdir: <path>`
/// inside a worktree or submodule.
fn resolve_git_dir(manifest_dir: &Path) -> Option<PathBuf> {
    let dot_git = manifest_dir.join(".git");

    if dot_git.is_dir() {
        return Some(dot_git);
    }

    let pointer = std::fs::read_to_string(&dot_git).ok()?;
    track(&dot_git);
    let path = Path::new(pointer.trim().strip_prefix("gitdir: ")?.trim());
    Some(if path.is_absolute() {
        path.to_path_buf()
    } else {
        manifest_dir.join(path)
    })
}

/// Register a rerun trigger, but only for a path that exists. Cargo treats a
/// missing `rerun-if-changed` path as "changed", which would re-stamp (and so
/// relink) on every single build.
fn track(path: &Path) {
    if path.exists() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

/// Current UTC time as RFC 3339, e.g. `2026-11-16T01:37:04Z`.
///
/// Done by hand to avoid adding a build dependency for one timestamp.
fn rfc3339_utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs();

    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let time_of_day = secs % 86_400;
    let (hour, minute, second) = (
        time_of_day / 3_600,
        (time_of_day % 3_600) / 60,
        time_of_day % 60,
    );

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Days since the Unix epoch to a civil (year, month, day), by Howard
/// Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Shift the epoch to 0000-03-01 so leap days land at the end of the cycle.
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097; // [0, 146096]
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365; // [0, 399]
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100); // [0, 365]
    let month_shifted = (5 * day_of_year + 2) / 153; // [0, 11], 0 == March
    let day = (day_of_year - (153 * month_shifted + 2) / 5 + 1) as u32; // [1, 31]
    let month = if month_shifted < 10 {
        month_shifted + 3
    } else {
        month_shifted - 9
    } as u32; // [1, 12]

    (year + i64::from(month <= 2), month, day)
}
