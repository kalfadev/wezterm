//! Termob fork: forgetting a host's key in a `known_hosts` file, so that a
//! host whose key changed can be asked about again where no shell can run
//! `ssh-keygen -R`, a phone above all.

use anyhow::Context;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Removes from `file` each name that stands for `host` on `port` exactly:
/// `host` itself on port 22, `[host]:port` on any port, plainly or hashed
/// (`|1|salt|hash`), with the case of the host ignored as OpenSSH ignores it.
/// A line that also names other hosts keeps them; wildcard patterns,
/// negations, comments and `@` marker lines are left alone. Returns how many
/// names were removed; the file is written again only when there were some,
/// and then as [`replace_whole`] writes it.
pub fn forget_host_key(file: &Path, host: &str, port: u16) -> anyhow::Result<usize> {
    let text = std::fs::read_to_string(file)
        .with_context(|| format!("reading known_hosts file {}", file.display()))?;
    let host = host.to_ascii_lowercase();
    let mut names = vec![format!("[{host}]:{port}")];
    if port == 22 {
        names.push(host);
    }
    let mut removed = 0;
    let mut kept = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let (line, gone) = forget_in_line(line, &names);
        removed += gone;
        kept.push_str(&line);
    }
    if removed > 0 {
        replace_whole(file, &kept)?;
    }
    Ok(removed)
}

/// Writes `text` over `file` as `ssh-keygen -R` does: whole, under another name
/// beside it, then renamed over it, so that a crash or a full disk leaves the
/// old file or the new one and never part of either. A symlinked file is
/// written where the link points and the link stays; the file keeps its
/// permissions.
fn replace_whole(file: &Path, text: &str) -> anyhow::Result<()> {
    let target = std::fs::canonicalize(file)
        .with_context(|| format!("resolving known_hosts file {}", file.display()))?;
    let permissions = std::fs::metadata(&target)
        .with_context(|| format!("reading known_hosts file {}", target.display()))?
        .permissions();
    let mut name = target.clone().into_os_string();
    name.push(".termob-new");
    let temp = PathBuf::from(name);
    let written = (|| -> std::io::Result<()> {
        let mut out = std::fs::File::create(&temp)?;
        out.set_permissions(permissions)?;
        out.write_all(text.as_bytes())?;
        out.sync_all()?;
        std::fs::rename(&temp, &target)
    })();
    if written.is_err() {
        // The temporary file is ours, not the user's, and the error that
        // matters is the write's: a failure to remove it is not reported.
        let _ = std::fs::remove_file(&temp);
    }
    written.with_context(|| format!("writing known_hosts file {}", target.display()))
}

/// `line` without the patterns that name one of `names`, and how many went;
/// a line left naming no host goes whole.
fn forget_in_line(line: &str, names: &[String]) -> (String, usize) {
    let body = line.trim_start();
    if body.is_empty() || body.starts_with('#') || body.starts_with('@') {
        return (line.to_string(), 0);
    }
    let Some((patterns, rest)) = body.split_once(char::is_whitespace) else {
        return (line.to_string(), 0);
    };
    let mut gone = 0;
    let left: Vec<&str> = patterns
        .split(',')
        .filter(|pattern| {
            let names_one = names.iter().any(|name| pattern_names(pattern, name));
            if names_one {
                gone += 1;
            }
            !names_one
        })
        .collect();
    if gone == 0 {
        (line.to_string(), 0)
    } else if left.is_empty() {
        (String::new(), gone)
    } else {
        (format!("{} {rest}", left.join(",")), gone)
    }
}

/// Whether `pattern`, one host pattern of a line, is `name` itself, plainly
/// or hashed; a wildcard or a negation never is.
fn pattern_names(pattern: &str, name: &str) -> bool {
    match pattern.strip_prefix("|1|") {
        Some(hashed) => hashed
            .split_once('|')
            .is_some_and(|(salt, hash)| hash_matches(salt, hash, name)),
        None => pattern.eq_ignore_ascii_case(name),
    }
}

/// Whether `hash` is the HMAC-SHA1 of `name` under `salt`, both in base64, as
/// OpenSSH hashes a host name.
fn hash_matches(salt: &str, hash: &str, name: &str) -> bool {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let (Ok(salt), Ok(hash)) = (engine.decode(salt), engine.decode(hash)) else {
        return false;
    };
    let Ok(key) = openssl::pkey::PKey::hmac(&salt) else {
        return false;
    };
    let Ok(mut signer) = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha1(), &key)
    else {
        return false;
    };
    signer
        .sign_oneshot_to_vec(name.as_bytes())
        .is_ok_and(|mac| mac == hash)
}
