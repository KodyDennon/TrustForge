//! TrustForge glob matching: the pattern language used by capability
//! target sets, negative-capability targets, and policy `target_patterns`.
//!
//! Semantics (canonical since B8):
//! - `*`  matches any run (possibly empty) of characters **except `/`**
//! - `**` matches any run (possibly empty) of characters, including `/`
//! - every other character, `?` included, matches itself literally
//!
//! Previously each call site converted the glob to a regex and matched
//! with the `regex` crate; the three private copies had drifted (two
//! still byte-iterated, corrupting non-ASCII patterns, and passed `?`
//! through as a regex quantifier). This module is the single
//! implementation. It matches directly — no regex, no compilation step —
//! in O(pattern × value) worst case with plain DP, so untrusted patterns
//! cannot trigger pathological backtracking.

/// Match `value` against a TrustForge glob `pattern`.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    enum Tok {
        /// `**` — any run, `/` included.
        Any,
        /// `*` — any run without `/`.
        AnySegment,
        Lit(char),
    }

    let mut toks = Vec::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '*' {
            if chars.peek() == Some(&'*') {
                chars.next();
                toks.push(Tok::Any);
            } else {
                toks.push(Tok::AnySegment);
            }
        } else {
            toks.push(Tok::Lit(c));
        }
    }

    let vals: Vec<char> = value.chars().collect();

    // dp[j] = "the tokens consumed so far can match vals[..j]".
    let mut dp = vec![false; vals.len() + 1];
    dp[0] = true;
    for tok in &toks {
        let mut next = vec![false; vals.len() + 1];
        match tok {
            Tok::Lit(l) => {
                for j in 0..vals.len() {
                    next[j + 1] = dp[j] && vals[j] == *l;
                }
            }
            Tok::Any => {
                let mut reachable = false;
                for j in 0..=vals.len() {
                    reachable = reachable || dp[j];
                    next[j] = reachable;
                }
            }
            Tok::AnySegment => {
                // Reachability propagates rightward but stops at `/`.
                let mut reachable = false;
                for j in 0..=vals.len() {
                    reachable = reachable || dp[j];
                    next[j] = reachable;
                    if j < vals.len() && vals[j] == '/' {
                        reachable = false;
                    }
                }
            }
        }
        dp = next;
    }
    dp[vals.len()]
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn literals() {
        assert!(glob_match("files.read", "files.read"));
        assert!(!glob_match("files.read", "files.write"));
        assert!(!glob_match("files.read", "files.read2"));
        assert!(!glob_match("files.read2", "files.read"));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "a"));
    }

    #[test]
    fn single_star_stops_at_slash() {
        assert!(glob_match("repo/*", "repo/main"));
        assert!(!glob_match("repo/*", "repo/main/file"));
        assert!(glob_match("repo/*/file", "repo/main/file"));
        assert!(glob_match("*.rs", "lib.rs"));
        assert!(!glob_match("*.rs", "src/lib.rs"));
        assert!(glob_match("a*", "a"));
    }

    #[test]
    fn double_star_crosses_slash() {
        assert!(glob_match("repo/**", "repo/main/deep/file"));
        assert!(glob_match("repo/**", "repo/"));
        assert!(glob_match("**/file", "repo/main/file"));
        assert!(glob_match("**", ""));
        assert!(glob_match("**", "anything/at/all"));
    }

    #[test]
    fn mixed_stars_requiring_full_backtracking() {
        // A single-backtrack matcher gets this wrong: `**` must grow
        // even though a later `*` hit the mismatch.
        assert!(glob_match("**/a*b", "x/a/ab"));
        // `/` is literal here: `**` does not swallow the separator.
        assert!(!glob_match("**/a*b", "aXb"));
        assert!(!glob_match("**/a*b", "x/a/a"));
        assert!(glob_match("*a*a*", "aaa"));
        assert!(!glob_match("*a*a*", "a/a"));
        assert!(glob_match("**a**a**", "a/a"));
    }

    #[test]
    fn question_mark_is_literal() {
        // B8: `?` is an ordinary character, not a wildcard.
        assert!(glob_match("ok?", "ok?"));
        assert!(!glob_match("ok?", "ok"));
        assert!(!glob_match("ok?", "okX"));
    }

    #[test]
    fn regex_meta_is_literal() {
        assert!(glob_match("a.b+c(d)", "a.b+c(d)"));
        assert!(!glob_match("a.b", "axb"));
        assert!(glob_match("[env]", "[env]"));
        assert!(glob_match("^start$", "^start$"));
    }

    #[test]
    fn non_ascii_patterns() {
        // The old byte-based converters corrupted multi-byte chars.
        assert!(glob_match("café/*", "café/menu"));
        assert!(!glob_match("café/*", "cafe/menu"));
        assert!(glob_match("*é", "résumé"));
    }
}
