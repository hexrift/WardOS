//! A pragmatic `.gitignore` matcher used when `include_ignored` is false.
//!
//! Supports the common cases: comments and blanks, negation (`!`), anchoring
//! (a leading or embedded `/`), directory-only patterns (trailing `/`),
//! basename patterns, and the `*` `?` `**` wildcards, with last-match-wins
//! precedence and deeper `.gitignore` files overriding shallower ones. It is
//! deliberately not a complete reimplementation of gitignore(5); character
//! classes and some escaping corner cases are out of scope.

/// One parsed ignore pattern, tied to the directory of its `.gitignore`.
#[derive(Clone, Debug)]
pub struct Rule {
    negated: bool,
    dir_only: bool,
    anchored: bool,
    /// Relative directory the rule is rooted at (empty for the snapshot root).
    base: Vec<u8>,
    pat: Vec<u8>,
}

impl Rule {
    fn matches(&self, path: &[u8], is_dir: bool) -> bool {
        if self.dir_only && !is_dir {
            return false;
        }
        let Some(rel) = strip_base(path, &self.base) else {
            return false;
        };
        if self.anchored {
            path_match(&self.pat, rel)
        } else {
            seg_match(&self.pat, basename(rel))
        }
    }
}

/// An ordered set of rules, root-first, evaluated last-match-wins.
#[derive(Clone, Debug, Default)]
pub struct Rules {
    rules: Vec<Rule>,
}

impl Rules {
    /// Append the rules from a `.gitignore` body located at `base` (a relative
    /// directory path, empty for the root). Returns how many were added so the
    /// caller can truncate back after leaving the subtree.
    pub fn push_file(&mut self, body: &[u8], base: &[u8]) -> usize {
        let before = self.rules.len();
        for line in body.split(|&b| b == b'\n') {
            if let Some(rule) = parse_line(line, base) {
                self.rules.push(rule);
            }
        }
        self.rules.len() - before
    }

    /// Drop the last `n` rules.
    pub fn truncate_by(&mut self, n: usize) {
        self.rules.truncate(self.rules.len() - n);
    }

    /// Whether `path` (relative to the root) is ignored.
    pub fn is_ignored(&self, path: &[u8], is_dir: bool) -> bool {
        let mut ignored = false;
        for rule in &self.rules {
            if rule.matches(path, is_dir) {
                ignored = !rule.negated;
            }
        }
        ignored
    }
}

fn parse_line(line: &[u8], base: &[u8]) -> Option<Rule> {
    let mut line = trim_end(line);
    if line.is_empty() || line[0] == b'#' {
        return None;
    }
    let negated = line[0] == b'!';
    if negated {
        line = &line[1..];
    }
    let dir_only = line.last() == Some(&b'/');
    if dir_only {
        line = &line[..line.len() - 1];
    }
    // Anchored if it contains a `/` at all now (a leading `/` just anchors to base).
    let anchored = line.contains(&b'/');
    let line = line.strip_prefix(b"/").unwrap_or(line);
    if line.is_empty() {
        return None;
    }
    Some(Rule {
        negated,
        dir_only,
        anchored,
        base: base.to_vec(),
        pat: line.to_vec(),
    })
}

fn trim_end(mut b: &[u8]) -> &[u8] {
    while let Some((&last, rest)) = b.split_last() {
        if last == b' ' || last == b'\r' || last == b'\t' {
            b = rest;
        } else {
            break;
        }
    }
    b
}

fn basename(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// Strip a base-directory prefix from `path`, returning the remainder.
fn strip_base<'a>(path: &'a [u8], base: &[u8]) -> Option<&'a [u8]> {
    if base.is_empty() {
        return Some(path);
    }
    let rest = path.strip_prefix(base)?;
    rest.strip_prefix(b"/")
}

/// Wildcard match within a single path segment (`*` any run, `?` one byte).
fn seg_match(pat: &[u8], text: &[u8]) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ti < text.len() {
        if pi < pat.len() && (pat[pi] == b'?' || pat[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == b'*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}

/// Anchored, slash-aware match where `**` spans zero or more segments.
fn path_match(pat: &[u8], text: &[u8]) -> bool {
    let ps: Vec<&[u8]> = pat.split(|&b| b == b'/').collect();
    let ts: Vec<&[u8]> = text.split(|&b| b == b'/').collect();
    seg_list_match(&ps, &ts)
}

fn seg_list_match(ps: &[&[u8]], ts: &[&[u8]]) -> bool {
    match ps.split_first() {
        None => ts.is_empty(),
        Some((&head, rest)) if head == b"**" => {
            (0..=ts.len()).any(|i| seg_list_match(rest, &ts[i..]))
        }
        Some((&head, rest)) => match ts.split_first() {
            Some((&t0, trest)) => seg_match(head, t0) && seg_list_match(rest, trest),
            None => false,
        },
    }
}
