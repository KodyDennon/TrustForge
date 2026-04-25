//! Capability semantics — mirrors `tools/tf-types-ts/src/core/capability.ts`.
//!
//! Evaluates constraint sets against a runtime context and computes the
//! tighter intersection of two constraint sets. Unknown constraint variants
//! fail closed.

use crate::generated::common::{ApprovalRequirement, Constraint};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EvalContext {
    pub now: String,
    pub session_id: Option<String>,
    pub target: Option<String>,
    pub approver_count: Option<u32>,
    pub device_actor: Option<String>,
}

pub fn constraints_satisfied(constraints: &[Constraint], ctx: &EvalContext) -> bool {
    constraints.iter().all(|c| satisfies(c, ctx))
}

fn satisfies(c: &Constraint, ctx: &EvalContext) -> bool {
    match c {
        Constraint::TimeWindow { from, until } => {
            if let Some(from_ts) = from {
                if ctx.now.as_str() < from_ts.as_str() {
                    return false;
                }
            }
            ctx.now.as_str() <= until.as_str()
        }
        Constraint::Target { patterns } => match &ctx.target {
            Some(t) => patterns.iter().any(|p| matches_glob(p, t)),
            None => false,
        },
        Constraint::Quantity { .. } => true, // requires external counter
        Constraint::Rate { .. } => true,     // requires external counter
        Constraint::Session { session_id } => ctx.session_id.as_deref() == Some(session_id.as_str()),
        Constraint::Approval { approval } => matches!(
            approval,
            ApprovalRequirement::None | ApprovalRequirement::Conditional
        ),
        Constraint::Quorum { quorum, .. } => ctx.approver_count.unwrap_or(0) as i64 >= *quorum,
        Constraint::DeviceBinding { device_actor } => {
            ctx.device_actor.as_deref() == Some(device_actor.as_str())
        }
    }
}

pub fn intersect_constraints(a: &[Constraint], b: &[Constraint]) -> Vec<Constraint> {
    let mut out: Vec<Constraint> = a.to_vec();
    for nc in b {
        let idx = out.iter().position(|c| same_kind(c, nc));
        match idx {
            Some(i) => {
                out[i] = intersect_same(&out[i], nc);
            }
            None => out.push(nc.clone()),
        }
    }
    out
}

fn same_kind(a: &Constraint, b: &Constraint) -> bool {
    matches!(
        (a, b),
        (Constraint::TimeWindow { .. }, Constraint::TimeWindow { .. })
            | (Constraint::Target { .. }, Constraint::Target { .. })
            | (Constraint::Quantity { .. }, Constraint::Quantity { .. })
            | (Constraint::Rate { .. }, Constraint::Rate { .. })
            | (Constraint::Session { .. }, Constraint::Session { .. })
            | (Constraint::Approval { .. }, Constraint::Approval { .. })
            | (Constraint::Quorum { .. }, Constraint::Quorum { .. })
            | (
                Constraint::DeviceBinding { .. },
                Constraint::DeviceBinding { .. }
            )
    )
}

fn intersect_same(a: &Constraint, b: &Constraint) -> Constraint {
    match (a, b) {
        (
            Constraint::TimeWindow {
                from: af,
                until: au,
            },
            Constraint::TimeWindow {
                from: bf,
                until: bu,
            },
        ) => Constraint::TimeWindow {
            from: pick_later(af.as_deref(), bf.as_deref()),
            until: pick_earlier(au, bu).to_string(),
        },
        (Constraint::Target { patterns: ap }, Constraint::Target { patterns: bp }) => {
            let shared: Vec<String> = ap.iter().filter(|p| bp.contains(p)).cloned().collect();
            if shared.is_empty() {
                let mut merged = ap.clone();
                merged.extend(bp.iter().cloned());
                Constraint::Target { patterns: merged }
            } else {
                Constraint::Target { patterns: shared }
            }
        }
        (
            Constraint::Quantity { max: am, unit: au },
            Constraint::Quantity { max: bm, unit: bu },
        ) => Constraint::Quantity {
            max: (*am).min(*bm),
            unit: au.clone().or_else(|| bu.clone()),
        },
        (
            Constraint::Rate {
                max_per_window: am,
                window_seconds: aw,
            },
            Constraint::Rate {
                max_per_window: bm,
                window_seconds: bw,
            },
        ) => Constraint::Rate {
            max_per_window: (*am).min(*bm),
            window_seconds: (*aw).min(*bw),
        },
        (
            Constraint::Quorum {
                quorum: aq,
                of: ao,
            },
            Constraint::Quorum { quorum: bq, .. },
        ) => Constraint::Quorum {
            quorum: (*aq).max(*bq),
            of: ao.clone(),
        },
        _ => a.clone(),
    }
}

fn pick_later(a: Option<&str>, b: Option<&str>) -> Option<String> {
    match (a, b) {
        (None, None) => None,
        (Some(x), None) => Some(x.to_string()),
        (None, Some(y)) => Some(y.to_string()),
        (Some(x), Some(y)) => Some(if x > y { x.to_string() } else { y.to_string() }),
    }
}

fn pick_earlier<'a>(a: &'a str, b: &'a str) -> &'a str {
    if a < b {
        a
    } else {
        b
    }
}

fn matches_glob(pattern: &str, value: &str) -> bool {
    // Minimal glob: `*` matches non-`/` chars, `**` matches any.
    // Escape regex meta first, then translate globs.
    let mut re = String::with_capacity(pattern.len() + 4);
    re.push('^');
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'*' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                    re.push_str(".*");
                    i += 2;
                } else {
                    re.push_str("[^/]*");
                    i += 1;
                }
            }
            b'.' | b'+' | b'^' | b'$' | b'{' | b'}' | b'(' | b')' | b'|' | b'[' | b']' | b'\\' => {
                re.push('\\');
                re.push(b as char);
                i += 1;
            }
            _ => {
                re.push(b as char);
                i += 1;
            }
        }
    }
    re.push('$');
    regex::Regex::new(&re).map(|r| r.is_match(value)).unwrap_or(false)
}
