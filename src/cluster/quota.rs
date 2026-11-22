//! Cluster quota consensus (v1.3): rules and usage piggyback on heartbeats.
//!
//! Each server votes once per `(scope, target)` — abstention means no rule was
//! configured, not "no quota". The most-voted value is the cluster fallback
//! when the local server has no rule of its own. Usage reports are summed per
//! `(instance, namespace)`; stale reports are ignored with a warning.

use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

/// A rule vote as carried on the wire: `(scope, target, limit)`.
pub type RuleVote = (String, String, u64);
/// A usage report as carried on the wire: `(instance, namespace, bytes)`.
pub type UsageReport = (String, String, u64);

#[derive(Clone, Debug, Default)]
pub struct ClusterQuota {
    /// node -> (scope, target, limit) votes from that node's last heartbeat.
    votes: HashMap<String, Vec<RuleVote>>,
    /// (instance, namespace) -> (node, bytes, when).
    usage: BTreeMap<(String, String), HashMap<String, (u64, Instant)>>,
}

impl ClusterQuota {
    /// Replace one peer's votes and usage. An empty vote list is an abstention
    /// on every target, not a vote against quotas.
    pub fn observe(&mut self, node: &str, votes: Vec<RuleVote>, usage: Vec<UsageReport>) {
        self.votes.insert(node.to_owned(), votes);
        let now = Instant::now();
        for (instance, namespace, bytes) in usage {
            self.usage
                .entry((instance, namespace))
                .or_default()
                .insert(node.to_owned(), (bytes, now));
        }
    }

    pub fn forget(&mut self, node: &str) {
        self.votes.remove(node);
        for reports in self.usage.values_mut() {
            reports.remove(node);
        }
    }

    /// Plurality value for a `(scope, target)` across all voting peers. Ties
    /// mean no consensus; abstentions are simply absent from the counts.
    #[must_use]
    pub fn consensus(&self, scope: &str, target: &str) -> Option<u64> {
        let mut counts: HashMap<u64, usize> = HashMap::new();
        for votes in self.votes.values() {
            for (v_scope, v_target, limit) in votes {
                if v_scope == scope && v_target == target {
                    *counts.entry(*limit).or_default() += 1;
                }
            }
        }
        let mut top = 0usize;
        let mut winner: Option<u64> = None;
        let mut tied = false;
        for (limit, count) in counts {
            if count > top {
                top = count;
                winner = Some(limit);
                tied = false;
            } else if count == top {
                tied = true;
            }
        }
        if tied { None } else { winner }
    }

    /// Sum of fresh usage reports for `(instance, namespace)`, plus the local
    /// value supplied by the caller. Reports older than `max_age` are ignored.
    #[must_use]
    pub fn global_usage(
        &self,
        instance: &str,
        namespace: &str,
        max_age: std::time::Duration,
    ) -> u64 {
        let Some(reports) = self.usage.get(&(instance.to_owned(), namespace.to_owned())) else {
            return 0;
        };
        let now = Instant::now();
        reports
            .values()
            .filter(|(_, when)| now.duration_since(*when) <= max_age)
            .map(|(bytes, _)| *bytes)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plurality_with_abstentions_and_ties() {
        let mut quota = ClusterQuota::default();
        quota.observe(
            "a",
            vec![("namespace".into(), "team/*".into(), 100)],
            vec![],
        );
        quota.observe("b", vec![], vec![]); // abstains
        assert_eq!(quota.consensus("namespace", "team/*"), Some(100));

        quota.observe(
            "c",
            vec![("namespace".into(), "team/*".into(), 200)],
            vec![],
        );
        assert_eq!(quota.consensus("namespace", "team/*"), None); // tie

        quota.observe(
            "d",
            vec![("namespace".into(), "team/*".into(), 100)],
            vec![],
        );
        assert_eq!(quota.consensus("namespace", "team/*"), Some(100));
    }

    #[test]
    fn fresh_usage_is_summed_and_stale_is_ignored() {
        let mut quota = ClusterQuota::default();
        quota.observe(
            "a",
            vec![],
            vec![("default".into(), "forge|repo".into(), 40)],
        );
        assert_eq!(
            quota.global_usage("default", "forge|repo", std::time::Duration::from_secs(30)),
            40
        );
        assert_eq!(
            quota.global_usage("default", "forge|repo", std::time::Duration::ZERO),
            0
        );
    }
}
