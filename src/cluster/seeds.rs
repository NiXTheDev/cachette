//! Static seed parsing for cluster discovery (plan task 28 / M5).
//!
//! `[cluster] seeds` is an array of `host[:port]` strings. The port is
//! optional: when omitted it defaults to the node's own listen port (m5), so
//! `["cache-a", "cache-b"]` on a node listening on `:8080` expands to
//! `cache-a:8080` and `cache-b:8080`. Seeds carry no identity — a seed becomes
//! a full peer only after mDNS or `POST /_internal/peers/hello` supplies
//! `node_id` / `fingerprint` (M5/M13).

use std::net::IpAddr;

use crate::config::split_host_port;

/// One static seed resolved to `host` + `port`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Seed {
    /// Host part as authored (`cache-a`, `10.0.0.1`, `::1`), brackets removed.
    pub host: String,
    /// Explicit port, or the node's listen port when the seed omitted one.
    pub port: u16,
}

impl Seed {
    /// `host:port` dial target; IPv6 hosts are bracketed (`[::1]:8080`).
    #[must_use]
    pub fn addr(&self) -> String {
        render_addr(&self.host, self.port)
    }
}

/// Parse every seed, dropping blank/malformed entries (a bad seed must never
/// block boot).
#[must_use]
pub fn parse_seeds(raw: &[String], default_port: u16) -> Vec<Seed> {
    raw.iter()
        .filter_map(|entry| parse_seed(entry, default_port))
        .collect()
}

/// Parse one `host[:port]` seed. `None` for blank or malformed input.
#[must_use]
pub fn parse_seed(raw: &str, default_port: u16) -> Option<Seed> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some((host, port)) = split_host_port(raw) {
        let host = unbracket(host);
        if host.is_empty() {
            return None;
        }
        return Some(Seed {
            host: host.to_owned(),
            port,
        });
    }
    // No parseable `:port` suffix: the whole entry is the host (bare hostname
    // or IP literal). A leftover colon that is not a valid IPv6 literal means
    // the entry was malformed (`host:bad`), never a seed.
    let host = unbracket(raw);
    if host.is_empty() || host.contains(char::is_whitespace) {
        return None;
    }
    if host.contains(':') && host.parse::<IpAddr>().is_err() {
        return None;
    }
    Some(Seed {
        host: host.to_owned(),
        port: default_port,
    })
}

/// Strip one surrounding `[`/`]` pair from an IPv6 literal.
fn unbracket(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}

/// Render `host:port`, bracketing IPv6 literals.
fn render_addr(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_ports_win_and_omitted_ports_default_to_listen() {
        let raw = vec![
            String::from("cache-a:9001"),
            String::from("cache-b"),
            String::from("10.0.0.3"),
            String::from("[::1]:9002"),
            String::from("  cache-d:9003  "),
        ];
        let seeds = parse_seeds(&raw, 8080);
        assert_eq!(
            seeds,
            vec![
                Seed {
                    host: String::from("cache-a"),
                    port: 9001
                },
                Seed {
                    host: String::from("cache-b"),
                    port: 8080
                },
                Seed {
                    host: String::from("10.0.0.3"),
                    port: 8080
                },
                Seed {
                    host: String::from("::1"),
                    port: 9002
                },
                Seed {
                    host: String::from("cache-d"),
                    port: 9003
                },
            ]
        );
        assert_eq!(seeds[0].addr(), "cache-a:9001");
        assert_eq!(seeds[3].addr(), "[::1]:9002");
    }

    #[test]
    fn malformed_and_blank_seeds_are_dropped() {
        let raw = vec![
            String::new(),
            String::from("   "),
            String::from("host:bad"),
            String::from("bad host:8080"),
            String::from("good:8080"),
        ];
        let seeds = parse_seeds(&raw, 8080);
        assert_eq!(seeds.len(), 1, "{seeds:?}");
        assert_eq!(seeds[0].host, "good");
    }

    #[test]
    fn bare_ipv6_literal_keeps_the_default_port() {
        let seed = parse_seed("2001:db8::1", 8080).expect("bare IPv6 is a host");
        assert_eq!(seed.host, "2001:db8::1");
        assert_eq!(seed.addr(), "[2001:db8::1]:8080");
    }
}
