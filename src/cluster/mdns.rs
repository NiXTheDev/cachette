//! mDNS responder + browser for cluster discovery (plan task 28 / M13).
//!
//! This node advertises itself as `_cachette._tcp.local.` with a TXT record
//! carrying `node_id`, `fingerprint`, and `port`, and browses the same service
//! type for peers. Link-local semantics (`set_link_local_only`) keep the
//! announcement on the local segment, matching mDNS's link-scoped nature.
//!
//! Discovery is best-effort: a host with no usable multicast interface (a
//! typical VPS) simply delivers no events, which is **not** an error (m10).
//! Only daemon creation / registration / browse failures bubble up, and the
//! caller logs them and continues with seeds only.
//!
//! TXT records are advisory: the authoritative identity is the peer's
//! certificate fingerprint, so a resolved record whose `node_id`/`fingerprint`
//! is missing is ignored rather than trusted blindly.

use std::net::IpAddr;
use std::sync::Arc;

use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::cluster::PeerTable;
use crate::config::split_host_port;

/// Service type advertised and browsed; `.local.` is the link-local mDNS
/// domain. The service name (`_cachette`) is well under the 15-char RFC 6763
/// limit.
const SERVICE_TYPE: &str = "_cachette._tcp.local.";

/// Keeps the mDNS daemon and its browse thread alive; tears both down on drop.
pub struct MdnsHandle {
    daemon: ServiceDaemon,
    browse: Option<std::thread::JoinHandle<()>>,
    fullname: String,
}

impl MdnsHandle {
    /// Registered service full-name (`<instance>._cachette._tcp.local.`).
    #[must_use]
    pub fn fullname(&self) -> &str {
        &self.fullname
    }
}

impl Drop for MdnsHandle {
    fn drop(&mut self) {
        // Shutdown closes the event channels, which unblocks and ends the
        // browse thread; joining guarantees no event fires after drop.
        let _ = self.daemon.shutdown();
        if let Some(handle) = self.browse.take() {
            let _ = handle.join();
        }
    }
}

/// Start the responder + browser and feed resolved peers into `peer_table`.
///
/// `advertise` is this node's `host:port` (default: the listen address); only
/// its port is advertised — the responder discovers its own interface
/// addresses (`enable_addr_auto`), which is what link-local mDNS wants.
///
/// # Errors
/// The first `mdns-sd` failure (daemon creation, service construction,
/// registration, or browse start). The daemon is shut down before returning so
/// a failed start never leaks a background thread.
pub fn start(
    advertise: &str,
    node_id: &str,
    fingerprint: &str,
    peer_table: &Arc<PeerTable>,
) -> Result<MdnsHandle, mdns_sd::Error> {
    let daemon = ServiceDaemon::new()?;
    let port = split_host_port(advertise)
        .map(|(_, port)| port)
        .unwrap_or(0);
    let instance = sanitize(node_id, fingerprint);
    let hostname = format!("{}.local.", sanitize(&instance, &instance));
    let port_txt = port.to_string();
    let properties = [
        ("node_id", node_id),
        ("fingerprint", fingerprint),
        ("port", port_txt.as_str()),
    ];
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        &instance,
        &hostname,
        "",
        port,
        &properties[..],
    )
    .map(|info| {
        let mut info = info;
        info.set_link_local_only(true);
        info.enable_addr_auto()
    });
    let info = match info {
        Ok(info) => info,
        Err(err) => {
            let _ = daemon.shutdown();
            return Err(err);
        }
    };
    let fullname = info.get_fullname().to_owned();
    if let Err(err) = daemon.register(info) {
        let _ = daemon.shutdown();
        return Err(err);
    }
    let receiver = match daemon.browse(SERVICE_TYPE) {
        Ok(receiver) => receiver,
        Err(err) => {
            let _ = daemon.shutdown();
            return Err(err);
        }
    };
    // The receiver is a blocking flume channel and the peer table is a std
    // RwLock, so a plain OS thread is enough — no async runtime required.
    let table = Arc::clone(peer_table);
    let self_id = node_id.to_owned();
    let self_fp = fingerprint.to_owned();
    let browse = std::thread::Builder::new()
        .name(String::from("cachette-mdns"))
        .spawn(move || {
            while let Ok(event) = receiver.recv() {
                if let ServiceEvent::ServiceResolved(resolved) = event {
                    on_resolved(&table, &self_id, &self_fp, &resolved);
                }
            }
        })
        .ok();
    Ok(MdnsHandle {
        daemon,
        browse,
        fullname,
    })
}

/// Fold one resolved service into the peer table (skipping this node).
fn on_resolved(table: &PeerTable, self_id: &str, self_fp: &str, resolved: &ResolvedService) {
    let node_id = resolved.get_property_val_str("node_id").unwrap_or_default();
    let fingerprint = resolved
        .get_property_val_str("fingerprint")
        .unwrap_or_default();
    // Identity is mandatory and self-records are the responder's own echo.
    if fingerprint.is_empty() || node_id == self_id || fingerprint == self_fp {
        return;
    }
    let port = resolved
        .get_property_val_str("port")
        .and_then(|raw| raw.parse::<u16>().ok())
        .unwrap_or(resolved.port);
    let Some(addr) = pick_address(resolved) else {
        return;
    };
    let endpoint = render_addr(addr, port);
    let now = u64::try_from(crate::auth::now_secs()).unwrap_or(0);
    table.observe_discovered(node_id, fingerprint, &endpoint, now);
    tracing::debug!(node_id, fingerprint, addr = %endpoint, "mDNS peer discovered");
}

/// Prefer a usable IPv4 address, then any IPv4, then any address at all.
fn pick_address(resolved: &ResolvedService) -> Option<IpAddr> {
    let mut fallback = None;
    let mut ipv4_fallback = None;
    for scoped in &resolved.addresses {
        let ip = scoped.to_ip_addr();
        if ip.is_ipv4() && !ip.is_loopback() && !ip.is_unspecified() {
            return Some(ip);
        }
        if ip.is_ipv4() && ipv4_fallback.is_none() {
            ipv4_fallback = Some(ip);
        }
        if fallback.is_none() {
            fallback = Some(ip);
        }
    }
    ipv4_fallback.or(fallback)
}

/// `ip:port` dial target; IPv6 literals are bracketed.
fn render_addr(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

/// Sanitize an mDNS instance/host label: keep `[A-Za-z0-9_-]`, map the rest to
/// `-`. Falls back to `fallback` when nothing usable remains.
fn sanitize(raw: &str, fallback: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect();
    if cleaned.trim_matches('-').is_empty() {
        fallback.to_owned()
    } else {
        cleaned
    }
}
