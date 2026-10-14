//! Plan task 30 acceptance (criterion 6): least-loaded placement with the
//! capacity filter, fill% ranking, and the three tiebreak methods.
//!
//! Kept in its own integration binary so the `CACHETTE__CLUSTER__TIEBREAK`
//! environment override test cannot race the process-global environment of the
//! other cluster tests.
//!
//! The fixture is the plan's exact one: three nodes with fixed heartbeats
//! `{A: total 100, used 90}, {B: total 100, used 60}, {C: total 100, used 60}`.
//! With `min_free = 20%` (= 20 bytes) an UNKNOWN-size reservation filters A
//! (`free = 10 < 20`) and ties B and C at 0.6 fill.

use std::collections::HashMap;

use cachette::cluster::PeerRecord;
use cachette::cluster::placement::{Placement, SeededRng, place};
use cachette::config::{MinFree, Tiebreak};

/// One healthy peer record with the given live B3 numbers.
fn peer(node_id: &str, used: u64, total: u64) -> PeerRecord {
    PeerRecord {
        node_id: node_id.to_owned(),
        fingerprint: format!("FP-{node_id}"),
        addr: format!("10.0.0.{}:9000", node_id.as_bytes()[0]),
        used_bytes: used,
        total_bytes: total,
        healthy: true,
        last_hello: 1,
    }
}

/// The criterion-6 three-node fixture (A over its floor, B and C tied).
fn fixture() -> Vec<PeerRecord> {
    vec![peer("A", 90, 100), peer("B", 60, 100), peer("C", 60, 100)]
}

fn min_free() -> MinFree {
    MinFree::Fraction(0.2)
}

/// Place repeatedly and collect the chosen node ids.
fn picks(placement: &Placement, peers: &[PeerRecord], iterations: usize) -> Vec<String> {
    (0..iterations)
        .map(|_| {
            placement
                .place(peers, None, min_free(), 0)
                .expect("a healthy peer admits an unknown-size reservation")
                .node_id
        })
        .collect()
}

#[test]
fn capacity_filter_excludes_the_under_floored_peer_for_every_tiebreak() {
    for tiebreak in [
        Tiebreak::Random,
        Tiebreak::RoundRobin,
        Tiebreak::Progressive,
    ] {
        let placement = Placement::with_seed(tiebreak, 42);
        for picked in picks(&placement, &fixture(), 20) {
            assert!(
                picked == "B" || picked == "C",
                "A must be filtered by the capacity floor, got {picked}"
            );
        }
    }
}

#[test]
fn random_tiebreak_stays_within_fifteen_percent_of_a_fifty_fifty_split() {
    let placement = Placement::with_seed(Tiebreak::Random, 0x5EED);
    let results = picks(&placement, &fixture(), 20);
    let b = results.iter().filter(|id| *id == "B").count();
    let c = results.iter().filter(|id| *id == "C").count();
    assert_eq!(b + c, 20);
    assert!(b > 0 && c > 0, "both tied nodes must appear: {results:?}");
    assert!(
        (7..=13).contains(&b),
        "expected ±15% of 50/50 over 20, got B={b} C={c}: {results:?}"
    );
}

#[test]
fn roundrobin_alternates_between_the_tied_nodes() {
    let placement = Placement::with_seed(Tiebreak::RoundRobin, 1);
    let results = picks(&placement, &fixture(), 20);
    let expected: Vec<String> = (0..20)
        .map(|index| if index % 2 == 0 { "B" } else { "C" }.to_owned())
        .collect();
    assert_eq!(results, expected, "round-robin must be B, C, B, C, …");
}

#[test]
fn progressive_falls_back_to_random_on_an_exact_tie_without_alternating() {
    let placement = Placement::with_seed(Tiebreak::Progressive, 3);
    let results = picks(&placement, &fixture(), 20);
    assert!(
        results.iter().all(|id| id == "B" || id == "C"),
        "exact-tie fallback must stay within the tied set: {results:?}"
    );
    let alternating: Vec<String> = (0..20)
        .map(|index| if index % 2 == 0 { "B" } else { "C" }.to_owned())
        .collect();
    assert_ne!(
        results, alternating,
        "a full-precision tie falls back to random, not alternation"
    );
}

#[test]
fn progressive_deterministically_breaks_the_fourth_decimal() {
    // B: 6000/10000 = 0.6000 vs C: 6001/10000 = 0.6001 — progressive compares
    // decimal digits and stops at the 4th, choosing B on every run.
    let peers = vec![peer("B", 6_000, 10_000), peer("C", 6_001, 10_000)];
    let placement = Placement::with_seed(Tiebreak::Progressive, 99);
    for _ in 0..20 {
        let picked = placement.place(&peers, None, min_free(), 0).expect("place");
        assert_eq!(picked.node_id, "B");
    }
}

#[test]
fn unhealthy_peers_are_never_chosen_even_when_least_loaded() {
    // D would be the least loaded (0% fill) but is unhealthy; it must never
    // be returned by any tiebreak.
    for tiebreak in [
        Tiebreak::Random,
        Tiebreak::RoundRobin,
        Tiebreak::Progressive,
    ] {
        let mut peers = fixture();
        let mut dead = peer("D", 0, 100);
        dead.healthy = false;
        peers.push(dead);
        let placement = Placement::with_seed(tiebreak, 13);
        for picked in picks(&placement, &peers, 20) {
            assert!(
                picked == "B" || picked == "C",
                "unhealthy D must never be chosen, got {picked}"
            );
        }
    }
}

#[test]
fn known_size_over_capacity_places_nowhere() {
    let placement = Placement::with_seed(Tiebreak::Random, 5);
    // B/C have 40 free; a 41-byte reservation does not fit on any peer.
    assert!(
        placement
            .place(&fixture(), Some(41), min_free(), 0)
            .is_none()
    );
    // Exactly 40 free admits.
    let picked = placement
        .place(&fixture(), Some(40), min_free(), 0)
        .expect("40 bytes fit on B/C");
    assert!(picked.node_id == "B" || picked.node_id == "C");
}

#[test]
fn single_node_places_on_self() {
    let peers = vec![peer("SELF", 10, 100)];
    let picked = place(
        &peers,
        None,
        min_free(),
        0,
        Tiebreak::Random,
        &mut SeededRng::from_seed(5),
        &mut HashMap::new(),
    )
    .expect("self is a candidate like any peer");
    assert_eq!(picked.node_id, "SELF");
}

#[test]
fn tiebreak_env_override_switches_the_configured_method() {
    let dir = std::env::temp_dir().join(format!("cachette-placement-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("cachette.toml");
    std::fs::write(&path, "[cluster]\ntiebreak = \"roundrobin\"\n").expect("write config");

    let baseline = cachette::config::load(Some(path.clone())).expect("load baseline");
    assert_eq!(baseline.cluster.tiebreak, Tiebreak::RoundRobin);

    // SAFETY: single-threaded within this test and no other test in this
    // binary reads the process environment.
    unsafe { std::env::set_var("CACHETTE__CLUSTER__TIEBREAK", "random") };
    let overridden = cachette::config::load(Some(path.clone())).expect("load override");
    unsafe { std::env::remove_var("CACHETTE__CLUSTER__TIEBREAK") };

    assert_eq!(
        overridden.cluster.tiebreak,
        Tiebreak::Random,
        "CACHETTE__CLUSTER__TIEBREAK must win over the file value"
    );

    // The switched method is what placement consumes.
    let placement = Placement::with_seed(overridden.cluster.tiebreak, 7);
    assert_eq!(placement.tiebreak(), Tiebreak::Random);
    assert!(
        picks(&placement, &fixture(), 20)
            .iter()
            .all(|id| id == "B" || id == "C")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn roundrobin_free_function_advances_across_successive_calls() {
    let mut rng = SeededRng::from_seed(1);
    let mut cursors = HashMap::new();
    let peers = fixture();
    let sequence: Vec<String> = (0..4)
        .map(|_| {
            place(
                &peers,
                None,
                min_free(),
                0,
                Tiebreak::RoundRobin,
                &mut rng,
                &mut cursors,
            )
            .expect("place")
            .node_id
        })
        .collect();
    assert_eq!(sequence, vec!["B", "C", "B", "C"]);
}
