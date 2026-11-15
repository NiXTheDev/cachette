//! Finalize-time content-defined chunking (v1.1 workstream B; docs/cdc.md).
//!
//! FastCDC-style cutting, hand-rolled on the Gear rolling hash
//! (`h = h<<1 + GEAR[byte]`), no new crate. The Gear table and the two
//! normalization masks are computed at compile time from a fixed seed, so
//! identical payloads chunk identically on every node across releases —
//! that determinism is the entire dedup contract. The algorithm version is
//! pinned by [`CDC_ALGO`]; any change to the cutting rules must namespace
//! new chunk ids before any content rolls under them.
//!
//! This module is only the splitter. The file/manifest/ref wiring lives in
//! [`crate::storage::fs`], and chunk content IDs reuse
//! [`crate::storage::digest::hash_bytes`] (same blake3-16 routine, per the
//! task-41 note).

/// Algorithm version of the cutting rules below. Chunk content IDs are
/// stable across nodes and versions exactly as long as this name is;
/// anything that changes boundary behavior must publish under a new name.
pub const CDC_ALGO: &str = "gear-fastcdc-v1";

/// Default `[storage.cdc] avg_chunk_bytes` target (128 KiB) - the docs
/// example at `docs/cdc.md` derives min 32 KiB / max 512 KiB from it.
pub const DEFAULT_AVG_CHUNK_BYTES: u64 = 128 * 1024;

/// Validation floor for `avg_chunk_bytes` (32 KiB): below it chunk files pay
/// their per-file overhead for ever-smaller dedup wins.
pub const MIN_AVG_CHUNK_BYTES: u64 = 32 * 1024;

/// Validation ceiling for `avg_chunk_bytes` (1 MiB): above it the max bound
/// (`avg * 4`) exceeds the per-chunk finalize buffering budget.
pub const MAX_AVG_CHUNK_BYTES: u64 = 1024 * 1024;

/// Fixed seed for the compile-time tables: the first 64 bits of the
/// hexadecimal expansion of pi - content-free, stable, and citable.
const GEAR_SEED: u64 = 0x243F_6A88_85A3_08D3;

/// Knuth 64-bit LCG constants stepping the seed through the table.
const LCG_MULT: u64 = 6_364_136_223_846_793_005;
const LCG_STEP: u64 = 1_442_695_040_888_963_407;

/// The Gear table, indexed by a byte value. Each row is a successive LCG
/// state off the fixed seed, so the table is a compile-time constant and
/// identical in every binary built from this source.
const fn build_gear() -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut state = GEAR_SEED;
    let mut i = 0;
    while i < table.len() {
        state = state.wrapping_mul(LCG_MULT).wrapping_add(LCG_STEP);
        table[i] = state;
        i += 1;
    }
    table
}

static GEAR: [u64; 256] = build_gear();

/// A cut mask with `bits` high bits set: clearing requires the top `bits`
/// window bits to all be zero, probability `2^-bits` per window shift.
const fn build_mask(bits: u32) -> u64 {
    if bits == 0 {
        return 0;
    }
    u64::MAX << (64 - bits)
}

/// Chunk-size bounds derived from the configured average
/// (`min = avg/4`, `max = avg * 4`; docs/cdc.md). Same `avg`, same chunking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CdcParams {
    min_chunk_bytes: u64,
    avg_chunk_bytes: u64,
    max_chunk_bytes: u64,
}

impl CdcParams {
    /// Build the bounds from a configured average. The value is expected to
    /// have passed `[storage.cdc]` validation
    /// ([`MIN_AVG_CHUNK_BYTES`](self::MIN_AVG_CHUNK_BYTES)..
    /// [`MAX_AVG_CHUNK_BYTES`](self::MAX_AVG_CHUNK_BYTES)); smaller values
    /// still behave correctly (the bounds just collapse) for unit tests.
    #[must_use]
    pub fn new(avg_chunk_bytes: u64) -> Self {
        Self {
            min_chunk_bytes: avg_chunk_bytes / 4,
            avg_chunk_bytes,
            max_chunk_bytes: avg_chunk_bytes * 4,
        }
    }

    /// A cut is suppressed before this length; only a stream end can emit a
    /// shorter (final) chunk.
    #[must_use]
    pub const fn min_chunk_bytes(&self) -> u64 {
        self.min_chunk_bytes
    }

    /// The normalization pivot: the score mask tightens at this length.
    #[must_use]
    pub const fn avg_chunk_bytes(&self) -> u64 {
        self.avg_chunk_bytes
    }

    /// Unconditional cut above this length.
    #[must_use]
    pub const fn max_chunk_bytes(&self) -> u64 {
        self.max_chunk_bytes
    }
}

/// Stateful FastCDC-style splitter over one byte stream (docs/cdc.md).
///
/// Cut scoring per byte: `hash & mask == 0` with the mask chosen from the
/// current chunk length — below the average, `mask(raw-1)` (looser, cut
/// probability `2^-(raw-1)` with `raw = floor(log2(avg))`); at/above the
/// average, `mask(raw)`. No cuts before [`CdcParams::min_chunk_bytes`];
/// unconditional cut at [`CdcParams::max_chunk_bytes`]. The trailing
/// partial chunk flushes through [`CdcSplitter::finish`].
#[derive(Clone, Debug)]
pub struct CdcSplitter {
    params: CdcParams,
    /// `mask(raw - 1)` for the lower (below-average) normalization level.
    mask_tame: u64,
    /// `mask(raw)` for the upper (at/above-average) level.
    mask_norm: u64,
    /// Gear hash of everything fed since the last cut.
    hash: u64,
    /// Bytes consumed into the currently open chunk.
    chunk_len: u64,
}

impl CdcSplitter {
    /// A splitter for `params`, ready to score a fresh stream.
    #[must_use]
    pub fn new(params: CdcParams) -> Self {
        let raw = params.avg_chunk_bytes.max(2).ilog2();
        Self {
            params,
            mask_tame: build_mask(raw.saturating_sub(1)),
            mask_norm: build_mask(raw),
            hash: 0,
            chunk_len: 0,
        }
    }

    /// Score `data` as the next bytes of the stream and return the length
    /// of each chunk completed by exactly these bytes, in order and
    /// contiguous from the stream position. The returned lengths always
    /// carve the consumed prefix without gaps; slice the fed prefix with
    /// them in a running sum (the per-chunk payload belongs to the caller,
    /// keeping buffers O(max chunk) not O(stream)).
    ///
    /// The rolling-hash state lives across calls, so boundaries do not
    /// depend on how the stream was cut into feeds — two feeds of the same
    /// bytes chunk identically however they are sliced.
    #[must_use]
    pub fn feed(&mut self, data: &[u8]) -> Vec<usize> {
        let params = self.params;
        let (mask_tame, mask_norm) = (self.mask_tame, self.mask_norm);
        let mut hash = self.hash;
        let mut chunk_len = self.chunk_len;
        let mut done = Vec::new();

        for &byte in data {
            hash = hash.wrapping_shl(1).wrapping_add(GEAR[byte as usize]);
            chunk_len += 1;
            // mask selection is cheap enough unconditional; `max` cuts first
            // in `(max || ...)` so the mask branch is pointless at the cap.
            let mask = if chunk_len >= params.avg_chunk_bytes {
                mask_norm
            } else {
                mask_tame
            };
            let cut = chunk_len >= params.max_chunk_bytes
                || (chunk_len >= params.min_chunk_bytes && hash & mask == 0);
            if cut {
                done.push(chunk_len as usize);
                hash = 0;
                chunk_len = 0;
            }
        }

        self.hash = hash;
        self.chunk_len = chunk_len;
        done
    }

    /// Flush the stream: the trailing partial chunk (if any) is emitted as
    /// the final chunk, which may be shorter than `min` but never longer
    /// than `max`. `None` when the stream ended exactly on a cut boundary
    /// or nothing was fed (`None`, not a zero-length chunk). The splitter
    /// resets to a fresh-stream state after this.
    #[must_use]
    pub fn finish(&mut self) -> Option<usize> {
        let tail = (self.chunk_len > 0).then_some(self.chunk_len as usize);
        self.hash = 0;
        self.chunk_len = 0;
        tail
    }

    /// Chunk lengths of a fully buffered byte slice in one call, i.e.
    /// [`feed`](CdcSplitter::feed) + [`finish`](CdcSplitter::finish)
    /// combined. The convenience of the two-call protocol for tests and
    /// in-memory payloads; real payloads feed slices to stay bounded.
    #[must_use]
    pub fn split_all(params: CdcParams, data: &[u8]) -> Vec<usize> {
        let mut splitter = Self::new(params);
        let mut lengths = splitter.feed(data);
        if let Some(tail) = splitter.finish() {
            lengths.push(tail);
        }
        lengths
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AVG: u64 = 16 * 1024;
    const MIN: u64 = AVG / 4;
    const MAX: u64 = AVG * 4;

    /// Tiny xorshift*: enough shuffle for test payloads, zero deps.
    fn next(state: &mut u64) -> u64 {
        *state ^= *state >> 12;
        *state ^= *state << 25;
        *state ^= *state >> 27;
        *state = state.wrapping_mul(0x2545F4914F6CDD1D);
        *state
    }

    fn payload(bytes: usize) -> Vec<u8> {
        let mut state = 0xfeed_face_dead_beef_u64;
        (0..bytes).map(|_| next(&mut state) as u8).collect()
    }

    /// Feed the payload through awkward slice sizes and collect every chunk
    /// (feeds + finish flush).
    fn chunked_in_slices(data: &[u8], slice: usize) -> Vec<usize> {
        let mut splitter = CdcSplitter::new(CdcParams::new(AVG));
        let mut lengths = Vec::new();
        for window in data.chunks(slice.max(1)) {
            lengths.append(&mut splitter.feed(window));
        }
        if let Some(tail) = splitter.finish() {
            lengths.push(tail);
        }
        lengths
    }

    fn covers(lengths: &[usize]) -> usize {
        lengths.iter().sum()
    }

    #[test]
    fn params_bounds_match_the_documented_window() {
        let params = CdcParams::new(128 * 1024);
        assert_eq!(params.min_chunk_bytes(), 32 * 1024);
        assert_eq!(params.avg_chunk_bytes(), 128 * 1024);
        assert_eq!(params.max_chunk_bytes(), 512 * 1024);
    }

    #[test]
    fn algo_pin_is_the_documented_version() {
        assert_eq!(CDC_ALGO, "gear-fastcdc-v1");
    }

    #[test]
    fn empty_stream_yields_no_chunks_and_finish_is_none() {
        let mut splitter = CdcSplitter::new(CdcParams::new(AVG));
        assert!(splitter.feed(b"").is_empty());
        assert_eq!(splitter.finish(), None);
        // A reset splitter stays ready for a fresh stream.
        assert_eq!(CdcSplitter::new(CdcParams::new(64)).finish(), None);
    }

    #[test]
    fn short_input_below_min_is_one_final_tail() {
        let data = payload(1234);
        assert!(1234 < MIN as usize, "test setup: shorter than min");
        let lengths = chunked_in_slices(&data, 100);
        assert_eq!(lengths, vec![1234]);
    }

    #[test]
    fn every_chunk_respects_the_min_max_window() {
        let data = payload(8 * 1024 * 1024);
        let lengths = chunked_in_slices(&data, 9237);
        assert_eq!(covers(&lengths), data.len(), "no byte lost");
        for (i, len) in lengths.iter().enumerate() {
            let last = i == lengths.len() - 1;
            assert!(
                *len >= MIN as usize || last,
                "chunk {i} is {len} < min {MIN} before the tail"
            );
            assert!(*len <= MAX as usize, "chunk {i} is {len} > max {MAX}");
        }
    }

    #[test]
    fn mean_chunk_size_lands_in_the_target_neighbourhood() {
        let data = payload(16 * 1024 * 1024);
        let lengths = chunked_in_slices(&data, u64::MAX as usize);
        let mean = covers(&lengths) / lengths.len();
        let target = AVG as usize;
        assert!(
            (0.5..=1.5).contains(&(mean as f64 / target as f64)),
            "mean chunk {mean} drifted from the {target} target over {} chunks",
            lengths.len()
        );
    }

    #[test]
    fn boundaries_are_independent_of_how_the_stream_is_fed() {
        let data = payload(4 * 1024 * 1024);
        let whole = chunked_in_slices(&data, usize::MAX);
        let odd = chunked_in_slices(&data, 1073);
        let even = chunked_in_slices(&data, 64 * 1024);
        assert_eq!(whole, odd, "1073-byte leads must not move boundaries");
        assert_eq!(whole, even, "64KiB slices must not move boundaries");
    }

    #[test]
    fn a_shared_prefix_chunks_identically_up_to_the_divergence() {
        // THE dedup property: two streams that agree on a prefix produce
        // identical chunk boundaries up to the first chunk overlapping the
        // divergence point.
        let base = payload(2 * 1024 * 1024);
        let tail = payload(1024 * 1024);
        let flipped = {
            let mut copy = tail.clone();
            copy[0] ^= 0xff;
            copy
        };
        let a = chunked_in_slices(
            &base.iter().chain(tail.iter()).copied().collect::<Vec<u8>>(),
            4096,
        );
        let b = chunked_in_slices(
            &base
                .iter()
                .chain(flipped.iter())
                .copied()
                .collect::<Vec<u8>>(),
            4096,
        );

        let mut consumed = 0;
        for (i, (left, right)) in a.iter().zip(b.iter()).enumerate() {
            if consumed >= base.len() {
                break;
            }
            assert_eq!(left, right, "chunk {i} differs inside the shared prefix");
            consumed += left;
        }
    }

    #[test]
    fn constant_input_stays_inside_the_window_and_covers_exactly() {
        // Degenerate bytes are free to hit the probabilistic mask earlier;
        // the hard invariants are the min/max window and exact coverage.
        let data = vec![0xff_u8; 8 * MAX as usize];
        let lengths = chunked_in_slices(&data, 9001);
        assert_eq!(covers(&lengths), data.len());
        for (i, len) in lengths.iter().enumerate() {
            let last = i == lengths.len() - 1;
            assert!(
                *len >= MIN as usize || last,
                "chunk {i} is {len} < min {MIN} before the tail"
            );
            assert!(*len <= MAX as usize, "chunk {i} is {len} > max {MAX}");
        }
    }
}
