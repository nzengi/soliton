//! `PoolState` raw byte layout + the incremental Poseidon Merkle tree.
//!
//! We use a fixed, manually-offset layout (no Borsh) so the BPF program reads
//! and writes the account data with zero allocation. All field elements are
//! 32-byte little-endian (the `soliton-poseidon` canonical encoding).
//!
//! Layout (offsets in bytes):
//! ```text
//!   0   magic            [u8; 4]   = b"SPL1"
//!   4   vault_bump       u8
//!   5   _pad             [u8; 3]
//!   8   next_index       u64 LE
//!  16   root             [u8; 32]   current tree root
//!  48   hist_head        u32 LE     ring-buffer write cursor
//!  52   hist_len         u32 LE     number of valid roots in history
//!  56   root_history     [[u8;32]; ROOT_HISTORY]
//!  ...  frontier         [[u8;32]; DEPTH]
//!  ...  queue_len        u32 LE
//!  ...  output_queue     [[u8;32]; QUEUE_CAP]
//! ```

use alloc::boxed::Box;

use soliton_poseidon as poseidon;
use solana_poseidon::{hashv, Endianness, Parameters};

/// 2-to-1 Merkle hash over 32-byte LE field encodings, via the `sol_poseidon`
/// SYSCALL (circom-BN254). On BPF this is the native syscall (~cheap); on host
/// it is `light-poseidon` — both bit-identical to `soliton_poseidon::hash2`
/// (proven in `crates/soliton-poseidon` Gate A and `cu_pool.rs` Gate G).
///
/// Inputs/outputs are little-endian canonical field bytes (the tree's storage
/// convention), so we use `Endianness::LittleEndian`. Both inputs are always
/// canonical (< modulus), so the syscall never errors on them.
#[inline]
#[allow(deprecated)] // solana-poseidon v3 API is Agave-unstable; intentional.
fn tree_hash2(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], u32> {
    let h = hashv(Parameters::Bn254X5, Endianness::LittleEndian, &[a, b])
        .map_err(|_| err::HASH_FAIL)?;
    Ok(h.to_bytes())
}

pub const DEPTH: usize = 32;
pub const ROOT_HISTORY: usize = 32;
pub const QUEUE_CAP: usize = 64;

pub const MAGIC: [u8; 4] = *b"SPL1";

// Offsets.
pub const OFF_MAGIC: usize = 0;
pub const OFF_BUMP: usize = 4;
pub const OFF_NEXT_INDEX: usize = 8;
pub const OFF_ROOT: usize = 16;
pub const OFF_HIST_HEAD: usize = 48;
pub const OFF_HIST_LEN: usize = 52;
pub const OFF_HISTORY: usize = 56;
pub const OFF_FRONTIER: usize = OFF_HISTORY + ROOT_HISTORY * 32; // 56 + 1024 = 1080
pub const OFF_QUEUE_LEN: usize = OFF_FRONTIER + DEPTH * 32; // 1080 + 1024 = 2104
pub const OFF_QUEUE: usize = OFF_QUEUE_LEN + 4; // 2108
pub const POOL_STATE_LEN: usize = OFF_QUEUE + QUEUE_CAP * 32; // 2108 + 2048 = 4156

#[inline]
fn rd_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}
#[inline]
fn wr_u32(data: &mut [u8], off: usize, v: u32) {
    data[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn rd_u64(data: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[off..off + 8]);
    u64::from_le_bytes(b)
}
#[inline]
fn wr_u64(data: &mut [u8], off: usize, v: u64) {
    data[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn rd_32(data: &[u8], off: usize) -> [u8; 32] {
    let mut b = [0u8; 32];
    b.copy_from_slice(&data[off..off + 32]);
    b
}
#[inline]
fn wr_32(data: &mut [u8], off: usize, v: &[u8; 32]) {
    data[off..off + 32].copy_from_slice(v);
}

/// Error codes.
pub mod err {
    pub const BAD_LEN: u32 = 0x100;
    pub const BAD_MAGIC: u32 = 0x101;
    pub const ALREADY_INIT: u32 = 0x102;
    pub const TREE_FULL: u32 = 0x103;
    pub const QUEUE_FULL: u32 = 0x104;
    pub const QUEUE_EMPTY: u32 = 0x105;
    pub const HASH_FAIL: u32 = 0x106;
}

/// Compute the empty-subtree root for each level 0..=DEPTH via the `sol_poseidon`
/// SYSCALL. Returns the array of LE-encoded roots; index `l` is the root of an
/// all-empty subtree of height `l`.
/// Heap-allocated (Box) so the 1056-byte table does NOT land on the caller's
/// SBF stack frame (the 4096-byte stack cap is tight in `shield`/`flush`).
#[inline(never)]
pub fn empty_roots() -> Result<Box<[[u8; 32]; DEPTH + 1]>, u32> {
    let mut out = Box::new([[0u8; 32]; DEPTH + 1]);
    out[0] = poseidon::fr_to_le(&poseidon::empty_leaf());
    for level in 1..=DEPTH {
        let prev = out[level - 1];
        out[level] = tree_hash2(&prev, &prev)?;
    }
    Ok(out)
}

/// The root of an all-empty depth-DEPTH tree (the initial root).
pub fn empty_root() -> Result<[u8; 32], u32> {
    Ok(empty_roots()?[DEPTH])
}

/// View over the raw PoolState bytes.
pub struct Pool<'a> {
    pub data: &'a mut [u8],
}

impl<'a> Pool<'a> {
    pub fn load(data: &'a mut [u8]) -> Result<Self, u32> {
        if data.len() < POOL_STATE_LEN {
            return Err(err::BAD_LEN);
        }
        if data[OFF_MAGIC..OFF_MAGIC + 4] != MAGIC {
            return Err(err::BAD_MAGIC);
        }
        Ok(Self { data })
    }

    /// Initialize a fresh (zeroed) account: set magic, bump, empty tree root,
    /// empty frontier, empty history (with the empty root pushed), empty queue.
    pub fn initialize(data: &'a mut [u8], bump: u8) -> Result<Self, u32> {
        if data.len() < POOL_STATE_LEN {
            return Err(err::BAD_LEN);
        }
        if data[OFF_MAGIC..OFF_MAGIC + 4] == MAGIC {
            return Err(err::ALREADY_INIT);
        }
        // Zero the whole region first.
        for b in data.iter_mut() {
            *b = 0;
        }
        data[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC);
        data[OFF_BUMP] = bump;
        wr_u64(data, OFF_NEXT_INDEX, 0);

        let er = empty_root()?;
        wr_32(data, OFF_ROOT, &er);

        // Frontier starts all-zero (unused until first insert sets level slots).
        // History: push the initial empty root.
        wr_u32(data, OFF_HIST_HEAD, 0);
        wr_u32(data, OFF_HIST_LEN, 0);
        wr_u32(data, OFF_QUEUE_LEN, 0);

        let mut pool = Self { data };
        pool.push_root(&er);
        Ok(pool)
    }

    pub fn bump(&self) -> u8 {
        self.data[OFF_BUMP]
    }
    pub fn next_index(&self) -> u64 {
        rd_u64(self.data, OFF_NEXT_INDEX)
    }
    pub fn root(&self) -> [u8; 32] {
        rd_32(self.data, OFF_ROOT)
    }
    pub fn frontier(&self, level: usize) -> [u8; 32] {
        rd_32(self.data, OFF_FRONTIER + level * 32)
    }
    fn set_frontier(&mut self, level: usize, v: &[u8; 32]) {
        wr_32(self.data, OFF_FRONTIER + level * 32, v);
    }

    /// Push a root into the history ring buffer and set it as current.
    pub fn push_root(&mut self, root: &[u8; 32]) {
        let head = rd_u32(self.data, OFF_HIST_HEAD) as usize;
        wr_32(self.data, OFF_HISTORY + head * 32, root);
        let new_head = ((head + 1) % ROOT_HISTORY) as u32;
        wr_u32(self.data, OFF_HIST_HEAD, new_head);
        let len = rd_u32(self.data, OFF_HIST_LEN);
        if (len as usize) < ROOT_HISTORY {
            wr_u32(self.data, OFF_HIST_LEN, len + 1);
        }
        wr_32(self.data, OFF_ROOT, root);
    }

    /// Is `root` present in the history ring buffer?
    pub fn root_known(&self, root: &[u8; 32]) -> bool {
        let len = rd_u32(self.data, OFF_HIST_LEN) as usize;
        for i in 0..len {
            if &rd_32(self.data, OFF_HISTORY + i * 32) == root {
                return true;
            }
        }
        false
    }

    // ---- output queue --------------------------------------------------------

    pub fn queue_len(&self) -> u32 {
        rd_u32(self.data, OFF_QUEUE_LEN)
    }

    pub fn queue_push(&mut self, cm: &[u8; 32]) -> Result<(), u32> {
        let len = self.queue_len() as usize;
        if len >= QUEUE_CAP {
            return Err(err::QUEUE_FULL);
        }
        wr_32(self.data, OFF_QUEUE + len * 32, cm);
        wr_u32(self.data, OFF_QUEUE_LEN, (len + 1) as u32);
        Ok(())
    }

    /// Pop the front of the queue (FIFO), shifting the rest down. Returns the
    /// popped commitment.
    pub fn queue_pop_front(&mut self) -> Result<[u8; 32], u32> {
        let len = self.queue_len() as usize;
        if len == 0 {
            return Err(err::QUEUE_EMPTY);
        }
        let front = rd_32(self.data, OFF_QUEUE);
        // Shift down.
        for i in 1..len {
            let v = rd_32(self.data, OFF_QUEUE + i * 32);
            wr_32(self.data, OFF_QUEUE + (i - 1) * 32, &v);
        }
        wr_u32(self.data, OFF_QUEUE_LEN, (len - 1) as u32);
        Ok(front)
    }

    // ---- incremental tree insert --------------------------------------------

    /// Incrementally insert `leaf` (LE field bytes), updating the frontier,
    /// next_index, current root, and pushing the new root into history.
    /// Performs exactly DEPTH H2 hashes (one per level). Returns the new root.
    #[inline(never)]
    pub fn insert(&mut self, leaf: &[u8; 32], empty: &[[u8; 32]; DEPTH + 1]) -> Result<[u8; 32], u32> {
        let mut idx = self.next_index();
        if idx >= (1u64 << DEPTH) {
            return Err(err::TREE_FULL);
        }
        let mut cur: [u8; 32] = *leaf;
        for level in 0..DEPTH {
            if idx & 1 == 0 {
                // current node is a LEFT child: record it in the frontier; its
                // right sibling is an all-empty subtree.
                self.set_frontier(level, &cur);
                cur = tree_hash2(&cur, &empty[level])?;
            } else {
                // current node is a RIGHT child: its left sibling is in frontier.
                let left = self.frontier(level);
                cur = tree_hash2(&left, &cur)?;
            }
            idx >>= 1;
        }
        let new_root = cur;
        wr_u64(self.data, OFF_NEXT_INDEX, self.next_index() + 1);
        self.push_root(&new_root);
        Ok(new_root)
    }
}
