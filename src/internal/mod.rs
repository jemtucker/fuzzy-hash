mod block_hash;
mod rolling_hash;

use self::block_hash::*;
use self::rolling_hash::*;

const NUM_BLOCK_HASHES: usize = 32;
const MIN_BLOCK_SIZE: u32 = 3;
const SPAMSUM_LENGTH: u32 = 64;
const BASE_64: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const TOTAL_SIZE_MAX: usize = ((MIN_BLOCK_SIZE as usize << (NUM_BLOCK_HASHES - 1)) * SPAMSUM_LENGTH as usize);

#[inline(always)]
fn block_size(index: u32) -> u32 {
    MIN_BLOCK_SIZE << index
}

#[inline(always)]
fn sum_hash(h: u32, byte: u8) -> u32 {
    (h * HASH_PRIME) ^ (byte as u32)
}

#[inline(always)]
fn base_64(h: u32) -> u8 {
    let index = (h % 64) as usize;
    BASE_64.as_bytes()[index]
}

struct Context {
    total_size: usize,
    fixed_size: usize,
    last_hash: u32,
    rolling_hash: AddlerBasedRollingHash,
    block_hashes: [SSDeepBasedBlockHash; NUM_BLOCK_HASHES],
    block_hash_start: usize,
    block_hash_end: usize,

    // TODO Bitflags the shit out of these guys
    need_last_hash: bool,
    is_fixed_size: bool,
}

impl Context {
    pub fn new() -> Context {
        Context {
            total_size: 0,
            fixed_size: 0,
            last_hash: 0,
            rolling_hash: AddlerBasedRollingHash::new(),
            block_hashes: [SSDeepBasedBlockHash::new(); NUM_BLOCK_HASHES],
            block_hash_start: 0,
            block_hash_end: NUM_BLOCK_HASHES - 1,

            // TODO Bitflags the shit out of these guys
            need_last_hash: false,
            is_fixed_size: false,
        }
    }

    pub fn update(&mut self, buffer: &[u8]) {
        // Update the current total size with the buffer length
        if self.total_size <= TOTAL_SIZE_MAX {
            let buffer_size = buffer.len();
            if buffer_size > TOTAL_SIZE_MAX || (TOTAL_SIZE_MAX - buffer_size < self.total_size) {
                self.total_size = TOTAL_SIZE_MAX + 1;
            } else {
                self.total_size += buffer_size;
            }
        }

        // Update the internal hashes with each byte
        for byte in buffer {
            self.step(*byte);
        }
    }

    fn step(&mut self, byte: u8) {
        // Update the rolling hash
        self.rolling_hash.hash(byte);
        let sum = self.rolling_hash.sum();

        // Update the blockhash
        for bh in self.block_hashes.iter_mut() {
            bh.update(byte);
        }

        // Update the last hash
        if self.need_last_hash {
            self.last_hash = sum_hash(self.last_hash, byte);
        }

        for i in 0..self.block_hashes.len() {
            let block_size = block_size(i as u32);

            // Once this condition is false for one block_size it will also evaluate to false for
            // the other: sum === -1 (% 2 * block_size) then sum === -1 (% block_size). Break from
            // the loop.
            if (sum % block_size) != (block_size - 1) {
                break;
            }

            // If we get this far it means it is time to reset!
            if 0 == self.block_hashes[i].index {
                self.try_fork_block_hash();
            }

            {
                let mut block_hash = self.block_hashes[i];

                let hash = block_hash.h;
                let half_hash = block_hash.halfh;
                let digest_index = block_hash.index;

                block_hash.digest.0[digest_index] = base_64(hash);
                block_hash.halfdigest = base_64(half_hash);
            }

            /* TODO: We can have a problem with the tail overflowing. The
            * easiest way to cope with this is to only reset the
            * normal hash if we have room for more characters in
            * our signature. This has the effect of combining the
            * last few pieces of the message into a single piece
            * */
            if self.block_hashes[i].index < (SPAMSUM_LENGTH - 1) as usize {
                let mut block_hash = self.block_hashes[i];

                block_hash.index += 1;
                block_hash.h = HASH_INIT;
                block_hash.digest.0[block_hash.index] = 0;

                if block_hash.index < (SPAMSUM_LENGTH / 2) as usize {
                    block_hash.halfh = HASH_INIT;
                    block_hash.halfdigest = 0;
                }
            } else {
                self.try_reduce_block_hash();
            }

        }

    }

    fn try_fork_block_hash(&mut self) {
        if self.block_hash_end >= self.block_hashes.len() {
            return;
        }

        let o = self.block_hash_end - 1;
        let n = self.block_hash_end;

        let temp_h = self.block_hashes[o].h;
        let temp_halfh = self.block_hashes[o].halfh;

        self.block_hashes[n].h = temp_h;
        self.block_hashes[n].halfh = temp_halfh;
        self.block_hashes[n].digest.0[0] = 0;
        self.block_hashes[n].halfdigest = 0;
        self.block_hashes[n].digest_len = 0;

        self.block_hash_end += 1;
    }

    fn try_reduce_block_hash(&mut self) {
        // We need at least two active hashes to be able to reduce the hash
        let num_hashes = self.block_hash_end - self.block_hash_start;
        if num_hashes < 2 {
            return;
        }

        // First block size estimation would chose this one or smaller, no reduction possible.
        let less_than_max_size = self.total_size <= TOTAL_SIZE_MAX;
        let current_size = if self.is_fixed_size { self.fixed_size } else { self.total_size };
        let current_block_size = block_size(self.block_hash_start as u32) * SPAMSUM_LENGTH;
        if less_than_max_size && (current_block_size >= current_size as u32) {
            return;
        }

        // Adjustment of estimation would result in this block size being selected.
        let index = self.block_hashes.len() + 1;
        let digest_index = self.block_hashes[index].index;
        if digest_index < (SPAMSUM_LENGTH / 2) as usize {
            return;
        }

        // If we get this far then it is time to increase the block size. Onto the next one!
        self.block_hash_start += 1;
    }

    pub fn digest(&mut self) -> &[u8] {
        unimplemented!();
    }
}
