use super::SPAMSUM_LENGTH;
use super::sum_hash;

pub trait BlockHash {
    fn update(&mut self, byte: u8);
}

pub const HASH_PRIME: u32 = 0x01000193;
pub const HASH_INIT: u32 = 0x28021967;

#[derive(Copy, Clone)]
pub struct SSDeepBasedBlockHash {
    pub h: u32,
    pub halfh: u32,
    pub digest: ByteArraySSLen,
    pub halfdigest: u8,
    pub index: usize,
    pub digest_len: usize,
}

impl BlockHash for SSDeepBasedBlockHash {
    fn update(&mut self, byte: u8) {
        self.h = sum_hash(self.h, byte);
        self.halfh = sum_hash(self.halfh, byte);
    }
}

impl SSDeepBasedBlockHash {
    pub fn new() -> SSDeepBasedBlockHash {
        SSDeepBasedBlockHash {
            h: HASH_INIT,
            halfh: HASH_INIT,
            digest: ByteArraySSLen([0; SPAMSUM_LENGTH as usize]),
            halfdigest: 0,
            index: 0,
            digest_len: 0,
        }
    }
}

use std::clone::Clone;

#[derive(Copy)]
pub struct ByteArraySSLen(pub [u8; SPAMSUM_LENGTH as usize]);

impl Clone for ByteArraySSLen {
    fn clone(&self) -> ByteArraySSLen {
        ByteArraySSLen(self.0)
    }
}
