const ROLLING_WINDOW: usize = 7;

pub trait RollingHash {
    fn hash(&mut self, byte: u8);
    fn sum(&self) -> u32;
}

pub struct AddlerBasedRollingHash {
      window: [u8; ROLLING_WINDOW],
      h1: u32,
      h2: u32,
      h3: u32,
      n: u32,
}

// based on roll_hash in ssdeep
impl RollingHash for AddlerBasedRollingHash {
    fn hash(&mut self, byte: u8) {
        self.h2 -= self.h1;
        self.h2 += (ROLLING_WINDOW * (byte as usize)) as u32;

        let index = self.n as usize;

        self.h1 += byte as u32;
        self.h1 -= self.window[index] as u32;

        self.window[index] = byte;
        self.n += 1;

        if self.n as usize == ROLLING_WINDOW {
            self.n = 0;
        }

        self.h3 <<= 5;
        self.h3 ^= byte as u32;
    }

    fn sum(&self) -> u32 {
        (self.h1 + self.h2 + self.h3) as u32
    }
}

impl AddlerBasedRollingHash {
    pub fn new() -> AddlerBasedRollingHash {
        AddlerBasedRollingHash {
              window: [0; ROLLING_WINDOW],
              h1: 0,
              h2: 0,
              h3: 0,
              n: 0,
        }
    }
}
