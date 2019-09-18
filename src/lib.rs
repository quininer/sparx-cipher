#![no_std]

extern crate byteorder;

use byteorder::{ ByteOrder, LittleEndian };


#[cfg(feature = "x64_128")]
pub mod params {
    pub const BLOCK_BYTES: usize = 64 / 8;
    pub const KEY_BYTES: usize = 128 / 8;
    pub type SubKey = [[u32; ROUNDS_PER_STEP]; BRANCHES * STEPS + 1];

    pub const BLOCK_SIZE: usize = BLOCK_BYTES / 4;
    pub const KEY_SIZE: usize = KEY_BYTES / 4;

    const ROUNDS: usize = 24;
    pub(crate) const ROUNDS_PER_STEP: usize = ROUNDS / STEPS;
    pub(crate) const STEPS: usize = 8;
    pub(crate) const BRANCHES: usize = 2;
}

#[cfg(feature = "x128_128")]
pub mod params {
    pub const BLOCK_BYTES: usize = 128 / 8;
    pub const KEY_BYTES: usize = 128 / 8;
    pub type SubKey = [[u32; ROUNDS_PER_STEP]; BRANCHES * STEPS + 1];

    pub const BLOCK_SIZE: usize = BLOCK_BYTES / 4;
    pub const KEY_SIZE: usize = KEY_BYTES / 4;

    const ROUNDS: usize = 32;
    pub(crate) const ROUNDS_PER_STEP: usize = ROUNDS / STEPS;
    pub(crate) const STEPS: usize = 8;
    pub(crate) const BRANCHES: usize = 4;
}

#[cfg(feature = "x128_256")]
pub mod params {
    pub const BLOCK_BYTES: usize = 128 / 8;
    pub const KEY_BYTES: usize = 256 / 8;
    pub type SubKey = [[u32; ROUNDS_PER_STEP]; BRANCHES * STEPS + 1];

    pub const BLOCK_SIZE: usize = BLOCK_BYTES / 4;
    pub const KEY_SIZE: usize = KEY_BYTES / 4;

    const ROUNDS: usize = 40;
    pub(crate) const ROUNDS_PER_STEP: usize = ROUNDS / STEPS;
    pub(crate) const STEPS: usize = 10;
    pub(crate) const BRANCHES: usize = 4;
}

pub mod block;

use params::*;
use block::{ key_schedule, encrypt_block, decrypt_block };


#[derive(Clone)]
pub struct Sparx(SubKey);

impl Sparx {
    pub fn new(key: &[u8; KEY_BYTES]) -> Self {
        let mut block = [0; KEY_SIZE];
        let mut subkey = [[0; ROUNDS_PER_STEP]; BRANCHES * STEPS + 1];
        LittleEndian::read_u32_into(key, &mut block);
        key_schedule(&mut block, &mut subkey);
        Sparx(subkey)
    }

    pub fn encrypt(&self, b: &mut [u8; BLOCK_BYTES]) {
        let mut nb = [0; BLOCK_SIZE];
        LittleEndian::read_u32_into(b, &mut nb);
        encrypt_block(&self.0, &mut nb);
        LittleEndian::write_u32_into(&nb, b);
    }

    pub fn decrypt(&self, b: &mut [u8; BLOCK_BYTES]) {
        let mut nb = [0; BLOCK_SIZE];
        LittleEndian::read_u32_into(b, &mut nb);
        decrypt_block(&self.0, &mut nb);
        LittleEndian::write_u32_into(&nb, b);
    }
}
