#![no_std]

#[cfg(feature = "x64_128")]
pub mod params {
    pub const BLOCK_BYTES: usize = 64 / 8;
    pub const KEY_BYTES: usize = 128 / 8;
    pub type SUBKEY = [[u32; ROUNDS_PER_STEP]; BRANCHES * STEPS + 1];

    pub(crate) const BLOCK_SIZE: usize = BLOCK_BYTES / 4; // TODO mem::size_of::<u32>()
    pub(crate) const KEY_SIZE: usize = KEY_BYTES / 4;

    const ROUNDS: usize = 24;
    pub(crate) const ROUNDS_PER_STEP: usize = ROUNDS / STEPS;
    pub(crate) const STEPS: usize = 8;
    pub(crate) const BRANCHES: usize = 2;
}

pub mod block;

use core::mem;
use params::{ SUBKEY, KEY_BYTES, BLOCK_BYTES, KEY_SIZE, BLOCK_SIZE };
use block::{ key_schedule, encrypt_block, decrypt_block };


#[derive(Clone)]
pub struct Sparx(SUBKEY);

impl Sparx {
    #[inline]
    pub fn new(key: &[u8; KEY_BYTES]) -> Self {
        let mut block = [0; KEY_SIZE];
        let mut subkey = Default::default();
        block.copy_from_slice(array_to_key(key));
        key_schedule(&mut block, &mut subkey);
        Sparx(subkey)
    }

    #[inline]
    pub fn encrypt(&self, b: &mut [u8; BLOCK_BYTES]) {
        encrypt_block(&self.0, array_to_block(b))
    }

    #[inline]
    pub fn decrypt(&self, b: &mut [u8; BLOCK_BYTES]) {
        decrypt_block(&self.0, array_to_block(b))
    }
}

#[inline]
fn array_to_block(x: &mut [u8; BLOCK_BYTES]) -> &mut [u32; BLOCK_SIZE] {
    unsafe { mem::transmute(x) }
}

fn array_to_key(x: &[u8; KEY_BYTES]) -> &[u32; KEY_SIZE] {
    unsafe { mem::transmute(x) }
}