#![cfg_attr(feature = "cargo-clippy", allow(needless_range_loop))]

use ::params::*;


macro_rules! split {
    ( $x:expr ) => {
        ($x as u16, ($x >> 16) as u16)
    }
}

macro_rules! merge {
    ( $l:expr, $r:expr ) => {
        u32::from($l) | (u32::from($r) << 16)
    }
}

// --

#[cfg(feature = "x64_128")]
#[inline]
fn l(x: &mut [u32; BLOCK_SIZE]) {
    let (l, r) = split!(x[0]);
    let tmp = (l ^ r).rotate_left(8);
    x[1] ^= x[0] ^ merge!(tmp, tmp);
    x.swap(0, 1);
}

#[cfg(feature = "x64_128")]
#[inline]
fn l_inv(x: &mut [u32; BLOCK_SIZE]) {
    x.swap(0, 1);
    let (l, r) = split!(x[0]);
    let tmp = (l ^ r).rotate_left(8);
    x[1] ^= x[0] ^ merge!(tmp, tmp);
}

#[cfg(any(feature = "x128_128"))]
#[inline]
fn l(x: &mut [u32; BLOCK_SIZE]) {
    let (x0l, x0r) = split!(x[0]);
    let (x1l, x1r) = split!(x[1]);
    let tmp = (x0l ^ x0r ^ x1l ^ x1r).rotate_left(8);
    let tmp = merge!(tmp, tmp);

    x[2] ^= merge!(x1l, x0r) ^ tmp;
    x[3] ^= merge!(x0l, x1r) ^ tmp;

    x.swap(0, 2);
    x.swap(1, 3);
}

#[cfg(any(feature = "x128_128"))]
#[inline]
fn l_inv(x: &mut [u32; BLOCK_SIZE]) {
    x.swap(0, 2);
    x.swap(1, 3);

    let (x0l, x0r) = split!(x[0]);
    let (x1l, x1r) = split!(x[1]);
    let tmp = (x0l ^ x0r ^ x1l ^ x1r).rotate_left(8);
    let tmp = merge!(tmp, tmp);

    x[2] ^= merge!(x1l, x0r) ^ tmp;
    x[3] ^= merge!(x0l, x1r) ^ tmp;
}

#[cfg(feature = "x64_128")]
fn key_perm(k: &mut [u32; KEY_SIZE], c: u16) {
    a(&mut k[0]);

    let (k0l, k0r) = split!(k[0]);
    let (k1l, k1r) = split!(k[1]);
    k[1] = merge!(k1l.wrapping_add(k0l), k1r.wrapping_add(k0r));;

    let (k3l, k3r) = split!(k[3]);
    k[3] = merge!(k3l, k3r.wrapping_add(c));

    let tmp = k[3];
    k[3] = k[2];
    k[2] = k[1];
    k[1] = k[0];
    k[0] = tmp;
}

#[cfg(feature = "x128_128")]
fn key_perm(k: &mut [u32; KEY_SIZE], c: u16) {
    a(&mut k[0]);
    let (k0l, k0r) = split!(k[0]);
    let (k1l, k1r) = split!(k[1]);
    k[1] = merge!(k1l.wrapping_add(k0l), k1r.wrapping_add(k0r));

    a(&mut k[2]);
    let (k2l, k2r) = split!(k[2]);
    let (k3l, k3r) = split!(k[3]);
    k[3] = merge!(k3l.wrapping_add(k2l), k3r.wrapping_add(k2r).wrapping_add(c));

    let tmp = k[3];
    k[3] = k[2];
    k[2] = k[1];
    k[1] = k[0];
    k[0] = tmp;
}

#[inline]
fn a(x: &mut u32) {
    let (mut l, mut r) = split!(*x);
    l = l.rotate_right(7).wrapping_add(r);
    r = r.rotate_left(2) ^ l;
    *x = merge!(l, r);
}

#[inline]
fn a_inv(x: &mut u32) {
    let (mut l, mut r) = split!(*x);
    r = (r ^ l).rotate_right(2);
    l = l.wrapping_sub(r).rotate_left(7);
    *x = merge!(l, r);
}

pub fn key_schedule(master_key: &mut [u32; KEY_SIZE], subkey: &mut SubKey) {
    for c in 0..(BRANCHES * STEPS + 1) {
        subkey[c][..ROUNDS_PER_STEP].copy_from_slice(&master_key[..ROUNDS_PER_STEP]);
        key_perm(master_key, c as u16 + 1);
    }
}

pub fn encrypt_block(subkey: &SubKey, block: &mut [u32; BLOCK_SIZE]) {
    for s in 0..STEPS {
        for b in 0..BRANCHES {
            for r in 0..ROUNDS_PER_STEP {
                block[b] ^= subkey[BRANCHES * s + b][r];
                a(&mut block[b]);
            }
        }
        l(block);
    }

    for b in 0..BRANCHES {
        block[b] ^= subkey[BRANCHES * STEPS][b];
    }
}

pub fn decrypt_block(subkey: &SubKey, block: &mut [u32; BLOCK_SIZE]) {
    for b in 0..BRANCHES {
        block[b] ^= subkey[BRANCHES * STEPS][b];
    }

    for s in (0..STEPS).rev() {
        l_inv(block);
        for b in 0..BRANCHES {
            for r in (0..ROUNDS_PER_STEP).rev() {
                a_inv(&mut block[b]);
                block[b] ^= subkey[BRANCHES * s + b][r];
            }
        }
    }
}
