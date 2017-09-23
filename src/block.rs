use ::params::*;


macro_rules! split {
    ( $x:expr ) => {
        ($x as u16, ($x >> 16) as u16)
    }
}

macro_rules! merge {
    ( $l:expr, $r:expr ) => {
        ($l as u32) | (($r as u32) << 16)
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

pub fn key_schedule(master_key: &mut [u32; KEY_SIZE], subkey: &mut SUBKEY) {
    for c in 0..(BRANCHES * STEPS + 1) {
        for i in 0..ROUNDS_PER_STEP {
            subkey[c][i] = master_key[i];
        }
        key_perm(master_key, c as u16 + 1);
    }
}

pub fn encrypt_block(subkey: &SUBKEY, block: &mut [u32; BLOCK_SIZE]) {
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

pub fn decrypt_block(subkey: &SUBKEY, block: &mut [u32; BLOCK_SIZE]) {
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
