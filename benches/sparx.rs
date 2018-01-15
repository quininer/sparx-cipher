#![feature(test)]

extern crate test;
extern crate sparx_cipher;

use test::{ Bencher, black_box };
use sparx_cipher::Sparx;
use sparx_cipher::params::{ KEY_BYTES, BLOCK_BYTES };


#[bench]
fn bench_sparx(b: &mut Bencher) {
    let key = black_box([0x41; KEY_BYTES]);
    b.iter(|| {
        let mut block = [0x42; BLOCK_BYTES];
        let cipher = Sparx::new(&key);
        cipher.encrypt(&mut block);
        cipher.decrypt(&mut block);
    });
}

#[bench]
fn bench_key_schedule(b: &mut Bencher) {
    let key = black_box([0x43; KEY_BYTES]);
    b.iter(|| {
        Sparx::new(&key)
    })
}

#[bench]
fn bench_encrypt(b: &mut Bencher) {
    let key = black_box([0x44; KEY_BYTES]);
    let cipher = Sparx::new(&key);

    b.iter(|| {
        let mut block = [0x45; BLOCK_BYTES];
        cipher.encrypt(&mut block);
    })
}

#[bench]
fn bench_decrypt(b: &mut Bencher) {
    let key = black_box([0x46; KEY_BYTES]);
    let cipher = Sparx::new(&key);

    b.iter(|| {
        let mut block = [0x48; BLOCK_BYTES];
        cipher.decrypt(&mut block);
    })
}
