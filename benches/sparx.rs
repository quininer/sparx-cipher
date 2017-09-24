#![feature(test)]

extern crate test;
extern crate sparx_cipher;

use test::Bencher;
use sparx_cipher::Sparx;
use sparx_cipher::params::{ KEY_BYTES, BLOCK_BYTES };


#[bench]
fn bench_sparx(b: &mut Bencher) {

    let key = [42; KEY_BYTES];
    b.iter(|| {
        let mut block = [0; BLOCK_BYTES];
        let cipher = Sparx::new(&key);
        cipher.encrypt(&mut block);
        cipher.decrypt(&mut block);
    });
}

#[bench]
fn bench_key_schedule(b: &mut Bencher) {
    b.iter(|| {
        let key = [42; KEY_BYTES];
        Sparx::new(&key)
    })
}

#[bench]
fn bench_encrypt(b: &mut Bencher) {
    let key = [42; KEY_BYTES];
    let cipher = Sparx::new(&key);

    b.iter(|| {
        let mut block = [0; BLOCK_BYTES];
        cipher.encrypt(&mut block);
    })
}

#[bench]
fn bench_decrypt(b: &mut Bencher) {
    let key = [42; KEY_BYTES];
    let cipher = Sparx::new(&key);

    b.iter(|| {
        let mut block = [0; BLOCK_BYTES];
        cipher.decrypt(&mut block);
    })
}
