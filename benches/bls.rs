use divan::{black_box, Bencher};

use ds_rust::{bls::algorithms::BLS, traits::ds::DigitalSignature};

const SECURY_LEVEL: u64 = 100;
const VALUES: &[u64] = &[1, 5, 10, 20, 30, 40];

#[divan::bench]
fn bls_keygen() {
    let _ = BLS::keygen(black_box(SECURY_LEVEL)).unwrap();
}

#[divan::bench(args=VALUES)]
fn bls_sign(bencher: Bencher, m: u64) {
    let (sk, _) = BLS::keygen(SECURY_LEVEL).unwrap();

    let m = m.to_le_bytes();

    bencher.bench_local(|| {
        let _ = BLS::sign(black_box(&sk), black_box(&m)).unwrap();
    });
}

#[divan::bench(args=VALUES)]
fn bls_verify(bencher: Bencher, m: u64) {
    let (sk, pk) = BLS::keygen(SECURY_LEVEL).unwrap();

    let m = m.to_le_bytes();
    let s = BLS::sign(&sk, &m).unwrap();

    bencher.bench_local(|| {
        let _ = BLS::verify(black_box(&pk), black_box(&s), black_box(&m));
    });
}

fn main() {
    divan::main();
}
