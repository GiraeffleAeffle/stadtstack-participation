// SPDX-License-Identifier: MIT
// BN254 domain separation and public input order are normative in docs/DESIGN.md.
use std::hash::poseidon2_permutation;

global DEPTH: u32 = 16;

fn h(a: Field, b: Field, domain: Field) -> Field {
    poseidon2_permutation([a, b, domain, 0], 4)[0]
}

fn merkle_root(leaf: Field, path: [Field; DEPTH], indices: [Field; DEPTH]) -> Field {
    let mut current = leaf;
    for i in 0..DEPTH {
        assert(indices[i] * (indices[i] - 1) == 0, "non-boolean index");
        let left = if indices[i] == 0 { current } else { path[i] };
        let right = if indices[i] == 0 { path[i] } else { current };
        current = h(left, right, 2);
    }
    current
}

fn main(
    secret: Field, path: [Field; DEPTH], indices: [Field; DEPTH],
    root: pub Field, nullifier: pub Field, scope: pub Field, signal_hash: pub Field,
) {
    assert(secret != 0, "zero secret");
    assert(scope != 0, "zero scope");
    assert(merkle_root(h(secret, 0, 1), path, indices) == root, "wrong root");
    assert(h(secret, scope, 3) == nullifier, "wrong nullifier");
    // Public ABI input: the transcript binds this field even without an extra constraint.
    let _ = signal_hash;
}

#[test]
fn valid_witness() {
    let path = [0; DEPTH];
    let indices = [0; DEPTH];
    main(42, path, indices, merkle_root(h(42, 0, 1), path, indices), h(42, 999, 3), 999, 7);
}

#[test(should_fail_with = "wrong root")]
fn wrong_root() {
    let path = [0; DEPTH];
    let indices = [0; DEPTH];
    main(42, path, indices, merkle_root(h(42, 0, 1), path, indices) + 1, h(42, 999, 3), 999, 7);
}

#[test(should_fail_with = "wrong nullifier")]
fn wrong_nullifier() {
    let path = [0; DEPTH];
    let indices = [0; DEPTH];
    main(42, path, indices, merkle_root(h(42, 0, 1), path, indices), h(43, 999, 3), 999, 7);
}

#[test(should_fail_with = "non-boolean index")]
fn non_boolean_index() {
    let mut indices = [0; DEPTH];
    indices[0] = 2;
    main(42, [0; DEPTH], indices, 0, 0, 999, 7);
}

#[test(should_fail_with = "zero secret")]
fn zero_secret() {
    let path = [0; DEPTH];
    let indices = [0; DEPTH];
    main(0, path, indices, merkle_root(h(0, 0, 1), path, indices), h(0, 999, 3), 999, 7);
}

#[test(should_fail_with = "zero scope")]
fn zero_scope() {
    let path = [0; DEPTH];
    let indices = [0; DEPTH];
    main(42, path, indices, merkle_root(h(42, 0, 1), path, indices), h(42, 0, 3), 0, 7);
}

#[test]
fn right_child_path() {
    let mut path = [0; DEPTH];
    path[0] = 123;
    let mut indices = [0; DEPTH];
    indices[0] = 1;
    let mut root = h(123, h(42, 0, 1), 2);
    for _ in 1..DEPTH { root = h(root, 0, 2); }
    main(42, path, indices, root, h(42, 999, 3), 999, 7);
}

#[test]
fn last_leaf_index_65535() {
    let path = [123; DEPTH];
    let indices = [1; DEPTH];
    let mut root = h(42, 0, 1);
    for _ in 0..DEPTH { root = h(123, root, 2); }
    main(42, path, indices, root, h(42, 999, 3), 999, 7);
}

// Generated fixtures take their oracle values from Noir, not the JS library.
#[test]
fn emit_parity_fixture() {
    let pairs: [[Field; 2]; 10] = [
        [0, 0], [1, 0], [0, 1], [1, 1], [0 - 1, 0],
        [0, 0 - 1], [0 - 1, 1], [1, 0 - 1], [0 - 1, 0 - 1], [42, 999],
    ];
    for domain in 1..6 {
        for pair in pairs {
            let a = pair[0];
            let b = pair[1];
            let d = domain as Field;
            let out = h(a, b, d);
            println(f"PARITY {a} {b} {d} {out}");
        }
    }
    // electionId = SHA256(canonical fixture identifier), hi128 followed by lo128.
    let scope = h(281719667222684358312946452997060730747, 122022769951235020314000080475135970725, 4);
    let leaf = h(42, 0, 1);
    let mut path = [0; DEPTH];
    let indices = [0; DEPTH];
    let mut empty: Field = 0;
    for i in 0..DEPTH {
        path[i] = empty;
        empty = h(empty, empty, 2);
    }
    let root = merkle_root(leaf, path, indices);
    let nullifier = h(42, scope, 3);
    let signal = h(1, scope, 5);
    println(f"EXAMPLE {leaf} {root} {scope} {nullifier} {signal}");
    main(42, path, indices, root, nullifier, scope, signal);
}
