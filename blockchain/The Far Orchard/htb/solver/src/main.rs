// Solver: Exploit the unanchored base bug in halo2_gadgets
//
// EXPLOIT: The circuit witnesses g_d as a NonIdentityPoint with only an
// on-curve check (y^2 = x^3 + b). It does NOT constrain g_d to be the Pallas
// generator G. So the attacker can substitute B' = [sk^-1] * pk_target.
//
// This solver generates proofs for all Far-Seals in the Merkle tree.
// Each proof uses a different random sk_attacker → different nullifier.
// The Orchard accepts all eight distant vows after the proofs are honored.

use ff::{Field, PrimeField};
use group::{Curve, Group};
use halo2_proofs::{
    circuit::Value,
    plonk::{create_proof, keygen_pk, keygen_vk},
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
};
use pasta_curves::{arithmetic::CurveAffine, pallas, vesta};
use rand::rngs::OsRng;
use rand::RngCore;
use std::io::Read;

const K_PARAM: u32 = 13;

use validator::circuit::{FarOrchardCircuit, MERKLE_DEPTH};
use validator::merkle;

fn random_field_element(rng: &mut OsRng) -> pallas::Base {
    let mut buf = [0u8; 32];
    loop {
        rng.fill_bytes(&mut buf);
        let v_opt: Option<pallas::Base> = pallas::Base::from_repr(buf).into();
        if let Some(v) = v_opt {
            if !v.is_zero_vartime() {
                return v;
            }
        }
    }
}

struct LeafInfo {
    index: usize,
    pk_x: pallas::Base,
    seal_id: usize,
}

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();

    // ── Parse Merkle tree data from server ─────────────────────────────
    let mut leaves: Vec<LeafInfo> = Vec::new();
    for line in input.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("LEAF=") {
            let parts: Vec<&str> = rest.split(',').collect();
            if parts.len() >= 3 {
                let idx: usize = parts[0].trim().parse().unwrap_or(0);
                if let Ok(pk_x) = merkle::hex_to_field(parts[1].trim()) {
                    let seal_id: usize = parts[2].trim().parse().unwrap_or(idx);
                    leaves.push(LeafInfo {
                        index: idx,
                        pk_x,
                        seal_id,
                    });
                }
            }
        }
    }

    // ── Local test mode: generate random tree if no server input ───────
    let tree = if leaves.is_empty() {
        eprintln!("=== Local Test Mode: Generating random Merkle tree ===");
        let mut rng = OsRng;
        let leaf_values: Vec<pallas::Base> = (0..8)
            .map(|_| {
                let sk = random_field_element(&mut rng);
                let pk_point =
                    pallas::Point::generator() * pallas::Scalar::from_repr(sk.to_repr()).unwrap();
                *pk_point.to_affine().coordinates().unwrap().x()
            })
            .collect();

        for (i, &pk_x) in leaf_values.iter().enumerate() {
            leaves.push(LeafInfo {
                index: i,
                pk_x,
                seal_id: i,
            });
        }

        merkle::MerkleTree::new(leaf_values, MERKLE_DEPTH)
    } else {
        eprintln!("=== Server Mode: Using provided Merkle tree ===");
        let leaf_values: Vec<pallas::Base> = leaves.iter().map(|l| l.pk_x).collect();
        merkle::MerkleTree::new(leaf_values, MERKLE_DEPTH)
    };

    eprintln!("  Merkle root = {}", hex::encode(tree.root.to_repr()));
    eprintln!("  Leaves: {}", leaves.len());

    // ── Build proving key ──────────────────────────────────────────────
    eprintln!("\nBuilding proving key...");
    let params: Params<vesta::Affine> = Params::new(K_PARAM);
    let empty_circuit = FarOrchardCircuit::default();
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk");
    let pk_key = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk");

    // ── EXPLOIT: Forge proof for each leaf ─────────────────────────────
    let mut rng = OsRng;

    for leaf in &leaves {
        eprintln!(
            "\n=== EXPLOIT: Far-Seal {} (leaf {}) ===",
            leaf.seal_id, leaf.index
        );

        // Step 1: Generate random attacker sk (256-bit, unique per leaf)
        let sk_attacker = random_field_element(&mut rng);
        eprintln!(
            "  Attacker sk = {} (256-bit random)",
            hex::encode(sk_attacker.to_repr())
        );

        // Step 2: Decompress pk_target from x-coordinate
        let pk_target_affine = decompress_pallas_point(leaf.pk_x);
        let pk_target_point = pallas::Point::from(pk_target_affine);

        // Step 3: Compute B' = [sk_attacker^{-1}] * pk_target
        let attacker_scalar = pallas::Scalar::from_repr(sk_attacker.to_repr()).unwrap();
        let attacker_inv = attacker_scalar.invert().unwrap();
        let b_prime_point = pk_target_point * attacker_inv;
        let b_prime_affine = b_prime_point.to_affine();

        eprintln!(
            "  B' (fake base) = x:{}",
            hex::encode(b_prime_affine.coordinates().unwrap().x().to_repr())
        );

        // Verify: [sk_attacker] * B' == pk_target
        let verify_point = b_prime_point * attacker_scalar;
        assert_eq!(
            verify_point.to_affine(),
            pk_target_affine,
            "B' computation failed for leaf {}",
            leaf.index
        );

        // Step 4: Build exploit circuit
        let target_path = tree.path(leaf.index);
        let attacker_nullifier = merkle::derive_nullifier(sk_attacker);

        eprintln!(
            "  Nullifier = {} (unique per leaf)",
            hex::encode(attacker_nullifier.to_repr())
        );

        let exploit_circuit = FarOrchardCircuit {
            sk: Value::known(sk_attacker),
            g_d: Value::known(b_prime_affine),
            merkle_path: Value::known(
                target_path
                    .try_into()
                    .unwrap_or([pallas::Base::zero(); MERKLE_DEPTH]),
            ),
            merkle_pos: Value::known(leaf.index as u32),
        };

        // Step 5: Generate proof
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        // The validator binds this proof to the exact canonical leaf being
        // honored, in addition to the orchard root and the nullifier.
        let exploit_inputs: [[pallas::Base; 3]; 1] = [[tree.root, attacker_nullifier, leaf.pk_x]];
        let exploit_instances: [&[&[pallas::Base]]; 1] = [&[&exploit_inputs[0]]];

        match create_proof(
            &params,
            &pk_key,
            &[exploit_circuit],
            &exploit_instances,
            OsRng,
            &mut transcript,
        ) {
            Ok(()) => {
                let proof = transcript.finalize();
                let serialized =
                    merkle::serialize_proof(&proof, &tree.root, &attacker_nullifier, &leaf.pk_x);
                let nf_hex = hex::encode(attacker_nullifier.to_repr());
                println!("PROOF={}", serialized);
                println!("NULLIFIER=0x{}", nf_hex);
                println!("SEAL_ID={}", leaf.seal_id);
                println!("LEAF_INDEX={}", leaf.index);
                eprintln!("  Proof generated ({} bytes)", proof.len());
            }
            Err(e) => {
                eprintln!("  Proof failed: {:?}", e);
            }
        }
    }

    eprintln!("\n=== All proofs generated ===");
    eprintln!("Submit each PROOF to /verify, then honor its Far-Seal on-chain.");
    eprintln!("Each proof has a unique nullifier — no double-spend detection.");
}

/// Decompress a Pallas curve point from its x-coordinate.
/// y^2 = x^3 + 5 (Pallas curve, b = 5)
fn decompress_pallas_point(x: pallas::Base) -> pallas::Affine {
    let y_sq = x * x * x + pallas::Base::from(5u64);
    let y = pallas::Base::sqrt(&y_sq).expect("Invalid x-coordinate: not on Pallas curve");
    let y_repr = y.to_repr();
    let y_canonical = if y_repr[0] % 2 == 0 { y } else { -y };
    pallas::Affine::from_xy(x, y_canonical).expect("Failed to construct point")
}
