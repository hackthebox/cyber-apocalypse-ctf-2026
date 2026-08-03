![img](../../assets/banner.png)



<img src='./assets/logo.png' style='zoom: 70%;' align=left /> <font size='10'>The Phantom Burn</font>

30<sup>th</sup> June 2026

Prepared By: `Pyp`

Challenge Author(s): `Pyp`

Difficulty: <font color='red'>Hard</font>

<br><br>
<br><br>

# Synopsis

The Phantom Burn is a secure-coding challenge built around a Solidity shard registry, a public Node/TypeScript application, and a separate archive service. Shard filings are recorded on a local EVM chain and later presented as receipts to unlock source material and authorize archive actions.

The registry stores and emits an archive-derived seal even though contract storage and event logs are public. The public app resolves a real event but does not prove that the configured registry emitted it. The archive service is weaker and accepts receipt-shaped JSON without consulting the chain. In both paths, caller-selected evidence reaches an authorization decision without enough provenance.

The patch must remove bearer material from public chain data and make both services establish the same facts before granting access: successful inclusion, proper confirmation depth, exact log position, expected event, configured registry, authenticated owner, relevant shard and action, and one-time use.

## Description
Caldrin Vowmark receives an Ash-Vault receipt that passes every local check, although no rightful keeper issued it. A sealed source transfer begins when the next burn is finalised. If the receipt is accepted first, the hidden hand gains the Ash-Vault's source bundle and can manufacture more receipts that appear lawful to every Eastreach verifier. Caldrin must discover how the counterfeit survives the weighing, stop the transfer, restore the witness chain, and preserve one legitimate owner unlock.

## Skills Required

- Solidity contracts, storage, calldata, and event logs
- EVM transaction receipts and confirmation depth
- TypeScript and Node.js service development
- Cross-service authentication and authorization boundaries
- Replay prevention and canonical identifiers
- Basic Git and pull-request workflow

## Skills Learned

- Proper understing of public blockchain configuration - cannot safely carry bearer secrets.
- Structured input is not proof that an event occurred on-chain.
- Off-chain services must verify contract origin, event identity, inclusion, finality, and decoded event data.
- Authorization must bind a verified owner to the acting principal and action.
- Receipt consumption must use an identifier derived from canonical evidence.

# Enumeration

## Application access

The Weighing House is served at:

```text
http://[IP]:[PORT]/app/
```

The issued console account is:

```text
operator / phantom-burn-2026
```

The console exposes recent shard filings, the Ash-Vault custody desk, operating procedure, and instrument status. Recent filings come from the local registry and include the owner, shard identifier, URI, unlock seal, and nonce published by `ShardFiled`. Because the seal is shown in the console and is also carried in the public event log, it is already visible to anyone before any exploitation begins, which is the first hint that it is not a secret.

The archive service is mounted at `/archive/`. It accepts an archive-open receipt and returns privileged archive grants after its verifier approves the submitted chain evidence. The two Node services form a chain of trust: the public app gates the source bundle, and the archive service gates the privileged grant. Both make an authorization decision from receipt-shaped input.

## The local chain

The challenge stack runs `ShardRegistry` on Anvil with chain id `31337`. The hosted RPC is an internal service used by the application and validator; Caddy does not mount it as a public route. The player repository includes the Foundry project and local-development commands, so the receipt paths can be traced and reproduced against a player-run Anvil instance with `forge`, `cast`, or `viem`.

Reading `ShardFiled` logs shows that each event carries the owner, shard id, URI, `unlockSeal`, and nonce. The contract stores the same seal in the shard record. Solidity visibility does not make either copy confidential: event data is exposed through the transaction receipt, and contract storage is readable directly from the chain.

## Locked source bundle

The public application distributes `archive-service.locked.tar.gz` only after issuing a source token. The repository includes a helper that demonstrates the token derivation from a filing receipt:

```bash
node phantom_burn/tools/unlock-source.mjs receipt.json
```

The helper prints the token formula but does not register a token in the running app; the download route accepts only tokens the app has issued. The relevant entry point is `POST /app/api/source/unlock`. That route fetches a transaction receipt and decodes a real event before recording a token, but it never establishes that the operator's configured registry emitted the event.

The unlocked bundle contains the archive-service source, including `chainReceipt.ts`. That verifier reveals the second half of the trust boundary, and it is weaker than the first: client-supplied event fields are accepted on shape alone, without any RPC lookup at all.

## Receipt anatomy

The submitted JSON mixes a transaction locator with claims about what that transaction means:

| Field | Safe use before verification | Authority after verification |
|---|---|---|
| `txHash` | Locate a transaction receipt | Only if the transaction succeeded and reached the required depth |
| `logIndex` | Locate one log in that receipt | Only if that exact log exists |
| `registry` | None | Must come from `log.address` and equal configured deployment metadata |
| `owner` | None | Must come from the decoded event and equal the authenticated principal |
| `shardId` | None | Must come from the decoded event and match the requested action |
| `unlockSeal` | None | Public event data; never a bearer credential |
| `nonce` | None | Must come from the decoded event and contribute to replay identity |

Only `txHash` and `logIndex` need to arrive from the caller, and even those are locators rather than trusted facts. The remaining values must be derived from the selected log after its origin, topic, inclusion, and finality have been checked.

## Repository access

```bash
git clone http://htb_developer:HTBDeveloperPassword@[IP]:[PORT]/git/core_application.git
cd core_application
git checkout -b developer
```

The relevant files are:

```text
phantom_burn/
|-- contracts/src/ShardRegistry.sol
|-- contracts/src/ReceiptVerifier.sol
|-- app/src/sourceVault.ts
|-- app/src/routes.ts
|-- archive-service/src/chainReceipt.ts
|-- archive-service/src/receiptStore.ts
`-- archive-service/src/routes.ts
```

The contract folder is a Foundry project. The public app and archive service are separate Node projects with their own lockfiles, TypeScript builds, and tests.

`archive-service/src/receiptStore.ts` is listed to show where consumption is recorded, not as a file to change. It is a replay ledger with no authorization logic: it only tracks which receipt identifiers have already been used. Its safety depends entirely on the identifier the verifier hands it, so the fix belongs in `chainReceipt.ts`, which must derive that identifier from canonical on-chain evidence. Replacing the store or moving the derivation into it does not close the gap.

# Identifying the Vulnerability

## Public logs are not sealed storage

`ShardRegistry.fileShard` derives `unlockSeal` from the caller-provided archive key, stores it in the public shard record, and includes it in `ShardFiled`:

```solidity
bytes32 unlockSeal = keccak256(
    abi.encodePacked("PHANTOM_BURN_ARCHIVE:", archiveKey)
);

shards[shardId] = Shard({
    owner: msg.sender,
    uri: uri,
    commitment: commitment,
    unlockSeal: unlockSeal,
    nonce: nonce
});

emit ShardFiled(msg.sender, shardId, uri, unlockSeal, nonce);
```

A private mapping restricts Solidity-level access but does not make its storage secret. The `private` keyword only prevents the compiler from generating a getter; the underlying storage slot is still readable with `eth_getStorageAt`, and here the value is additionally emitted in `ShardFiled`, so it is available in the log topics and data of every filing. The application nevertheless treats the published seal as part of a bearer capability for the source bundle, which means the capability is minted directly into public data at filing time.

## Event-shaped data is not chain authority

The source-unlock path in the public app looks careful. `resolveFiling` actually fetches the transaction over RPC and decodes the real `ShardFiled` event before deriving a token, so a purely fabricated receipt is rejected:

```typescript
const txReceipt = await client.getTransactionReceipt({ hash: receipt.txHash });
const log = txReceipt.logs.find((e) => Number(e.logIndex) === receipt.logIndex) ?? txReceipt.logs[0];
const decoded = decodeEventLog({ abi: [shardFiledEvent], data: log.data, topics: log.topics });
// token bound to the decoded filing... but the emitting contract is never checked
```

The gap is provenance, not shape. The code resolves whatever contract the caller's `txHash` and `logIndex` identify. It does not compare `log.address` with the configured registry, require confirmation depth, bind the decoded owner to a principal, or consume the receipt. A transaction from an attacker-deployed copy of `ShardRegistry` therefore supplies a perfectly decodable `ShardFiled` event while proving nothing about the operator's registry. A shallow transaction may still disappear in a reorganization, and a filing owned by one address is not authority for another. The archive service skips even the RPC lookup and authorizes its privileged action on shape alone:

```typescript
if (!receipt.txHash?.startsWith("0x") ||
    !receipt.owner?.startsWith("0x") ||
    !receipt.shardId?.startsWith("0x")) {
  return { ok: false, reason: "malformed receipt" };
}
return { ok: true, receiptId: receiptId(receipt) };
```

The archive route calls `markConsumed`, but its identifier is a hash of caller-supplied fields. The caller can change an unchecked field and obtain a different hash for the same alleged authority. Replay prevention begins after provenance: the consumed identifier must be derived from verified event values together with the action being authorized.

## Chaining the two gaps

The full analysis follows the same untrusted receipt through two verifiers. Public `unlockSeal` data reveals the token ingredients and confirms that the design treats a published value as entitlement. To make the app issue a usable download token, we deploy another `ShardRegistry` in the local reproduction environment and file a shard on it:

```bash
# file a shard on an attacker-controlled registry
cast send --rpc-url "$RPC" --private-key "$KEY" "$MY_REGISTRY" \
  "fileShard(bytes32,string,bytes32)" "$SHARD_ID" "ipfs://foreign/shard" "$ARCHIVE_KEY"
```

That filing produces a genuine `ShardFiled` log with a real transaction hash and log index. `resolveFiling` fetches and decodes it successfully. Because no check pins `log.address` to the configured deployment, `POST /api/source/unlock` accepts the foreign event and records a bundle token. The archive service accepts a receipt-shaped body even without that genuine event because `verifyReceipt` checks prefixes instead of chain state. One path mistakes a foreign fact for a local one; the other mistakes a claim for a fact.

# Real-World Impact

The first failure is assuming that a value held in `private` contract storage, or omitted from public getters, is confidential. On-chain storage and event logs are world-readable regardless of Solidity visibility. A bearer value written there is disclosed at the same moment it is created.

The second is accepting structured input that resembles a chain event as proof that the event occurred on the expected contract for the current actor. Equivalent flaws can release protected artifacts, authorize withdrawals, replay operations, or cross tenant boundaries. Indexers, bridges, custody services, and webhook consumers must establish event origin, identity, inclusion, finality, decoded values, principal binding, and replay state before granting access.

# Solution

The contract should publish commitments and public metadata only. Include the archive key inside the commitment, but store and emit a neutral value in the existing `unlockSeal` field so the filing ABI and normal workflow remain stable:

```solidity
bytes32 commitment = keccak256(
    abi.encode(msg.sender, shardId, uri, archiveKey, nonce)
);
bytes32 publicSeal = bytes32(0);
```

Both services must then verify each receipt against canonical chain state, trusting only the transaction locator (`txHash` and `logIndex`) as input and deriving everything else from what the chain actually returns. The verifier should, in order:

1. Validate the locator shape only: `txHash` is a 32-byte hash and `logIndex` an integer. No other submitted field is read as authority.
2. Fetch the transaction receipt over RPC and require a successful status, then require sufficient confirmation depth so an unconfirmed or reorg-able transaction is rejected.
3. Take the log at the claimed `logIndex` and confirm it was emitted by the configured registry by comparing the emitting `log.address` against the deployed address (never a caller-supplied `registry` field), and confirm it carries the `ShardFiled` topic.
4. Decode the event and derive every authorization value, owner, shard, URI, and nonce, from the decoded log rather than from the request.
5. Bind authority to the actor: the filing owner decoded from the log must equal the authenticated principal, and the shard must match the requested action.

Because every value that grants access is taken from the decoded, provenance-checked event, the caller cannot assert a registry, owner, shard, seal, or nonce by naming it. A foreign registry fails at step 3, a mismatched owner at step 5, and a fabricated transaction at step 2.

The provenance check that closes the app route is small; the point is where it draws its facts from:

```typescript
const txReceipt = await client.getTransactionReceipt({ hash: receipt.txHash });
if (txReceipt.status !== "success") throw new Error("unconfirmed or reverted");
if (currentBlock - txReceipt.blockNumber < MIN_CONFIRMATIONS) throw new Error("insufficient depth");

const log = txReceipt.logs[receipt.logIndex];
if (getAddress(log.address) !== getAddress(REGISTRY_ADDRESS)) throw new Error("foreign registry");

const decoded = decodeEventLog({ abi: [shardFiledEvent], data: log.data, topics: log.topics });
if (decoded.eventName !== "ShardFiled") throw new Error("wrong event");
if (getAddress(decoded.args.owner) !== principal.address) throw new Error("owner is not the caller");
// token derived from decoded.args only, never from `receipt`
```

The archive service applies the same discipline and derives its one-time receipt identifier from these decoded, canonical values plus the requested action, so a replay of an already-consumed receipt is rejected by `markConsumed`.

The player should ensure that public app issues a server-signed, short-lived source token bound to the action, registry, owner, shard, transaction, log, and nonce. The archive service should derive its one-time receipt identifier only from the verified canonical values and include the requested action before calling `markConsumed`.

This removes the capability from public chain data, establishes provenance over RPC, binds authority to the principal and shard, and preserves replay protection. The two halves are load-bearing together: contract-only cleanup remains incomplete while the services still trust event-shaped JSON, and service-only validation remains incomplete while new filings keep publishing usable unlock material. A patch that fixes one service but not the other also fails, because the attack has two independent entry points and the grade requires closing both.

The validation exercises each of these facets separately. It submits fabricated receipts, receipts naming a foreign registry the attacker deployed, receipts whose owner differs from the authenticated principal, replays of an already-consumed receipt, and receipts pointing at shallow or failed transactions. A complete fix rejects all of them while the legitimate operator flow, filing a shard on the deployed registry and opening the archive for its real owner, continues to work.

## Submitting the Patch

```bash
git add phantom_burn/
git commit -m "verify receipts against canonical chain state"
git push -u origin developer
```

The push creates a pull request. Follow its status at:

```text
http://[IP]:[PORT]/pulls
```

## Getting the Flag

After the hard and soft validation gates pass:

```bash
curl -s http://[IP]:[PORT]/flag | jq
```
