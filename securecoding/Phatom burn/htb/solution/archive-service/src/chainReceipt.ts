import crypto from "node:crypto";
import { createPublicClient, decodeEventLog, http, parseAbiItem, toEventHash } from "viem";
import { foundry } from "viem/chains";
import type { ArchiveConfig } from "./config.js";

export type ChainReceipt = {
  txHash: string;
  logIndex: number;
  registry: string;
  owner: string;
  shardId: string;
  unlockSeal: string;
  nonce: string;
};

export type Principal = {
  address: string;
  role: "keeper" | "visitor";
};

function verifiedReceiptId(input: {
  registry: string;
  owner: string;
  shardId: string;
  txHash: string;
  logIndex: number;
  unlockSeal: string;
  nonce: string;
}): string {
  return crypto
    .createHash("sha256")
    .update([
      "archive.open",
      input.registry.toLowerCase(),
      input.owner.toLowerCase(),
      input.shardId.toLowerCase(),
      input.txHash.toLowerCase(),
      input.logIndex,
      input.unlockSeal.toLowerCase(),
      input.nonce
    ].join(":"))
    .digest("hex");
}

const shardFiledEvent = parseAbiItem(
  "event ShardFiled(address indexed owner, bytes32 indexed shardId, string uri, bytes32 unlockSeal, uint256 nonce)"
);

function isHex(value: string | undefined, bytes?: number): value is `0x${string}` {
  if (!value || !/^0x[0-9a-fA-F]+$/.test(value)) {
    return false;
  }
  return bytes === undefined || value.length === 2 + bytes * 2;
}

function sameHex(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

export async function verifyReceipt(
  config: ArchiveConfig,
  principal: Principal,
  receipt: ChainReceipt
): Promise<{ ok: true; receiptId: string; shardId: string; owner: string } | { ok: false; reason: string }> {
  // Submitted fields locate the event; verified event values determine authority.
  if (!isHex(receipt.txHash, 32) || !Number.isInteger(receipt.logIndex) || !isHex(principal.address, 20)) {
    return { ok: false, reason: "malformed receipt" };
  }

  const client = createPublicClient({
    chain: foundry,
    transport: http(config.rpcUrl)
  });

  const txReceipt = await client.getTransactionReceipt({ hash: receipt.txHash });
  if (txReceipt.status !== "success" || txReceipt.blockNumber === null) {
    return { ok: false, reason: "transaction not finalized" };
  }

  const latest = await client.getBlockNumber();
  if (latest - txReceipt.blockNumber + 1n < BigInt(config.confirmations)) {
    return { ok: false, reason: "insufficient confirmations" };
  }

  const eventTopic = toEventHash(shardFiledEvent);
  const log = txReceipt.logs.find((candidate) => Number(candidate.logIndex) === receipt.logIndex);
  if (!log || !sameHex(log.address, config.registryAddress)) {
    return { ok: false, reason: "receipt log not found" };
  }

  if (!sameHex(String(log.topics[0]), eventTopic)) {
    return { ok: false, reason: "unexpected event" };
  }

  const decoded = decodeEventLog({
    abi: [shardFiledEvent],
    data: log.data,
    topics: log.topics
  });
  const args = decoded.args as {
    owner: string;
    shardId: string;
    unlockSeal: string;
    nonce: bigint;
  };

  if (!sameHex(args.owner, principal.address)) {
    return { ok: false, reason: "principal does not own filing" };
  }

  return {
    ok: true,
    receiptId: verifiedReceiptId({
      registry: config.registryAddress,
      owner: args.owner,
      shardId: args.shardId,
      txHash: receipt.txHash,
      logIndex: Number(log.logIndex),
      unlockSeal: args.unlockSeal,
      nonce: args.nonce.toString()
    }),
    // Authority values are returned from the decoded event so the route grants
    // against the verified shard and owner, never the submitted receipt.
    shardId: args.shardId,
    owner: args.owner
  };
}
