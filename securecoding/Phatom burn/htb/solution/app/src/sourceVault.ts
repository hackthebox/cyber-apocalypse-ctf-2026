import crypto from "node:crypto";
import { createPublicClient, decodeEventLog, http, parseAbiItem, toEventHash } from "viem";
import { foundry } from "viem/chains";
import type { AppConfig } from "./config.js";

export type UnlockReceipt = {
  txHash: string;
  logIndex: number;
  registry: string;
  owner: string;
  shardId: string;
  uri: string;
  unlockSeal?: string;
  nonce: string;
};

const shardFiledEvent = parseAbiItem(
  "event ShardFiled(address indexed owner, bytes32 indexed shardId, string uri, bytes32 unlockSeal, uint256 nonce)"
);
const sourceConfirmations = Number(process.env.SOURCE_BUNDLE_CONFIRMATIONS ?? "12");
const sourceBundleAction = "source.bundle.download";

function signingKey(): string {
  const key = process.env.SOURCE_BUNDLE_SIGNING_KEY;
  if (!key || key.length < 32) {
    throw new Error("SOURCE_BUNDLE_SIGNING_KEY is not configured");
  }
  return key;
}

function isHex(value: string | undefined, bytes?: number): value is `0x${string}` {
  if (!value || !/^0x[0-9a-fA-F]+$/.test(value)) {
    return false;
  }
  return bytes === undefined || value.length === 2 + bytes * 2;
}

function sameHex(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function encode(data: object): string {
  return Buffer.from(JSON.stringify(data)).toString("base64url");
}

function sign(payload: string): string {
  return crypto.createHmac("sha256", signingKey()).update(payload).digest("base64url");
}

export type VerifiedUnlock = {
  registry: string;
  owner: string;
  shardId: string;
  txHash: string;
  logIndex: number;
  uri: string;
  unlockSeal: string;
  nonce: string;
};

const consumedUnlockReceipts = new Set<string>();

export function unlockReceiptId(verified: VerifiedUnlock): string {
  return crypto
    .createHash("sha256")
    .update([
      "source.unlock",
      verified.registry.toLowerCase(),
      verified.owner.toLowerCase(),
      verified.shardId.toLowerCase(),
      verified.txHash.toLowerCase(),
      verified.logIndex,
      verified.unlockSeal.toLowerCase(),
      verified.nonce
    ].join(":"))
    .digest("hex");
}

export function consumeUnlockReceipt(receiptId: string): boolean {
  if (consumedUnlockReceipts.has(receiptId)) {
    return false;
  }
  consumedUnlockReceipts.add(receiptId);
  return true;
}

export function resetUnlockStoreForTests(): void {
  consumedUnlockReceipts.clear();
}

export function issueArchiveToken(verified: VerifiedUnlock): string {
  const payload = encode({
    action: sourceBundleAction,
    registry: verified.registry.toLowerCase(),
    owner: verified.owner.toLowerCase(),
    shardId: verified.shardId.toLowerCase(),
    uri: verified.uri,
    txHash: verified.txHash.toLowerCase(),
    logIndex: verified.logIndex,
    nonce: verified.nonce,
    exp: Math.floor(Date.now() / 1000) + 300
  });
  return `${payload}.${sign(payload)}`;
}

export function verifyArchiveToken(token: string, context: { shardId: string; txHash: string }): boolean {
  const [payload, signature] = token.split(".");
  if (!payload || !signature) {
    return false;
  }
  const expected = sign(payload);
  if (
    signature.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))
  ) {
    return false;
  }
  try {
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as {
      action?: string;
      exp?: number;
      shardId?: string;
      txHash?: string;
      nonce?: string;
    };
    return Boolean(
      decoded.action === sourceBundleAction &&
        typeof decoded.exp === "number" &&
        decoded.exp >= Math.floor(Date.now() / 1000) &&
        isHex(decoded.shardId, 32) &&
        isHex(decoded.txHash, 32) &&
        sameHex(decoded.shardId, context.shardId) &&
        sameHex(decoded.txHash, context.txHash) &&
        decoded.nonce
    );
  } catch {
    return false;
  }
}

export async function verifyUnlockReceipt(
  config: AppConfig,
  receipt: UnlockReceipt,
  principal: string
): Promise<{ ok: true; verified: VerifiedUnlock; receiptId: string } | { ok: false }> {
  // Only the transaction locator and principal are trusted; authority comes from the confirmed registry log.
  if (!isHex(receipt.txHash, 32) || !Number.isInteger(receipt.logIndex) || !isHex(principal, 20)) {
    return { ok: false };
  }

  const client = createPublicClient({ chain: foundry, transport: http(config.rpcUrl) });
  const txReceipt = await client.getTransactionReceipt({ hash: receipt.txHash });
  if (txReceipt.status !== "success" || txReceipt.blockNumber === null) {
    return { ok: false };
  }

  const latest = await client.getBlockNumber();
  if (latest - txReceipt.blockNumber + 1n < BigInt(sourceConfirmations)) {
    return { ok: false };
  }

  const eventTopic = toEventHash(shardFiledEvent);
  const log = txReceipt.logs.find((candidate) => Number(candidate.logIndex) === receipt.logIndex);
  if (!log || !sameHex(log.address, config.registryAddress)) {
    return { ok: false };
  }

  const decoded = decodeEventLog({
    abi: [shardFiledEvent],
    data: log.data,
    topics: log.topics
  });
  const args = decoded.args as {
    owner: string;
    shardId: string;
    uri: string;
    unlockSeal: string;
    nonce: bigint;
  };

  const authorized =
    sameHex(String(log.topics[0]), eventTopic) &&
    sameHex(args.owner, principal);

  if (!authorized) {
    return { ok: false };
  }

  const verified: VerifiedUnlock = {
    registry: config.registryAddress,
    owner: args.owner,
    shardId: args.shardId,
    txHash: receipt.txHash,
    logIndex: Number(log.logIndex),
    uri: args.uri,
    unlockSeal: args.unlockSeal,
    nonce: args.nonce.toString()
  };

  return { ok: true, verified, receiptId: unlockReceiptId(verified) };
}
