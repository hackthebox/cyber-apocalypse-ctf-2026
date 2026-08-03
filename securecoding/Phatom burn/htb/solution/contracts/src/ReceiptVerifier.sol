// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract ReceiptVerifier {
    bytes32 public constant OPEN_ARCHIVE_ACTION = keccak256("phantom_burn.archive.open");

    function receiptId(
        address registry,
        address owner,
        bytes32 shardId,
        bytes32 txHash,
        uint256 logIndex
    ) external pure returns (bytes32) {
        return keccak256(abi.encode(registry, owner, shardId, txHash, logIndex));
    }

    function actionReceiptId(
        address registry,
        address owner,
        bytes32 shardId,
        bytes32 txHash,
        uint256 logIndex,
        bytes32 action
    ) external pure returns (bytes32) {
        return keccak256(abi.encode(registry, owner, shardId, txHash, logIndex, action));
    }
}
