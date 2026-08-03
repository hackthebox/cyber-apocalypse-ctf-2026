// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IShardRegistry} from "./interfaces/IShardRegistry.sol";

contract ShardRegistry is IShardRegistry {
    mapping(bytes32 => Shard) private shards;
    mapping(address => uint256) private ownerNonces;

    function fileShard(bytes32 shardId, string calldata uri, bytes32 archiveKey) external {
        require(shardId != bytes32(0), "empty shard");
        require(shards[shardId].owner == address(0), "already filed");

        uint256 nonce = ++ownerNonces[msg.sender];
        // Preserve the event ABI without publishing bearer material.
        bytes32 commitment = keccak256(abi.encode(msg.sender, shardId, uri, archiveKey, nonce));
        bytes32 publicSeal = bytes32(0);

        shards[shardId] = Shard({
            owner: msg.sender,
            uri: uri,
            commitment: commitment,
            unlockSeal: publicSeal,
            nonce: nonce
        });

        emit ShardFiled(msg.sender, shardId, uri, publicSeal, nonce);
    }

    function shardOf(bytes32 shardId) external view returns (Shard memory) {
        return shards[shardId];
    }

    function nonceOf(address owner) external view returns (uint256) {
        return ownerNonces[owner];
    }
}
