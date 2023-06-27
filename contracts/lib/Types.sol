// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import "./RLPEncode.sol";
import "./ProofLib.sol";
import "./BCS.sol";
import "./BLS.sol";
import "./Bytes.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

library Types {

    struct LedgerInfoWithSignatures {
        uint64 epoch;
        uint64 round;
        bytes32 id;                 // block hash
        bytes32 executedStateId;
        uint64 version;
        uint64 timestampUsecs;
        EpochState nextEpochState;  // only available for the last block of epoch
        Decision pivot;             // may be empty for epoch genesis block
        bytes32 consensusDataHash;
        AccountSignature[] signatures;
    }

    struct AccountSignature {
        bytes32 account;
        bytes consensusSignature;
    }

    struct Decision {
        bytes32 blockHash;
        uint64 height;
    }

    struct EpochState {
        uint64 epoch;
        ValidatorInfo[] validators;
        uint64 quorumVotingPower;
        uint64 totalVotingPower;
        bytes vrfSeed;
    }

    struct ValidatorInfo {
        bytes32 account;
        bytes compressedPublicKey;
        bytes uncompressedPublicKey; // encoded uncompressed public key in 128 bytes
        bytes vrfPublicKey;
        uint64 votingPower;
    }

    struct Committee {
        uint64 quorumVotingPower;
        mapping (bytes32 => CommitteeMember) members;
        bytes32[] accounts;
        uint256 numAccounts;
    }

    struct CommitteeMember {
        bytes publicKey;
        uint64 votingPower;
    }

    function updateCommittee(Committee storage committee, EpochState memory state) internal {
        if (committee.quorumVotingPower != state.quorumVotingPower) {
            committee.quorumVotingPower = state.quorumVotingPower;
        }

        // reset mapping
        uint256 oldLen = committee.numAccounts;
        for (uint256 i = 0; i < oldLen; i++) {
            delete committee.members[committee.accounts[i]];
        }

        // update mapping
        uint256 newLen = state.validators.length;
        for (uint256 i = 0; i < newLen; i++) {
            ValidatorInfo memory validator = state.validators[i];
            require(validator.votingPower > 0, "validator voting pow is zero");
            committee.members[validator.account] = CommitteeMember(
                validator.uncompressedPublicKey,
                validator.votingPower
            );
        }

        // reset and update accounts array
        if (oldLen == 0) {
            committee.accounts = new bytes32[](newLen);
            committee.numAccounts = newLen;
            oldLen = newLen;
        }

        uint256 len = oldLen < newLen ? oldLen : newLen;
        for (uint256 i = 0; i < len; i++) {
            committee.accounts[i] = state.validators[i].account;
        }

        for (uint256 i = oldLen; i < newLen; i++) {
            committee.accounts.push(state.validators[i].account);
        }

        if (oldLen != newLen) {
            committee.numAccounts = newLen;
        }
    }

    function validateBLS(Committee storage committee, LedgerInfoWithSignatures memory ledgerInfo) internal view {
        bytes memory bcsEncoded = _bcsEncodeLedgerInfo(ledgerInfo);

        uint256 voted = 0;
        bytes32 lastAccount = 0;

        for (uint256 i = 0; i < ledgerInfo.signatures.length; i++) {
            // requires in order to avoid duplicated pos account
            bytes32 account = ledgerInfo.signatures[i].account;
            require(account > lastAccount, "signature accounts not in order");
            lastAccount = account;

            // should be in committee
            CommitteeMember memory member = committee.members[account];
            require(member.votingPower > 0, "validator not in committee");
            voted += member.votingPower;

            BLS.verify(ledgerInfo.signatures[i].consensusSignature, bcsEncoded, member.publicKey);
        }

        require(voted >= committee.quorumVotingPower, "voting power not enough");
    }

    bytes32 private constant BCS_CFX_PREFIX = 0xcd510d1ab583c33b54fa949014601df0664857c18c4cfb228c862dd869df1b62;

    function _bcsEncodeLedgerInfo(LedgerInfoWithSignatures memory ledgerInfo) private pure returns (bytes memory) {
        bytes memory consensusDataHash = abi.encodePacked(ledgerInfo.consensusDataHash);
        bytes memory id = abi.encodePacked(ledgerInfo.id);
        bytes memory executedStateId = abi.encodePacked(ledgerInfo.executedStateId);

        uint256 size = BCS.SIZE_BYTES32 // BCS prefix
            + BCS.SIZE_UINT64 // epoch
            + BCS.SIZE_UINT64 // round
            + BCS.sizeBytes(id)
            + BCS.sizeBytes(executedStateId)
            + BCS.SIZE_UINT64 // version
            + BCS.SIZE_UINT64 // timestampUsecs
            + BCS.SIZE_OPTION + _bcsSize(ledgerInfo.nextEpochState) // Option(nextEpochState)
            + BCS.SIZE_OPTION // Option(pivot)
            + BCS.sizeBytes(consensusDataHash);

        bytes memory pivotBlockHash;
        if (ledgerInfo.pivot.blockHash != 0) {
            pivotBlockHash = bytes(Strings.toHexString(uint256(bytes32(ledgerInfo.pivot.blockHash)), 32));
            size += BCS.SIZE_UINT64; // height
            size += BCS.sizeBytes(pivotBlockHash); // block hash
        }

        Bytes.Builder memory builder = Bytes.newBuilder(size);

        BCS.encodeBytes32(builder, BCS_CFX_PREFIX);
        BCS.encodeUint64(builder, ledgerInfo.epoch);
        BCS.encodeUint64(builder, ledgerInfo.round);
        BCS.encodeBytes(builder, id);
        BCS.encodeBytes(builder, executedStateId);
        BCS.encodeUint64(builder, ledgerInfo.version);
        BCS.encodeUint64(builder, ledgerInfo.timestampUsecs);
        _bcsEncode(builder, ledgerInfo.nextEpochState);

        // pivot
        BCS.encodeOption(builder, ledgerInfo.pivot.blockHash != 0);
        if (ledgerInfo.pivot.blockHash != 0) {
            BCS.encodeUint64(builder, ledgerInfo.pivot.height);
            BCS.encodeBytes(builder, pivotBlockHash);
        }

        BCS.encodeBytes(builder, consensusDataHash);

        return builder.buf;
    }

    function _bcsSize(EpochState memory state) private pure returns (uint256 size) {
        if (state.epoch == 0) {
            return 0;
        }

        size += BCS.SIZE_UINT64; // epoch
        size += BCS.SIZE_UINT64; // quorumVotingPower
        size += BCS.SIZE_UINT64; // totalVotingPower

        size += BCS.sizeBytes(state.vrfSeed); // vrf seed

        // validators
        uint256 numValidators = state.validators.length;
        size += BCS.sizeLength(numValidators);
        bytes32 lastAccount = 0;
        for (uint256 i = 0; i < numValidators; i++) {
            // pos account in ASC order
            ValidatorInfo memory validator = state.validators[i];
            require(validator.account > lastAccount, "Validators not in order");
            lastAccount = validator.account;

            // map key: pos account
            size += BCS.SIZE_BYTES32;

            // map value: public key, vrf public key and voting power
            size += BCS.sizeBytes(validator.compressedPublicKey);
            size += BCS.SIZE_OPTION;
            if (validator.vrfPublicKey.length > 0) {
                size += BCS.sizeBytes(validator.vrfPublicKey);
            }
            size += BCS.SIZE_UINT64;
        }
    }

    function _bcsEncode(Bytes.Builder memory builder, EpochState memory state) private pure {
        BCS.encodeOption(builder, state.epoch > 0);

        if (state.epoch == 0) {
            return;
        }

        BCS.encodeUint64(builder, state.epoch);

        uint256 numValidators = state.validators.length;
        BCS.encodeLength(builder, numValidators);
        for (uint256 i = 0; i < numValidators; i++) {
            ValidatorInfo memory validator = state.validators[i];
            BCS.encodeBytes32(builder, validator.account);

            BCS.encodeBytes(builder, validator.compressedPublicKey);
            BCS.encodeOption(builder, validator.vrfPublicKey.length > 0);
            if (validator.vrfPublicKey.length > 0) {
                BCS.encodeBytes(builder, validator.vrfPublicKey);
            }
            BCS.encodeUint64(builder, validator.votingPower);
        }

        BCS.encodeUint64(builder, state.quorumVotingPower);
        BCS.encodeUint64(builder, state.totalVotingPower);
        BCS.encodeBytes(builder, state.vrfSeed);
    }

    struct BlockHeader {
        bytes32 parentHash;
        uint256 height;
        uint256 timestamp;
        address author;
        bytes32 transactionsRoot;
        bytes32 deferredStateRoot;
        bytes32 deferredReceiptsRoot;
        bytes32 deferredLogsBloomHash;
        uint256 blame;
        uint256 difficulty;
        bool adaptive;
        uint256 gasLimit;
        bytes32[] refereeHashes;
        bytes[] custom;
        uint256 nonce;
        bytes32 posReference;
    }

    function encodeBlockHeader(BlockHeader memory header) internal pure returns (bytes memory) {
        uint256 len = header.posReference == bytes32(0) ? 14 : 15;
        len += header.custom.length;
        bytes[] memory list = new bytes[](len);

        list[0] = RLPEncode.encodeBytes(abi.encodePacked(header.parentHash));
        list[1] = RLPEncode.encodeUint(header.height);
        list[2] = RLPEncode.encodeUint(header.timestamp);
        list[3] = RLPEncode.encodeAddress(header.author);
        list[4] = RLPEncode.encodeBytes(abi.encodePacked(header.transactionsRoot));
        list[5] = RLPEncode.encodeBytes(abi.encodePacked(header.deferredStateRoot));
        list[6] = RLPEncode.encodeBytes(abi.encodePacked(header.deferredReceiptsRoot));
        list[7] = RLPEncode.encodeBytes(abi.encodePacked(header.deferredLogsBloomHash));
        list[8] = RLPEncode.encodeUint(header.blame);
        list[9] = RLPEncode.encodeUint(header.difficulty);
        list[10] = RLPEncode.encodeUint(header.adaptive ? 1 : 0);
        list[11] = RLPEncode.encodeUint(header.gasLimit);
        list[12] = _encodeBytes32Array(header.refereeHashes);
        list[13] = RLPEncode.encodeUint(header.nonce);

        uint256 offset = 14;

        if (header.posReference != bytes32(0)) {
            list[offset] = _encodePosReference(header.posReference);
            offset++;
        }

        for (uint256 i = 0; i < header.custom.length; i++) {
            // add as raw data
            list[offset + i] = header.custom[i];
        }

        return RLPEncode.encodeList(list);
    }

    function _encodePosReference(bytes32 pos) private pure returns (bytes memory) {
        if (pos == bytes32(0)) {
            bytes[] memory list = new bytes[](0);
            return RLPEncode.encodeList(list);
        } else {
            bytes[] memory list = new bytes[](1);
            list[0] = RLPEncode.encodeBytes(abi.encodePacked(pos));
            return RLPEncode.encodeList(list);
        }
    }

    function _encodeBytes32Array(bytes32[] memory data) private pure returns (bytes memory) {
        bytes[] memory list = new bytes[](data.length);

        for (uint256 i = 0; i < data.length; i++) {
            list[i] = RLPEncode.encodeBytes(abi.encodePacked(data[i]));
        }

        return RLPEncode.encodeList(list);
    }

    function computeBlockHash(BlockHeader memory header) internal pure returns (bytes32) {
        bytes memory encoded = encodeBlockHeader(header);
        return keccak256(encoded);
    }

    struct ReceiptProof {
        // Continuous block headers, that head is for receipts root,
        // and tail block should be relayed on chain.
        BlockHeader[] headers;

        bytes blockIndex;
        ProofLib.ProofNode[] blockProof;

        bytes32 receiptsRoot;
        bytes index;
        TxReceipt receipt;
        ProofLib.ProofNode[] receiptProof;
    }

    struct TxReceipt {
        uint256 accumulatedGasUsed;
        uint256 gasFee;
        bool gasSponsorPaid;
        bytes logBloom;
        TxLog[] logs;
        uint8 outcomeStatus;
        bool storageSponsorPaid;
        StorageChange[] storageCollateralized;
        StorageChange[] storageReleased;
    }

    struct TxLog {
        address addr;
        bytes32[] topics;
        bytes data;
        uint8 space; // Native: 1, Ethereum: 2
    }

    struct StorageChange {
        address account;
        uint64 collaterals;
    }

    function encodeReceipt(TxReceipt memory receipt) internal pure returns (bytes memory) {
        bytes[] memory list = new bytes[](9);

        list[0] = RLPEncode.encodeUint(receipt.accumulatedGasUsed);
        list[1] = RLPEncode.encodeUint(receipt.gasFee);
        list[2] = RLPEncode.encodeBool(receipt.gasSponsorPaid);
        list[3] = RLPEncode.encodeBytes(receipt.logBloom);
        list[4] = encodeLogs(receipt.logs);
        list[5] = RLPEncode.encodeUint(receipt.outcomeStatus);
        list[6] = RLPEncode.encodeBool(receipt.storageSponsorPaid);
        list[7] = _encodeStorageChanges(receipt.storageCollateralized);
        list[8] = _encodeStorageChanges(receipt.storageReleased);

        return RLPEncode.encodeList(list);
    }

    function encodeLogs(TxLog[] memory logs) internal pure returns (bytes memory) {
        bytes[] memory list = new bytes[](logs.length);

        for (uint256 i = 0; i < logs.length; i++) {
            require(logs[i].space == 1 || logs[i].space == 2, "Types: invalid space of receipt");

            bytes[] memory tmp = new bytes[](logs[i].space == 1 ? 3 : 4);

            tmp[0] = RLPEncode.encodeAddress(logs[i].addr);
            tmp[1] = _encodeBytes32Array(logs[i].topics);
            tmp[2] = RLPEncode.encodeBytes(logs[i].data);

            // append space for eSpace
            if (logs[i].space == 2) {
                tmp[3] = RLPEncode.encodeUint(2);
            }

            list[i] = RLPEncode.encodeList(tmp);
        }

        return RLPEncode.encodeList(list);
    }

    function _encodeStorageChanges(StorageChange[] memory changes) private pure returns (bytes memory) {
        bytes[] memory list = new bytes[](changes.length);
        bytes[] memory tmp = new bytes[](2);

        for (uint256 i = 0; i < changes.length; i++) {
            tmp[0] = RLPEncode.encodeAddress(changes[i].account);
            tmp[1] = RLPEncode.encodeUint(changes[i].collaterals);
            list[i] = RLPEncode.encodeList(tmp);
        }

        return RLPEncode.encodeList(list);
    }

}
