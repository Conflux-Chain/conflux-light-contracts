// SPDX-License-Identifier: MIT

pragma solidity 0.8.4;

import "./RLPEncode.sol";
import "./ProofLib.sol";

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
        bytes publicKey;
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
                validator.publicKey,
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
        uint256 voted = 0;

        bytes32 lastAccount = 0;

        for (uint256 i = 0; i < ledgerInfo.signatures.length; i++) {
            bytes32 account = ledgerInfo.signatures[i].account;
            require(account > lastAccount, "signature accounts not in order");
            lastAccount = account;

            // should be in committee
            CommitteeMember memory member = committee.members[account];
            require(member.votingPower > 0, "validator not in committee");
            voted += member.votingPower;

            // TODO validate BLS public key
            // bytes memory pubKey = _recoverBLSPublicKey(ledgerInfo, ledgerInfo.signatures[i].consensusSignature);
            // require(keccak256(pubKey) == keccak256(member.publicKey), "public key invalid");
        }

        require(voted >= committee.quorumVotingPower, "voting power not enough");
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

    // compare with pre-computed receipts root for empty blocks [1, 20]
    function isEmptyBlock(BlockHeader memory header) internal pure returns (bool) {
        if (header.deferredReceiptsRoot == 0x09f8709ea9f344a810811a373b30861568f5686e649d6177fd92ea2db7477508) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0x12af19d53c378426ebe08ad33e48caf3efdaaade0994770c161c0637e65a6566) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0xd5f7e7960e9b56753868260c280746c01353dcd1b91a20cee2c919d0dc7bf78b) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0x57e0321f5f0efec94535cd6ad03d443a42892a6ee12f29030b8088b6779bd87a) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0xa7b4b94904890070672b21e6776c4ae06241a9a6fe88b3726f4c0edb2594257a) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0x42f61401e73d24bc24028eb3209bbe9d135be4a15dd56506dbdb66c38ad57984) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0xd7862ef54f5a4b15bdeaee63f3980ec03404c9f287853b80f88d5dc8d445bc0e) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0x0ea51f5d0e4cf9fa6ab8754df358757484d09750f5f5a89428bd726b980d935b) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0x9341a5784b41abfd78f7beaa2c217f78bdd681fbe1ee5cbbded07e863466535a) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0xa1da1d64f2e04d74e79e9eb0c3ddc5cd3451ef7b5b7a52992599e90678a8e1e1) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0xeb9a8367b7c337007429aacde08df68b472cc05db17badf3349c0aa52b7a5b43) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0x0b65f15fb078211b73cf5bfcb67b8d5dda93841bdd595f0bf0ebc51863d922db) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0xf92b605838d45c811f96a01e50874f0c0b753290b3c377fdb0259b71b3c1eaf4) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0x233046ceceb5ac2a080c1a57aa6858983aa01e705747f2e8815e75a9fee9d936) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0x0c2d11c5f29ee19e2e5dce03fbba2034414c33315896e44f54263235d3863d4a) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0x55fda8bbcfe5f702778bbc31dfae46b720bed7a000ba45479383cf7d6f18a71f) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0xc631a8288b078fcd2961706020640c113a60fb782230a5cb7e75cf77bf8b415a) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0x361fbf183096216dcdbb1b7e9ddef12ed701e0af4489681958a03672ad8f9200) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0xf4f37fec623a9f2db3716d2ec53a4e9d5f1a9a9e5b1eb47cc87c34993ed67fb9) {
            return true;
        }

        if (header.deferredReceiptsRoot == 0x5c97b3758899c93a47387f9a6f05aa9600120925c07c009e108dc3713d94c937) {
            return true;
        }

        return false;
    }

    struct ReceiptProof {
        uint256 epochNumber;

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
