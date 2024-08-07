// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import "./RLPReader.sol";
import "./ProofLib.sol";

library Types {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for RLPReader.Iterator;

    struct BlockHeaderWrapper {
        bytes32 parentHash;
        uint256 height;
        bytes32 deferredReceiptsRoot;
    }

    function rlpDecodeBlockHeader(bytes memory header) internal pure returns (BlockHeaderWrapper memory wrapper) {
        RLPReader.Iterator memory iter = RLPReader.toRlpItem(header).iterator();
        wrapper.parentHash = bytes32(iter.next().toUintStrict());
        wrapper.height = iter.next().toUint();
        iter.next(); // timestamp
        iter.next(); // miner
        iter.next(); // txs root
        iter.next(); // state root
        wrapper.deferredReceiptsRoot = bytes32(iter.next().toUintStrict());
    }

    struct ReceiptProof {
        // Continuous block headers (RLP encoded), that head is for receipts root,
        // and tail block should be relayed on chain.
        bytes[] headers;

        bytes blockIndex;
        ProofLib.ProofNode[] blockProof;

        bytes32 receiptsRoot;
        bytes index;
        bytes receipt; // RLP encoded
        ProofLib.ProofNode[] receiptProof;
    }

}
