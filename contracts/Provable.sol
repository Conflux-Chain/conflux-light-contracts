// SPDX-License-Identifier: MIT

pragma solidity 0.8.4;

import "./lib/ProofLib.sol";
import "./lib/Types.sol";

contract Provable {

    function prove(
        bytes32 root,
        bytes memory key,
        bytes32 valueHash,
        ProofLib.ProofNode[] memory nodes
    ) external pure returns (bool) {
        return ProofLib.Prove(root, key, valueHash, nodes);
    }

    function proveReceipt(
        bytes32 blockRoot,
        bytes memory blockIndex,
        ProofLib.ProofNode[] memory blockProof,
        bytes32 receiptsRoot,
        bytes memory index,
        Types.TxReceipt memory receipt,
        ProofLib.ProofNode[] memory receiptProof
    ) external pure returns (bool) {
        bytes memory encodedReceipt = Types.encodeReceipt(receipt);
        if (!ProofLib.Prove(receiptsRoot, index, keccak256(encodedReceipt), receiptProof)) {
            return false;
        }

        bytes memory blockValue = abi.encodePacked(receiptsRoot);
        return ProofLib.Prove(blockRoot, blockIndex, keccak256(blockValue), blockProof);
    }

}
