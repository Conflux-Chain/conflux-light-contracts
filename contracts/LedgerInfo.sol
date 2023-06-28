// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import "./lib/LedgerInfoLib.sol";
import "./lib/BLS.sol";

contract LedgerInfo {

    /**
     * @dev BCS encode the specified `ledgerInfo`.
     */
    function bcsEncode(LedgerInfoLib.LedgerInfoWithSignatures memory ledgerInfo) public pure returns (bytes memory) {
        return LedgerInfoLib.bcsEncodeLedgerInfo(ledgerInfo);
    }

    /**
     * @dev Verify BLS signatures in batch.
     * @param signatures uncompressed BLS signatures (each in 192 bytes).
     * @param message message to verify.
     * @param publicKeys uncompressed BLS public keys (each in 96 bytes).
     */
    function batchVerifyBLS(bytes[] memory signatures, bytes memory message, bytes[] memory publicKeys) public view returns (bool) {
        return BLS.batchVerify(signatures, message, publicKeys);
    }

    /**
     * @dev Verifies BLS signature.
     * @param signature uncompressed BLS signature in 192 bytes.
     * @param message message to verify.
     * @param publicKey uncompressed BLS public key in 96 bytes.
     */
    function verifyBLS(bytes memory signature, bytes memory message, bytes memory publicKey) public view returns (bool) {
        return BLS.verify(signature, message, publicKey);
    }

    /**
     * @dev Verifies BLS signature with hashed message.
     * @param signature uncompressed BLS signature in 192 bytes.
     * @param g2Message hashed message (G2 point encoded) in 256 bytes to verify.
     * @param publicKey uncompressed BLS public key in 96 bytes.
     */
    function verifyBLSHashed(bytes memory signature, bytes memory g2Message, bytes memory publicKey) public view returns (bool) {
        return BLS.verifyHashed(signature, g2Message, publicKey);
    }

    function hashToCurve(bytes memory message) public view returns (bytes memory) {
        return BLS.hashToCurve(message);
    }

    function hashToField(bytes memory message) public view returns (bytes[2] memory) {
        return BLS.hashToField(message);
    }

    function expandMessageXmd(bytes memory message) public pure returns (bytes[2] memory) {
        return BLS.expandMessageXmd(message);
    }

    function callPrecompile(address precompile, bytes memory input) public view returns (bytes memory) {
        return BLS.callPrecompile(precompile, input);
    }

}
