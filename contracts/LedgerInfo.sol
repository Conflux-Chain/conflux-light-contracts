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

}
