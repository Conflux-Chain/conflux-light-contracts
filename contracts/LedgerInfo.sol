// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import "./interface/ILedgerInfo.sol";
import "./lib/LedgerInfoLib.sol";
import "./lib/BLS.sol";

contract LedgerInfo is ILedgerInfo {

    function bcsEncode(LedgerInfoLib.LedgerInfoWithSignatures memory ledgerInfo) external pure override returns (bytes memory) {
        return LedgerInfoLib.bcsEncodeLedgerInfo(ledgerInfo);
    }

    function batchVerifyBLS(bytes[] memory signatures, bytes memory message, bytes[] memory publicKeys) external view override returns (bool) {
        return BLS.batchVerify(signatures, message, publicKeys);
    }

    function verifyBLS(bytes memory signature, bytes memory message, bytes memory publicKey) external view override returns (bool) {
        return BLS.verify(signature, message, publicKey);
    }

}
