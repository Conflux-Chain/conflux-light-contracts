// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import "./Bytes.sol";

/**
 * @dev BLS12-381 library to verify BLS signatures.
 */
library BLS {
    using Bytes for Bytes.Builder;

    // Point G1 of -1
    bytes32 private constant G1_NEG_ONE_0 = 0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f;
    bytes32 private constant G1_NEG_ONE_1 = 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
    bytes32 private constant G1_NEG_ONE_2 = 0x00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f2;
    bytes32 private constant G1_NEG_ONE_3 = 0x67816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca;

    /**
     * @dev Batch verify BLS signatures.
     * @param signatures uncompressed BLS signatures.
     * @param message message to verify.
     * @param publicKeys uncompressed BLS public keys.
     */
    function batchVerify(bytes[] memory signatures, bytes memory message, bytes[] memory publicKeys) internal view returns (bool) {
        require(signatures.length == publicKeys.length, "signatures and publicKeys length mismatch");

        bytes memory hashedMessage = hashToCurve(message);
        Bytes.Builder memory builder = _prepareBuffer(hashedMessage);

        for (uint256 i = 0; i < signatures.length; i++) {
            if (!_verify(builder, signatures[i], publicKeys[i])) {
                return false;
            }
        }

        return true;
    }

    /**
     * @dev Verifies BLS signature.
     * @param signature uncompressed BLS signature in 192 bytes.
     * @param message message to verify.
     * @param publicKey uncompressed BLS public key in 96 bytes.
     */
    function verify(bytes memory signature, bytes memory message, bytes memory publicKey) internal view returns (bool) {
        bytes memory hashedMessage = hashToCurve(message);
        return verifyHashed(signature, hashedMessage, publicKey);
    }

    function verifyHashed(bytes memory signature, bytes memory hashedMessage, bytes memory publicKey) internal view returns (bool) {
        Bytes.Builder memory builder = _prepareBuffer(hashedMessage);
        return _verify(builder, signature, publicKey);
    }

    function _prepareBuffer(bytes memory hashedMessage) private pure returns (Bytes.Builder memory) {
        Bytes.Builder memory builder = Bytes.newBuilder(768);

        // public key with padding
        builder.appendEmpty(128);

        // message
        builder.appendBytes(hashedMessage);

        // -1
        builder.appendBytes32(G1_NEG_ONE_0);
        builder.appendBytes32(G1_NEG_ONE_1);
        builder.appendBytes32(G1_NEG_ONE_2);
        builder.appendBytes32(G1_NEG_ONE_3);

        return builder;
    }

    function _verify(Bytes.Builder memory builder, bytes memory signature, bytes memory publicKey) private view returns (bool) {
        require(signature.length == 192, "BLS: signature length mismatch");
        require(publicKey.length == 96, "BLS: public key length mismatch");

        builder.reset();

        // public key with padding
        _paddingAppend(builder, 16, publicKey, 0, 48);
        _paddingAppend(builder, 16, publicKey, 48, 48);

        // message and -1 already filled
        builder.appendEmpty(384);

        // signature with padding
        _paddingAppend(builder, 16, signature, 48, 48);
        _paddingAppend(builder, 16, signature, 0, 48);
        _paddingAppend(builder, 16, signature, 144, 48);
        _paddingAppend(builder, 16, signature, 96, 48);

        // BLS12_PAIRING
        bytes memory output = callPrecompile(address(0x10), builder.seal(), 32);

        return abi.decode(output, (bool));
    }

    function hashToCurve(bytes memory message) internal view returns (bytes memory) {
        bytes[2] memory fe = hashToField(message);

        // BLS12_MAP_FP2_TO_G2
        bytes memory p0 = callPrecompile(address(0x12), fe[0], 256);
        bytes memory p1 = callPrecompile(address(0x12), fe[1], 256);

        // BLS12_G2ADD
        return callPrecompile(address(0xd), Bytes.concat2(p0, p1), 256);
    }

    uint256 private constant H_IN_CHUNK_SIZE = 64;
    uint256 private constant H_OUT_CHUNK_SIZE = 32;
    uint256 private constant L = 64;
    uint256 private constant MSG_LEN = L * 2 * 2; // 256
    uint256 private constant ELL = MSG_LEN / H_OUT_CHUNK_SIZE; // 8

    bytes private constant DST_SUFFIX = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_+";
    bytes32 private constant P_0 = 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7;
    bytes32 private constant P_1 = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    function hashToField(bytes memory message) internal view returns (bytes[2] memory) {
        bytes[2] memory expanded = expandMessageXmd(message);

        for (uint256 i = 0; i < 2; i++) {
            for (uint256 j = 0; j < MSG_LEN/2; j += L) {
                _inPlaceBigMod(expanded[i], j);
            }
        }

        return expanded;
    }

    function expandMessageXmd(bytes memory message) internal pure returns (bytes[2] memory) {
        bytes32[ELL+1] memory b;

        Bytes.Builder memory builder = Bytes.newBuilder(H_IN_CHUNK_SIZE + message.length + 2 + 1 + DST_SUFFIX.length);
        builder.appendIntOSP(0, H_IN_CHUNK_SIZE);
        builder.appendBytes(message);
        builder.appendIntOSP(MSG_LEN, 2);
        builder.appendIntOSP(0, 1);
        builder.appendBytes(DST_SUFFIX);
        b[0] = sha256(builder.seal());

        builder = Bytes.newBuilder(32 + 1 + DST_SUFFIX.length);
        builder.appendBytes32(b[0]);
        builder.appendIntOSP(1, 1);
        builder.appendBytes(DST_SUFFIX);
        b[1] = sha256(builder.seal());

        for (uint256 i = 2; i <= ELL; i++) {
            builder.reset();
            for (uint256 j = 0; j < 32; j++) {
                builder.appendUint8(uint8(b[0][j] ^ b[i - 1][j]));
            }
            builder.appendIntOSP(i, 1);
            builder.appendBytes(DST_SUFFIX);
            b[i] = sha256(builder.seal());
        }

        Bytes.Builder memory fe0 = Bytes.newBuilder(128);
        for (uint256 i = 1; i <= ELL/2; i++) {
            fe0.appendBytes32(b[i]);
        }

        Bytes.Builder memory fe1 = Bytes.newBuilder(128);
        for (uint256 i = ELL/2 + 1; i <= ELL; i++) {
            fe1.appendBytes32(b[i]);
        }

        return [fe0.buf, fe1.buf];
    }

    function _inPlaceBigMod(bytes memory buf, uint256 offset) private view {
        Bytes.Builder memory builder = Bytes.newBuilder(32 * 3 + L + 1 + L);
        builder.appendIntOSP(L, 32);
        builder.appendIntOSP(1, 32);
        builder.appendIntOSP(L, 32);
        builder.appendBytes(buf, offset, L);
        builder.appendUint8(1);
        builder.appendBytes32(P_0);
        builder.appendBytes32(P_1);

        // bigModExp
        bytes memory output = callPrecompile(address(0x5), builder.seal(), L);

        Bytes.copy(buf, offset, output);
    }

    function _paddingAppend(Bytes.Builder memory builder, uint256 padding, bytes memory val, uint256 offset, uint256 len) private pure {
        builder.appendEmpty(padding);
        builder.appendBytes(val, offset, len);
    }

    function callPrecompile(address precompile, bytes memory input, uint256 outputLen) internal view returns (bytes memory out) {
        bool success;
        out = new bytes(outputLen);

        assembly {
            success := staticcall(gas(), precompile, add(input, 32), mload(input), add(out, 32), outputLen)
        }

        require(success, "BLS: Failed to call pre-compile contract");
    }

}
