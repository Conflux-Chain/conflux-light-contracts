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

    address private constant PRECOMPILE_BIG_MOD_EXP = 0x0000000000000000000000000000000000000005;
    address private constant PRECOMPILE_BLS12_MAP_FP2_TO_G2 = 0x0000000000000000000000000000000000000012;
    address private constant PRECOMPILE_BLS12_G2ADD = 0x000000000000000000000000000000000000000d;
    address private constant PRECOMPILE_BLS12_PAIRING = 0x0000000000000000000000000000000000000010;

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

        bytes memory output = new bytes(32);
        callPrecompile(PRECOMPILE_BLS12_PAIRING, builder.seal(), output);
        return abi.decode(output, (bool));
    }

    function hashToCurve(bytes memory message) internal view returns (bytes memory) {
        bytes memory fe = hashToField(message);

        bytes memory p = new bytes(512);
        callPrecompile(PRECOMPILE_BLS12_MAP_FP2_TO_G2, fe, 0, 128, p, 0, 256);
        callPrecompile(PRECOMPILE_BLS12_MAP_FP2_TO_G2, fe, 128, 128, p, 256, 256);

        bytes memory output = new bytes(256);
        callPrecompile(PRECOMPILE_BLS12_G2ADD, p, output);
        return output;
    }

    uint256 private constant H_IN_CHUNK_SIZE = 64;
    uint256 private constant H_OUT_CHUNK_SIZE = 32;
    uint256 private constant L = 64;
    uint256 private constant MSG_LEN = L * 2 * 2; // 256
    uint256 private constant ELL = MSG_LEN / H_OUT_CHUNK_SIZE; // 8

    bytes private constant DST_SUFFIX = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_+";
    bytes32 private constant P_0 = 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7;
    bytes32 private constant P_1 = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    function hashToField(bytes memory message) internal view returns (bytes memory) {
        bytes memory expanded = expandMessageXmd(message);

        Bytes.Builder memory builder = Bytes.newBuilder(32 * 3 + L + 1 + L);
        builder.appendIntOSP(L, 32);
        builder.appendIntOSP(1, 32);
        builder.appendIntOSP(L, 32);
        builder.appendEmpty(L); // placeholder for expanded message
        builder.appendUint8(1);
        builder.appendBytes32(P_0);
        builder.appendBytes32(P_1);

        for (uint256 i = 0; i < MSG_LEN; i += L) {
            _inPlaceBigMod(builder, expanded, i);
        }

        return expanded;
    }

    function expandMessageXmd(bytes memory message) internal pure returns (bytes memory) {
        Bytes.Builder memory b = Bytes.newBuilder(ELL * 32);
        bytes memory buf = b.buf;

        Bytes.Builder memory builder = Bytes.newBuilder(H_IN_CHUNK_SIZE + message.length + 2 + 1 + DST_SUFFIX.length);
        builder.appendIntOSP(0, H_IN_CHUNK_SIZE);
        builder.appendBytes(message);
        builder.appendIntOSP(MSG_LEN, 2);
        builder.appendIntOSP(0, 1);
        builder.appendBytes(DST_SUFFIX);
        bytes32 b0 = sha256(builder.seal());

        builder = Bytes.newBuilder(32 + 1 + DST_SUFFIX.length);
        builder.appendBytes32(b0);
        builder.appendIntOSP(1, 1);
        builder.appendBytes(DST_SUFFIX);
        b.appendBytes32(sha256(builder.seal()));

        for (uint256 i = 2; i <= ELL; i++) {
            builder.reset();
            // append b[0] ^ b[i-1] 
            bytes32 xorVal;
            uint256 offset = b.offset;
            assembly {
                xorVal := xor(b0, mload(add(buf, offset)))
            }
            builder.appendBytes32(xorVal);
            builder.appendIntOSP(i, 1);
            builder.appendEmpty(DST_SUFFIX.length); // filled already
            b.appendBytes32(sha256(builder.seal()));
        }

        return b.seal();
    }

    function _inPlaceBigMod(Bytes.Builder memory builder, bytes memory buf, uint256 offset) private view {
        builder.reset();
        builder.appendEmpty(96);
        builder.appendBytes(buf, offset, L);
        builder.appendEmpty(1 + L);

        callPrecompile(PRECOMPILE_BIG_MOD_EXP, builder.seal(), buf, offset, L);
    }

    function _paddingAppend(Bytes.Builder memory builder, uint256 padding, bytes memory val, uint256 offset, uint256 len) private pure {
        builder.appendEmpty(padding);
        builder.appendBytes(val, offset, len);
    }

    function callPrecompile(address precompile, bytes memory input, bytes memory output) internal view {
        return callPrecompile(precompile, input, 0, input.length, output, 0, output.length);
    }

    function callPrecompile(address precompile, bytes memory input, bytes memory output, uint256 outputOffset, uint256 outputLen) internal view {
        return callPrecompile(precompile, input, 0, input.length, output, outputOffset, outputLen);
    }

    function callPrecompile(address precompile, 
        bytes memory input, uint256 inputOffset, uint256 inputLen,
        bytes memory output, uint256 outputOffset, uint256 outputLen
    ) internal view {
        require(inputOffset + inputLen <= input.length, "BLS: input out of bound");
        require(outputOffset + outputLen <= output.length, "BLS: output out of bound");

        bool success;

        assembly {
            let inputPtr := add(input, add(inputOffset, 32))
            let outputPtr := add(output, add(outputOffset, 32))
            success := staticcall(gas(), precompile, inputPtr, inputLen, outputPtr, outputLen)
        }

        require(success, "BLS: Failed to call pre-compile contract");
    }

}
