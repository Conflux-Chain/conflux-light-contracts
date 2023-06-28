// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

/**
 * @dev This is used to optimize gas cost for bytes operations.
 *
 * Note, client should make sure the buffer size is enough for append operations.
 */
library Bytes {

    struct Builder {
        bytes buf;
        uint256 offset;
    }

    function newBuilder(uint256 size) internal pure returns (Builder memory) {
        return Builder(new bytes(size), 0);
    }

    function seal(Builder memory builder) internal pure returns (bytes memory) {
        require(builder.offset == builder.buf.length, "Bytes: buffer not fully filled");
        return builder.buf;
    }

    function reset(Builder memory builder) internal pure {
        builder.offset = 0;
    }

    function appendUint8(Builder memory builder, uint8 val) internal pure {
        builder.buf[builder.offset] = bytes1(val);
        builder.offset++;
    }

    function appendBytes32(Builder memory builder, bytes32 val) internal pure {
        for (uint256 i = 0; i < 32; i++) {
            builder.buf[builder.offset + i] = val[i];
        }

        builder.offset += 32;
    }

    function appendBytes(Builder memory builder, bytes memory val) internal pure {
        for (uint256 i = 0; i < val.length; i++) {
            builder.buf[builder.offset + i] = val[i];
        }

        builder.offset += val.length;
    }

    function appendBytes(Builder memory builder, bytes memory val, uint256 offset, uint256 len) internal pure {
        for (uint256 i = 0; i < len; i++) {
            builder.buf[builder.offset + i] = val[offset + i];
        }

        builder.offset += len;
    }

    function appendEmpty(Builder memory builder, uint256 n) internal pure {
        builder.offset += n;
    }

    function appendIntOSP(Builder memory builder, uint256 x, uint256 len) internal pure {
        uint256 index = builder.offset + len - 1;

        while (x > 0) {
            builder.buf[index] = bytes1(uint8(x & 0xFF)); // big endian
            index--;
            x >>= 8;
        }

        builder.offset += len;
    }

    function concat2(bytes memory b1, bytes memory b2) internal pure returns (bytes memory) {
        bytes memory result = new bytes(b1.length + b2.length);

        for (uint256 i = 0; i < b1.length; i++) {
            result[i] = b1[i];
        }

        for (uint256 i = 0; i < b2.length; i++) {
            result[b1.length + i] = b2[i];
        }

        return result;
    }

    function copy(bytes memory b1, uint256 offset, bytes memory b2) internal pure {
        for (uint256 i = 0; i < b2.length; i++) {
            b1[offset + i] = b2[i];
        }
    }

}
