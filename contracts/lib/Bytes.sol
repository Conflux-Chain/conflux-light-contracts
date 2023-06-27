// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

/**
 * @dev This is used to optimize gas cost for bytes operations.
 */
library Bytes {

    struct Builder {
        bytes buf;
        uint256 offset;
    }

    function newBuilder(uint256 size) internal pure returns (Builder memory) {
        return Builder(new bytes(size), 0);
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

        builder.offset += val.length;
    }

    function appendEmpty(Builder memory builder, uint256 n) internal pure {
        builder.offset += n;
    }

}
