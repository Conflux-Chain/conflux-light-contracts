// SPDX-License-Identifier: MIT

pragma solidity 0.8.4;

import "../lib/Types.sol";

interface ILightNode {

    struct ClientState {
        uint256 epoch;                  // pos block epoch
        uint256 round;                  // pos block round

        uint256 earliestBlockNumber;    // earliest pow block number relayed
        uint256 finalizedBlockNumber;   // last finalized pow block number

        uint256 relayBlockStartNumber;  // inclusive pow block number to relay from
        uint256 relayBlockEndNumber;    // inclusive pow block number to relay to
        bytes32 relayBlockEndHash;      // pow block hash to relay to

        uint256 blocks;                 // number of relayed non-empty pow blocks
        uint256 maxBlocks;              // maximum number of pow blocks to retain
    }

    event UpdateLightClient(address indexed account, uint256 epoch, uint256 round);
    event UpdateBlockHeader(address indexed account, uint256 start, uint256 end);

    function initialize(
        address _controller,
        address _mptVerify,
        Types.LedgerInfoWithSignatures memory ledgerInfo,
        Types.BlockHeader memory header
    ) external;

    function verifyReceiptProof(Types.ReceiptProof memory proof) external view returns (bool success, Types.TxLog[] memory logs);
    function verifyProofData(bytes memory receiptProof) external view returns (bool success, string memory message, bytes memory rlpLogs);

    function updateLightClient(Types.LedgerInfoWithSignatures memory ledgerInfo) external;
    function updateBlockHeader(Types.BlockHeader[] memory headers) external;
    function removeBlockHeader(uint256 limit) external;

    function clientState() external view returns(ClientState memory);
    function verifiableHeaderRange() external view returns (uint256, uint256);
}
