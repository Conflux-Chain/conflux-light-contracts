// SPDX-License-Identifier: MIT

pragma solidity 0.8.4;

import "../lib/Types.sol";

interface ILightNode {

    struct ClientState {
        uint256 epoch;                  // pos block epoch
        uint256 round;                  // pos block round

        uint256 earliestBlockNumber;    // earliest pow block number relayed
        uint256 finalizedBlockNumber;   // last finalized pow block number

        uint256 blocks;                 // number of relayed pow blocks
        uint256 maxBlocks;              // maximum number of pow blocks to retain
    }

    event UpdateLightClient(address indexed account, uint256 epoch, uint256 round, uint256 height);
    event UpdateBlockHeader(address indexed account, uint256 start, uint256 end);

    function initialize(
        address _controller,
        address _mptVerify,
        Types.LedgerInfoWithSignatures memory ledgerInfo
    ) external;

    function verifyReceiptProof(Types.ReceiptProof memory proof) external view returns (bool success, Types.TxLog[] memory logs);
    function verifyProofData(bytes memory receiptProof) external view returns (bool success, string memory message, bytes memory rlpLogs);

    function updateLightClient(Types.LedgerInfoWithSignatures memory ledgerInfo) external;
    function updateBlockHeader(Types.BlockHeader[] memory headers) external;

    function clientState() external view returns(ClientState memory);
    function verifiableHeaderRange() external view returns (uint256, uint256);
}
