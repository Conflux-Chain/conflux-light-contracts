// SPDX-License-Identifier: MIT

pragma solidity 0.8.4;

import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "./interface/ILightNode.sol";
import "./lib/Types.sol";
import "./Provable.sol";

// Possible improvements:
// 1.1 Could only relay pos blocks and provide pow block headers to verify proof.
// 1.2 Archive pos blocks into merkle root to support full history.
//      E.g. merge 4096 blocks into a root (full simple MPT with depth 3), and ~130 roots per year.
// 2. Allow to validate transaction proof.

contract LightNode is UUPSUpgradeable, Initializable, Pausable, ILightNode {

    uint256 public constant DEFER_EXECUTION_BLOCKS = 5;

    address public mptVerify;

    ClientState private _state;
    Types.Committee private _committee;

    // pow block number => deferred receipt root
    mapping(uint256 => bytes32) public deferredReceiptsRoots;

    /**
     * @dev Always initialize with the first pos block of any epoch.
     *
     * Note, the `nextEpochState` comes from last epoch and not required to validate.
     */
    function initialize(
        address _controller,
        address _mptVerify,
        Types.LedgerInfoWithSignatures memory ledgerInfo,
        Types.BlockHeader memory header
    ) external override initializer {
        require(_controller != address(0), "invalid controller address");
        require(_mptVerify != address(0), "invalid mptVerify address");

        _changeAdmin(_controller);
        mptVerify = _mptVerify;

        require(ledgerInfo.epoch > 0, "invalid epoch");
        require(header.height > DEFER_EXECUTION_BLOCKS, "block number too small");
        require(header.height == ledgerInfo.pivot.height, "block height mismatch");
        require(Types.computeBlockHash(header) == ledgerInfo.pivot.blockHash, "block hash mismatch");

        // init client state
        _state.epoch = ledgerInfo.epoch;
        _state.round = ledgerInfo.round;
        _state.earliestBlockNumber = header.height;
        _state.finalizedBlockNumber = header.height;
        _state.maxBlocks = 86400 * 7;   // about one week

        // init committee
        require(ledgerInfo.nextEpochState.epoch == ledgerInfo.epoch, "invalid committee epoch");
        Types.updateCommittee(_committee, ledgerInfo.nextEpochState);

        if (!Types.isEmptyBlock(header)) {
            deferredReceiptsRoots[header.height] = header.deferredReceiptsRoot;
            _state.blocks = 1;
        }
    }

    modifier onlyInitialized() {
        require(_getInitializedVersion() > 0, "uninitialized");
        _;
    }

    function setMaxBlocks(uint256 val) external onlyOwner {
        _state.maxBlocks = val;
    }

    // relay pos block
    function updateLightClient(Types.LedgerInfoWithSignatures memory ledgerInfo) external override onlyInitialized whenNotPaused {
        // ensure previous pow blocks already fully relayed
        require(_state.relayBlockEndNumber == 0, "pow blocks not relayed yet");

        require(ledgerInfo.epoch == _state.epoch, "epoch mismatch");
        require(ledgerInfo.round > _state.round, "round mismatch");

        Types.validateBLS(_committee, ledgerInfo);

        if (ledgerInfo.nextEpochState.epoch == 0) {
            _state.round = ledgerInfo.round;
        } else {
            require(ledgerInfo.nextEpochState.epoch == _state.epoch + 1, "invalid epoch for the next committee");
            _state.epoch = ledgerInfo.nextEpochState.epoch;
            _state.round = 0; // indicate to relay pos block in next epoch
            Types.updateCommittee(_committee, ledgerInfo.nextEpochState);
        }

        // in case that pow block may not generate for a long time
        if (ledgerInfo.pivot.height > _state.finalizedBlockNumber) {
            _state.relayBlockStartNumber = _state.finalizedBlockNumber + 1;
            _state.relayBlockEndNumber = ledgerInfo.pivot.height;
            _state.relayBlockEndHash = ledgerInfo.pivot.blockHash;
            _state.finalizedBlockNumber = ledgerInfo.pivot.height;
        }

        emit UpdateLightClient(msg.sender, ledgerInfo.epoch, ledgerInfo.round);
    }

    // relay pow blocks
    function updateBlockHeader(Types.BlockHeader[] memory headers) external override onlyInitialized whenNotPaused {
        require(_state.relayBlockEndNumber != 0, "no pow block to relay");

        require(headers.length > 0, "empty block headers");
        require(headers.length <= _state.relayBlockEndNumber - _state.relayBlockStartNumber + 1, "too many block headers");

        // relay in reverse order
        uint256 expectedBlockNumber = _state.relayBlockEndNumber;
        bytes32 expectedBlockHash = _state.relayBlockEndHash;
        uint256 nonEmptyBlocks = 0;
        for (uint256 i = 0; i < headers.length; i++) {
            uint256 index = headers.length - 1 - i;
            require(headers[index].height == expectedBlockNumber, "block number mismatch");
            require(Types.computeBlockHash(headers[index]) == expectedBlockHash, "block hash mismatch");

            if (!Types.isEmptyBlock(headers[index])) {
                deferredReceiptsRoots[expectedBlockNumber] = headers[index].deferredReceiptsRoot;
                nonEmptyBlocks++;
            }

            expectedBlockNumber--;
            expectedBlockHash = headers[index].parentHash;
        }

        if (nonEmptyBlocks > 0) {
            _state.blocks += nonEmptyBlocks;
        }

        // update relay state
        if (expectedBlockNumber < _state.relayBlockStartNumber) {
            // completed to relay pow blocks
            _state.relayBlockEndNumber = 0;
        } else {
            // partial pow blocks relayed
            _state.relayBlockEndNumber = expectedBlockNumber;
            _state.relayBlockEndHash = expectedBlockHash;
        }

        emit UpdateBlockHeader(msg.sender, headers[0].height, headers[headers.length - 1].height);
    }

    // garbage collect pow blocks
    function removeBlockHeader(uint256 limit) external override {
        require(limit > 0, "limit is zero");

        if (_state.blocks <= _state.maxBlocks) {
            return;
        }

        uint256 numRemoved = _state.blocks - _state.maxBlocks;
        if (numRemoved > limit) {
            numRemoved = limit;
        }

        uint256 earliest = _state.earliestBlockNumber;
        uint256 nonEmptyBlocks = 0;
        for (uint256 i = earliest; i < earliest + numRemoved; i++) {
            if (deferredReceiptsRoots[i] != bytes32(0)) {
                nonEmptyBlocks++;
                delete deferredReceiptsRoots[i];
            }
        }

        if (nonEmptyBlocks > 0) {
            _state.blocks -= nonEmptyBlocks;
        }

        _state.earliestBlockNumber = earliest + numRemoved;
    }

    function verifyReceiptProof(Types.ReceiptProof memory proof) public view override returns (bool success, Types.TxLog[] memory logs) {
        bytes32 root = deferredReceiptsRoots[proof.epochNumber + DEFER_EXECUTION_BLOCKS];
        require(root != bytes32(0), "epoch number not verifiable");

        success = Provable(mptVerify).proveReceipt(
            root,
            proof.blockIndex,
            proof.blockProof,
            proof.receiptsRoot,
            proof.index,
            proof.receipt,
            proof.receiptProof
        );

        if (success) {
            logs = proof.receipt.logs;
        }
    }

    function verifyProofData(bytes memory receiptProof) external view override returns (
        bool success, string memory message, bytes memory rlpLogs
    ) {
        Types.ReceiptProof memory proof = abi.decode(receiptProof, (Types.ReceiptProof));

        Types.TxLog[] memory logs;
        (success, logs) = verifyReceiptProof(proof);

        if (success) {
            rlpLogs = Types.encodeLogs(logs);
        } else {
            message = "failed to verify mpt";
        }
    }

    function clientState() external view override returns(ClientState memory) {
        return _state;
    }

    function verifiableHeaderRange() external view override returns (uint256, uint256) {
        uint256 latest = _state.relayBlockEndNumber == 0 ? _state.finalizedBlockNumber : _state.relayBlockStartNumber - 1;
        return (_state.earliestBlockNumber - DEFER_EXECUTION_BLOCKS, latest - DEFER_EXECUTION_BLOCKS);
    }

    /** common code copied from other light nodes ********************/
    modifier onlyOwner() {
        require(msg.sender == _getAdmin(), "lightnode :: only admin");
        _;
    }

    function togglePause(bool flag) external onlyOwner returns (bool) {
        if (flag) {
            _pause();
        } else {
            _unpause();
        }

        return true;
    }

    /** UUPS *********************************************************/
    function _authorizeUpgrade(address) internal view override {
        require(msg.sender == _getAdmin(), "LightNode: only Admin can upgrade");
    }

    function changeAdmin(address _admin) public onlyOwner {
        require(_admin != address(0), "zero address");

        _changeAdmin(_admin);
    }

    function getAdmin() external view returns (address) {
        return _getAdmin();
    }

    function getImplementation() external view returns (address) {
        return _getImplementation();
    }
}
