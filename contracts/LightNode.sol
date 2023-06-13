// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "./interface/ILightNode.sol";
import "./lib/Types.sol";
import "./Provable.sol";

contract LightNode is UUPSUpgradeable, Initializable, Pausable, ILightNode {

    address public mptVerify;

    ClientState private _state;
    Types.Committee private _committee;

    // pow block number => pow block hash
    mapping(uint256 => bytes32) public finalizedBlocks;

    /**
     * @dev Always initialize with the first pos block of any epoch.
     *
     * Note, the `nextEpochState` comes from last epoch and not required to validate.
     */
    function initialize(
        address _controller,
        address _mptVerify,
        Types.LedgerInfoWithSignatures memory ledgerInfo
    ) external override initializer {
        require(_controller != address(0), "invalid controller address");
        require(_mptVerify != address(0), "invalid mptVerify address");

        _changeAdmin(_controller);
        mptVerify = _mptVerify;

        require(ledgerInfo.epoch > 0, "invalid epoch");
        require(ledgerInfo.pivot.height > 0, "block number too small");

        // init client state
        _state.epoch = ledgerInfo.epoch;
        _state.round = ledgerInfo.round;
        _state.earliestBlockNumber = ledgerInfo.pivot.height;
        _state.finalizedBlockNumber = ledgerInfo.pivot.height;
        _state.blocks = 1;
        _state.maxBlocks = 3 * 1440 * 30; // about 1 month
        finalizedBlocks[ledgerInfo.pivot.height] = ledgerInfo.pivot.blockHash;

        // init committee
        require(ledgerInfo.nextEpochState.epoch == ledgerInfo.epoch, "invalid committee epoch");
        Types.updateCommittee(_committee, ledgerInfo.nextEpochState);
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
            _state.finalizedBlockNumber = ledgerInfo.pivot.height;
            _state.blocks++;
            finalizedBlocks[ledgerInfo.pivot.height] = ledgerInfo.pivot.blockHash;
        }

        emit UpdateLightClient(msg.sender, ledgerInfo.epoch, ledgerInfo.round, ledgerInfo.pivot.height);

        removeBlockHeader(1);
    }

    // relay pow blocks
    function updateBlockHeader(Types.BlockHeader[] memory headers) external override onlyInitialized whenNotPaused {
        Types.BlockHeader memory head = _validateHeaders(headers);

        if (finalizedBlocks[head.height] == bytes32(0)) {
            _state.blocks++;
            finalizedBlocks[head.height] = Types.computeBlockHash(head);
        }

        emit UpdateBlockHeader(msg.sender, headers[0].height, headers[headers.length - 1].height);

        removeBlockHeader(1);
    }

    function _validateHeaders(Types.BlockHeader[] memory headers) private view returns (Types.BlockHeader memory head) {
        require(headers.length > 0, "empty block headers");

        Types.BlockHeader memory tail = headers[headers.length - 1];
        uint256 expectedBlockNumber = tail.height;
        bytes32 expectedBlockHash = finalizedBlocks[tail.height];
        require(expectedBlockHash != bytes32(0), "tail block not found");
        for (uint256 i = 0; i < headers.length; i++) {
            // validate in reverse order
            uint256 index = headers.length - 1 - i;

            require(headers[index].height == expectedBlockNumber, "block number mismatch");
            require(Types.computeBlockHash(headers[index]) == expectedBlockHash, "block hash mismatch");

            expectedBlockNumber--;
            expectedBlockHash = headers[index].parentHash;
        }

        head = headers[0];
        require(head.height > _state.earliestBlockNumber, "block number too small");
    }

    function removeBlockHeader(uint256 limit) public override {
        require(limit > 0, "limit is zero");

        if (_state.blocks <= _state.maxBlocks) {
            return;
        }

        uint256 numRemoved = _state.blocks - _state.maxBlocks;
        if (numRemoved > limit) {
            numRemoved = limit;
        }

        uint256 earliest = _state.earliestBlockNumber;
        for (; numRemoved > 0; earliest++) {
            if (finalizedBlocks[earliest] != 0) {
                delete finalizedBlocks[earliest];
                numRemoved--;
            }
        }

        _state.blocks -= numRemoved;

        while (finalizedBlocks[earliest] == 0) {
            earliest++;
        }

        _state.earliestBlockNumber = earliest;
    }

    function verifyReceiptProof(Types.ReceiptProof memory proof) public view override returns (
        bool success, Types.TxLog[] memory logs
    ) {
        Types.BlockHeader memory head = _validateHeaders(proof.headers);

        success = Provable(mptVerify).proveReceipt(
            head.deferredReceiptsRoot,
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

        Types.BlockHeader memory head = _validateHeaders(proof.headers);

        // not sure why OutOfGas occurred if put below line in the end
        bytes memory encodedLogs = Types.encodeLogs(proof.receipt.logs);

        success = Provable(mptVerify).proveReceipt(
            head.deferredReceiptsRoot,
            proof.blockIndex,
            proof.blockProof,
            proof.receiptsRoot,
            proof.index,
            proof.receipt,
            proof.receiptProof
        );

        if (success) {
            rlpLogs = encodedLogs;
        } else {
            message = "failed to verify mpt";
        }
    }

    function clientState() external view override returns(ClientState memory) {
        return _state;
    }

    function verifiableHeaderRange() external view override returns (uint256, uint256) {
        return (_state.earliestBlockNumber, _state.finalizedBlockNumber);
    }

    function nearestPivot(uint256 height) external view override returns (uint256) {
        require(height >= _state.earliestBlockNumber, "block already pruned");
        require(height <= _state.finalizedBlockNumber, "block not finalized yet");

        while (finalizedBlocks[height] == 0) {
            height++;
        }

        return height;
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
