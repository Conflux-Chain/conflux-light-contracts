# Conflux Light Node Contracts

Conflux light node contracts are used to verify transactions or receipts on other blockchain in manner of zero-knowledge.

## Provable

[Provable](./contracts/Provable.sol) contract is an utility to verify MPT proof of Conflux network.

## Light Node

[Light node](./contracts/LightNode.sol) contract is deployed on any blockchain for Conflux transaction or receipt verification.

Firstly, light node contract should be initialized with any trusted PoS/PoW block. Then, Off-chain service is required to relay blocks periodically:

```solidity
function initialize(
    address _controller,
    address _mptVerify,
    Types.LedgerInfoWithSignatures memory ledgerInfo,
    Types.BlockHeader memory header
) external;

function updateLightClient(Types.LedgerInfoWithSignatures memory ledgerInfo) external;

function updateBlockHeader(Types.BlockHeader[] memory headers) external;
```

To avoid too many records persisted on chain, relayer could garbage collect stale blocks, e.g. 1 week ago.

```solidity
function removeBlockHeader(uint256 limit) external;
```

Once blocks relayed, transaction or receipt proof could be verified cryptographically:

```solidity
function verifyReceiptProof(Types.ReceiptProof memory proof) external view returns (bool success, Types.TxLog[] memory logs);

function verifyProofData(bytes memory receiptProof) external view returns (bool success, string memory message, bytes memory rlpLogs);
```

## Differences from Ethereum

1. **RLP Encoding**: encode `false` into `0x00` instead of `0x80`.
2. **MPT**: Only **branch node** and **leaf node** in Conflux MPT. Whereas, there is **extension node** in Ethereum.
