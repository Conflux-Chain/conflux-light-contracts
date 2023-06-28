# Conflux Light Node Contracts

Conflux light node contracts are used to verify transactions or receipts on other blockchain in manner of zero-knowledge.

## Provable

[Provable](./contracts/Provable.sol) contract is an utility to verify MPT proof of Conflux network.

## LegerInfo
[LedgerInfo](./contracts/LedgerInfo.sol) contract is an utility to verify BLS signatures of ledger info.

## Light Node

[LightNode](./contracts/LightNode.sol) contract is deployed on any blockchain for Conflux transaction or receipt verification. It could be deployed behind a [LightNodeProxy](./contracts/LightNodeProxy.sol).

Firstly, light node contract should be initialized with any trusted PoS/PoW block. Then, Off-chain service is required to relay **PoS blocks** periodically. However, PoW blocks relay is not mandatory, since receipt proof contains PoW blocks to prove on chain. You could relay as many as PoW blocks whenever the **gas fee** for receipt proof verification is higher than PoW blocks relay.

```solidity
function initialize(
    address _controller,
    address _ledgerInfoUtil,
    address _mptVerify,
    LedgerInfoLib.LedgerInfoWithSignatures memory ledgerInfo
) external;

function updateLightClient(LedgerInfoLib.LedgerInfoWithSignatures memory ledgerInfo) external;

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
2. **MPT**: Only `branch node` and `leaf node` in Conflux MPT. Whereas, there is `extension node` in Ethereum.
3. Conflux use **BLS12-381** algorithm for PoS blocks, but the `hash_to_curve` is different from Ethereum. For more details, please refer to the [implementation](./contracts/lib/BLS.sol).
