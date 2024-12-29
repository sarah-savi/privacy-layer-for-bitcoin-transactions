# Secure Privacy Pool Implementation

A security-hardened privacy-preserving pool implementation that enables confidential Bitcoin transactions using zero-knowledge proofs and Merkle trees.

## Overview

This smart contract implements a privacy pool that allows users to make confidential transactions on the Bitcoin network. It uses zero-knowledge proofs and Merkle trees to ensure transaction privacy while maintaining security.

### Key Features

- Zero-knowledge proof verification for private transactions
- Merkle tree implementation for commitment storage
- SIP-010 token standard compliance
- Deposit and withdrawal functionality
- Nullifier tracking to prevent double-spending
- Configurable deposit limits
- Owner-controlled token allowlist

## Architecture

The contract consists of several key components:

1. **Merkle Tree**: A 20-level tree storing transaction commitments
2. **Deposit System**: Handles user deposits and commitment storage
3. **Withdrawal System**: Processes withdrawals with zero-knowledge proof verification
4. **Token Management**: Supports SIP-010 compliant tokens
5. **Security Controls**: Includes ownership management and authorization checks

## Usage

### Depositing Funds

```clarity
(contract-call? .privacy-pool deposit
    commitment     ;; (buff 32) - Commitment hash
    amount        ;; uint - Amount to deposit
    token         ;; <ft-trait> - Token contract
)
```

### Withdrawing Funds

```clarity
(contract-call? .privacy-pool withdraw
    nullifier     ;; (buff 32) - Nullifier hash
    root          ;; (buff 32) - Merkle root
    proof         ;; (list 20 (buff 32)) - Merkle proof
    recipient     ;; principal - Recipient address
    token         ;; <ft-trait> - Token contract
    amount        ;; uint - Amount to withdraw
)
```

## Security Considerations

- Minimum deposit amounts prevent dust attacks
- Maximum deposit limits protect against large-scale attacks
- Nullifier tracking prevents double-spending
- Zero-knowledge proofs ensure transaction privacy
- Owner-controlled token allowlist prevents unauthorized tokens

## Installation

1. Deploy the contract to your Stacks node
2. Initialize allowed token(s) using `set-allowed-token`
3. Users can begin making deposits and withdrawals

## Testing

Comprehensive test cases should cover:

1. Deposit functionality
2. Withdrawal verification
3. Merkle tree operations
4. Token management
5. Security controls
6. Error conditions

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and development process.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## Security

For security concerns, please review our [Security Policy](SECURITY.md).
