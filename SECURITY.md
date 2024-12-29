# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the Privacy Pool Implementation, please follow these steps:

1. **Do Not** create a public issue
2. Send details privately to the maintainers
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fixes (if any)

## Security Considerations

### Smart Contract Security

1. **Access Control**

   - Owner-only administrative functions
   - Proper authorization checks
   - Role-based access control

2. **Input Validation**

   - Amount limits
   - Hash validation
   - Nullifier checks

3. **Privacy Protection**

   - Zero-knowledge proof verification
   - Merkle tree implementation
   - Commitment scheme

4. **Asset Security**
   - Double-spend prevention
   - Token allowlist
   - Transfer safety

### Known Security Measures

1. Minimum deposit amounts prevent dust attacks
2. Maximum deposit limits protect against large-scale attacks
3. Nullifier tracking prevents double-spending
4. Zero-knowledge proofs ensure transaction privacy
5. Owner-controlled token allowlist prevents unauthorized tokens

## Security Best Practices

1. Always verify transaction recipients
2. Use secure random number generation
3. Validate all inputs
4. Monitor for suspicious activity
5. Keep dependencies updated
6. Regular security audits

## Version Support

Only the latest version receives security updates. Users should always upgrade to the latest version.
