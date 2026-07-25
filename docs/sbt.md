# SBT Contract

`contracts/sbt` implements soulbound tokens (SBTs): non-transferable, admin-issued
badges bound to a Stellar address. It has no `transfer` function — the only way a
token's holder ever changes is a successful recovery. On top of the core
mint/holder model it implements four features tracked as issues #48-#51.

## Core Model

- `initialize(env, admin)` — sets the issuer authority.
- `mint_sbt(env, owner, metadata) -> u64` — admin-only issuance, returns `sbt_id`.
- `get_holder`, `get_metadata`, `get_schema_version` — read accessors.

## #48 — Identity Linkage (`link_sbt_to_identity`)

SBT ownership is pseudonymous by default. Optional linking associates a token
with a real-world identity for use cases like KYC, without putting identity
data or proofs on-chain.

**Privacy guarantee**: the contract never stores raw identity data or the
proof used to establish it — only two hashes:

1. An attestor (a registered KYC/identity oracle) verifies an individual
   off-chain and calls `register_identity_attestation(env, attestor,
   identity_hash, proof)`. The contract stores `sha256(proof)` keyed by
   `(identity_hash, sha256(proof))` — a commitment, not the proof itself.
2. The SBT owner later reveals the same `proof` to
   `link_sbt_to_identity(env, sbt_id, identity_hash, proof)`. The contract
   re-hashes it and checks it matches a commitment from a *currently
   trusted* attestor, then stores only `identity_hash` against the SBT.

This means: the contract can attest "this SBT is linked to an identity a
trusted attestor vouched for," while `identity_hash` reveals nothing about
the underlying identity on its own (it's presumed to be a salted hash the
individual controls), and the proof/PII never touch chain state at all.

`unlink_sbt_identity`, `is_identity_linked`, and `get_linked_identity_hash`
round out the lifecycle. Revoking an attestor (`remove_attestor`) does not
delete existing links, but blocks new links from being redeemed against that
attestor's outstanding commitments — mirroring `zk_verifier`'s oracle
revocation semantics.

## Error Codes

| Code | Name | Description |
|------|------|--------------|
| 1 | AlreadyInitialized | Contract already initialized |
| 2 | NotInitialized | Contract not yet initialized |
| 3 | NotAttestor | Caller is not a registered identity attestor |
| 4 | SbtNotFound | No SBT exists with the given id |
| 5 | EmptyMetadata | Metadata bytes were empty |
| 6 | MetadataTooLarge | Metadata exceeds `MAX_METADATA_SIZE` |
| 7 | EmptyProof | Proof bytes were empty |
| 8 | ProofTooLarge | Proof exceeds `MAX_IDENTITY_PROOF_SIZE` |
| 9 | IdentityAlreadyLinked | SBT already has a linked identity |
| 10 | NoIdentityLinked | SBT has no linked identity to unlink |
| 11 | AttestationNotFound | No matching, currently-trusted attestation |
