# PledgeVerify — Charitable Pledge Verification via Proof of Impact

> **Donors pledge funds to verified recipients who prove their cause.**
> Recipients submit proof of impact, and validators verify proof quality under consensus.
> Funds release only when validators agree on proof validity.

[![GenLayer](https://img.shields.io/badge/Built%20on-GenLayer-6366f1?style=for-the-badge&logo=genlayer)](https://genlayer.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Equivalence](https://img.shields.io/badge/Equivalence%20Principle-OK-16a34a?style=for-the-badge)](https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle)
[![Tests](https://img.shields.io/badge/tests-14%20passed-16a34a?style=for-the-badge)](https://github.com/)

---

## Table of Contents

- [How it works](#how-it-works)
- [Consensus design](#consensus-design)
- [Reusable patterns](#reusable-patterns)
- [Security & audit](#security--audit)
- [Local lint & test](#local-lint--test)
- [Deployed contract (proof on explorer)](#deployed-contract-proof-on-explorer)
- [Extension ideas](#extension-ideas)

---

## How it works

1. Recipient registers identity by signing a message with their wallet (EIP-191).
2. Donor creates a pledge to a registered recipient with a purpose, amount, and deadline.
3. Recipient submits proof of impact (URL + description) before the deadline.
4. Anyone triggers verification for a pledge with submitted proof.
5. Under consensus, validators independently score proof quality against the stated purpose.
6. If validators agree and score meets threshold, funds are released.
7. If proof is insufficient or deadline passed, pledge is rejected.

---

## Consensus design

PledgeVerify uses `run_nondet_unsafe` with the Equivalence Principle:
- **Leader**: scores proof of impact via LLM evaluation against pledge purpose.
- **Validator**: independently scores the same proof and compares `(verified, proof_score)` decision fields.
- Consensus requires agreement on both fields. Mismatches trigger rotation.
- Error classification: `[EXPECTED]` for deterministic errors (exact match), `[TRANSIENT]` for network errors (agree if both), `[LLM]` for LLM errors (always disagree, force rotation).

---

## Reusable patterns

PledgeVerify establishes patterns that can be reused in other contracts:

- **EIP-191 signature verification**: `_signer_of()` + `_ecrecover()` — pure-Python secp256k1 ecrecover. Drop-in pattern for wallet authentication.
- **Conditional fund release**: pledge status machine (pending → proof_submitted → verified/rejected) with consensus gate.
- **Proof-of-impact scoring**: LLM evaluation of proof quality vs. stated purpose in consensus loop.
- **Donor-recipient relationship model**: pledges link donors to registered recipients.
- **Quality scoring in consensus**: not just pass/fail but numeric score comparison for validator agreement.
- **Consensus via `run_nondet_unsafe`**: Leader + Validator with `(verified, score)` decision field comparison.

---

## Security & audit

- **Signature verification**: registration and proof submission require EIP-191 signatures verified on-chain via pure-Python secp256k1 ecrecover.
- **Proof access control**: only the recipient can submit proof for their pledge.
- **SSRF blocklist**: proof URL validation blocks localhost, private networks, cloud metadata.
- **AST sandbox**: proof scoring uses LLM with structured JSON output only.
- **Pledge status machine**: verified transition requires consensus; cannot release without validator agreement.
- **Input validation**: purpose length limits, amount must be positive, deadline must be in future, URL format validated.

---

## Local lint & test

```bash
# Run tests
pytest tests/ -v

# Run linter
 genvm-lint check contracts/pledge_verify.py
```

14 GenVM direct-mode tests pass. Lint passes. Validate fails due to known SDK bug (missing runner tar). E2E test passes on studionet (register_recipient, get_recipient_pledges). Deployed to studionet.

---

## Deployed contract (proof on explorer)

[![Explore](https://img.shields.io/badge/Explore-Studionet-6366f1?style=for-the-badge)](https://genlayer-explorer.vercel.app)

**Address:** `0xa67323a35F332f604E9c0EB31CF8a0cB5997a336`
**Chain:** Studionet (Genlayer Studio Network)
**Deployer:** `0x689759bb926E032EAfb1eE986eD7A98C1496ec1c`
**Tx:** `0xbaf911bf5902aaa68f947c5c2992a0c9455c5835a2b661975f4438691f41bed3`
**Status:** Deployed and tested on studionet. E2E test passes (register_recipient, get_recipient_pledges). 14/14 direct-mode tests pass. All functions operational: register_recipient, create_pledge, submit_proof, verify_pledge, views.

---

## Extension ideas

- Multi-signature pledge approval (require M of N validators)
- Escrow with milestone-based releases
- Impact score staking (validators stake to vouch for recipients)
- Cross-contract pledge integration with other verification systems
