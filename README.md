# PledgeVerify — Charitable Pledge Verification via Proof of Impact

> **Donors pledge funds to verified recipients who prove their cause.**
> Recipients submit proof of impact, and validators verify proof quality under consensus.
> Funds release only when validators agree on proof validity.

[![GenLayer](https://img.shields.io/badge/Built%20on-GenLayer-6366f1?style=for-the-badge&logo=genlayer)](https://genlayer.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Equivalence](https://img.shields.io/badge/Equivalence%20Principle-OK-16a34a?style=for-the-badge)](https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle)
[![Tests](https://img.shields.io/badge/tests-23%20passed-16a34a?style=for-the-badge)](https://github.com/)

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
- **Leader**: fetches the actual evidence from the proof URL via `gl.nondet.web.get()`, then scores the fetched content + description against the pledge purpose via LLM.
- **Validator**: independently fetches the same URL and re-scores the retrieved evidence, then compares `(verified, proof_score)` decision fields.
- Both leader and validators assess retrieved evidence — never just the URL string or description.
- Error classification: `[EXPECTED]` for deterministic errors (exact match), `[EXTERNAL]` for 4xx responses (exact match), `[TRANSIENT]` for 5xx/network errors (agree if both), `[LLM]` for LLM errors (always disagree, force rotation).

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

- **Signature verification**: registration and proof submission require EIP-191 signatures verified on-chain via pure-Python secp256k1 ecrecover; `register_recipient` additionally requires the recovered signer to equal the transaction sender.
- **Proof access control**: only the recipient can submit proof for their pledge.
- **SSRF policy**: proof URLs are parsed with `urllib.parse` and host-checked with `ipaddress` — blocks private/loopback/link-local/reserved/multicast IPv4+IPv6 (incl. CGNAT), decimal/hex/octal numeric IP literals, userinfo, control characters, backslashes, and `.local`/`.internal`/`.localhost`/`.nip.io`/`.sslip.io`/`metadata.google` hosts.
- **Redirect validation**: `_fetch_proof_evidence` follows at most 5 redirects, resolving relative `Location` headers and re-validating every hop against the same SSRF policy.
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

23 GenVM direct-mode tests pass. Lint passes. Validate passes. E2E test passes on studionet (register_recipient, get_recipient_pledges). Deployed to studionet.

---

## Deployed contract (proof on explorer)

[![Explore](https://img.shields.io/badge/Explore-Studionet-6366f1?style=for-the-badge)](https://genlayer-explorer.vercel.app)

**Address:** `0xed2592E7f97fbC693c76Fe35B2314fF7d405fc67`
**Chain:** Studionet (Genlayer Studio Network)
**Deployer:** `0x689759bb926E032EAfb1eE986eD7A98C1496ec1c`
**Tx:** `0x77db809a72161693a54d79ff84e37297304afc16c9c52ea3625b52af9b5903d9`
**Status:** Deployed and tested on studionet. E2E test passes (register_recipient, get_recipient_pledges). 23/23 direct-mode tests pass. All functions operational: register_recipient, create_pledge, submit_proof, verify_pledge, views.

---

## Extension ideas

- Multi-signature pledge approval (require M of N validators)
- Escrow with milestone-based releases
- Impact score staking (validators stake to vouch for recipients)
- Cross-contract pledge integration with other verification systems
