# PledgeVerify — Non-Custodial Pledge Attestation via Proof of Impact

> **Donors declare pledges to verified recipients; recipients prove their impact.**
> Recipients submit proof of impact, validators independently verify proof quality under consensus,
> and the contract issues an on-chain attestation verdict (verified / rejected).
>
> This contract is a **non-custodial attestation registry**: it never receives, holds, escrows, or
> transfers funds. `declared_amount` is the donor's declared off-chain pledge commitment, recorded
> for attestation only — funds move directly between donor and recipient outside the contract.

[![GenLayer](https://img.shields.io/badge/Built%20on-GenLayer-6366f1?style=for-the-badge&logo=genlayer)](https://genlayer.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Equivalence](https://img.shields.io/badge/Equivalence%20Principle-OK-16a34a?style=for-the-badge)](https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle)
[![Tests](https://img.shields.io/badge/tests-29%20passed-16a34a?style=for-the-badge)](https://github.com/)

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
2. Donor creates a pledge record for a registered recipient: purpose, `declared_amount` (the donor's off-chain commitment — no funds enter the contract), and deadline.
3. Recipient submits proof of impact (URL + description).
4. Anyone triggers attestation for a pledge with submitted proof.
5. Under consensus, validators independently fetch the evidence and score proof quality against the stated purpose.
6. The verdict is stored as an on-chain attestation: `verified` (score meets threshold) or `rejected`.

---

## Consensus design

PledgeVerify uses `run_nondet_unsafe` with the Equivalence Principle:
- **Leader**: fetches the actual evidence from the proof URL via `gl.nondet.web.get()`, then scores the fetched content + description against the pledge purpose via LLM.
- **Validator**: independently fetches the same URL and re-scores the retrieved evidence, then compares the decision fields: `verified` must match exactly, `proof_score` within an explicit ±10 tolerance (LLM scores vary across independent runs — exact equality causes `MAJORITY_DISAGREE`).
- Both leader and validators assess retrieved evidence — never just the URL string or description.
- Error classification: `[EXPECTED]` for deterministic errors (exact match), `[EXTERNAL]` for 4xx responses (exact match), `[TRANSIENT]` for 5xx/network errors (agree if both), `[LLM]` for LLM errors (always disagree, force rotation).

---

## Reusable patterns

PledgeVerify establishes patterns that can be reused in other contracts:

- **EIP-191 signature verification**: `_signer_of()` + `_ecrecover()` — pure-Python secp256k1 ecrecover. Drop-in pattern for wallet authentication.
- **Non-custodial attestation recording**: declared commitments recorded with explicit naming (`declared_amount`) and docstrings; no fund semantics implied.
- **Consensus-gated attestation status machine**: pledge status (pending → proof_submitted → verified/rejected); the verdict transition requires validator agreement.
- **Proof-of-impact scoring**: LLM evaluation of proof quality vs. stated purpose in consensus loop.
- **Donor-recipient relationship model**: pledges link donors to registered recipients.
- **Score tolerance in consensus**: exact decision-bit match + explicit numeric tolerance for LLM score variance.
- **Consensus via `run_nondet_unsafe`**: Leader + Validator with tolerant decision-field comparison.

---

## Security & audit

- **Signature verification**: registration and proof submission require EIP-191 signatures verified on-chain via pure-Python secp256k1 ecrecover; `register_recipient` additionally requires the recovered signer to equal the transaction sender.
- **Proof access control**: only the recipient can submit proof for their pledge.
- **SSRF policy**: proof URLs are parsed with `urllib.parse` and host-checked with `ipaddress` — blocks private/loopback/link-local/reserved/multicast IPv4+IPv6 (incl. CGNAT), decimal/hex/octal numeric IP literals, userinfo, control characters, backslashes, and `.local`/`.internal`/`.localhost`/`.nip.io`/`.sslip.io`/`metadata.google` hosts.
- **DNS resolution before fetch**: every hop's hostname is resolved via DNS-over-HTTPS (`dns.google/resolve`, A + AAAA) inside the consensus loop; if any resolved address is private/loopback/link-local/reserved, the fetch is rejected (`[EXTERNAL] resolved address is blocked`) before any request is sent to it — closing DNS-rebinding for domain names. NXDOMAIN raises `[EXTERNAL] host did not resolve`; resolver outages raise `[TRANSIENT]`.
- **Redirect validation**: `_fetch_proof_evidence` follows at most 5 redirects, resolving relative `Location` headers, re-validating the URL policy and re-resolving the hostname of every hop.
- **AST sandbox**: proof scoring uses LLM with structured JSON output only.
- **Attestation status machine**: the `verified` transition requires consensus — no verdict without validator agreement. The contract has no custody: it cannot and does not move funds.
- **Input validation**: purpose length limits, `declared_amount` must be positive, deadline must be in future, URL format validated.

---

## Local lint & test

```bash
# Run tests
pytest tests/ -v

# Run linter
genvm-lint check contracts/pledge_verify.py
```

29 GenVM direct-mode tests pass. Lint passes. Validate passes. E2E test passes on studionet (register_recipient, create_pledge, submit_proof, verify_pledge under real LLM+web consensus → MAJORITY_AGREE, final attestation state). Deployed to studionet.

---

## Deployed contract (proof on explorer)

[![Explore](https://img.shields.io/badge/Explore-Studionet-6366f1?style=for-the-badge)](https://genlayer-explorer.vercel.app)

**Address:** `0x78bD26dAA24c1F2Af9F4115724094562Df887f33`
**Chain:** Studionet (Genlayer Studio Network)
**Deployer:** `0x689759bb926E032EAfb1eE986eD7A98C1496ec1c`
**Tx:** `0x45249ca782e93258f776dd9bd968a0bb480150c40b97091209d27a0c5e34617b`
**Status:** Deployed and tested on studionet. Full E2E passes (register → pledge → proof → attestation under real consensus, MAJORITY_AGREE). 29/29 direct-mode tests pass. All functions operational: register_recipient, create_pledge, submit_proof, verify_pledge, views.

---

## Extension ideas

- Multi-signature attestation (require M of N attestations)
- Donor pledge registry aggregated across recipients
- Impact score staking (validators stake to vouch for recipients)
- Cross-contract pledge integration with other verification systems
