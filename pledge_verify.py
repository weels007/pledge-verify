# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""PledgeVerify — Charitable Pledge Verification via Proof of Impact

> Donors pledge funds to verified recipients who prove their cause.
> Validators independently verify proof quality under consensus.
> Funds release only when validators agree on proof validity.

Unique patterns:
  1. Conditional fund release after consensus
  2. Proof-of-impact verification with SSRF blocklist
  3. Donor-recipient relationship model
  4. Quality scoring in consensus (not just pass/fail)
"""

import json
import re
from datetime import datetime, timezone
from dataclasses import dataclass

from genlayer import *
from genlayer.py.keccak import Keccak256

MIN_PROOF_CHARS = 20
MAX_PROOF_CHARS = 2000
MAX_PURPOSE_CHARS = 200
MAX_DESCRIPTION_CHARS = 500
MAX_URL_CHARS = 2048
MIN_SCORE = 60

ERROR_LLM = "[LLM] "
ERROR_EXTERNAL = "[EXTERNAL] "
ERROR_TRANSIENT = "[TRANSIENT] "
ERROR_EXPECTED = "[EXPECTED] "


def _now_ts() -> int:
    try:
        dt = datetime.now(timezone.utc)
        return int(dt.timestamp())
    except Exception:
        pass
    try:
        raw = gl.message_raw["datetime"]
        if not raw:
            return 0
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return 0


def _addr_hex(addr) -> str:
    if hasattr(addr, "as_hex"):
        return str(addr.as_hex).lower().replace("0x", "")
    if hasattr(addr, "as_bytes"):
        return bytes(addr.as_bytes).hex().lower()
    if hasattr(addr, "hex"):
        return addr.hex().lower()
    if hasattr(addr, "__bytes__"):
        return bytes(addr).hex().lower()
    return str(addr).lower().replace("0x", "")


def _addr_eq(a, b) -> bool:
    return _addr_hex(a) == _addr_hex(b)


def _secp_inv(a: int, m: int) -> int:
    return pow(a, m - 2, m)


def _secp_add(p, q):
    _SECP256K1_P = 2**256 - 2**32 - 977
    _SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    _SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    _SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _SECP256K1_P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0]) * _secp_inv(2 * p[1], _SECP256K1_P) % _SECP256K1_P
    else:
        lam = (q[1] - p[1]) * _secp_inv(q[0] - p[0], _SECP256K1_P) % _SECP256K1_P
    x = (lam * lam - p[0] - q[0]) % _SECP256K1_P
    y = (lam * (p[0] - x) - p[1]) % _SECP256K1_P
    return (x, y)


def _secp_mul(k: int, pt):
    if k == 0 or pt is None:
        return None
    if k < 0:
        return _secp_mul(-k, (pt[0], (-pt[1]) % _SECP256K1_P))
    result = None
    while k:
        if k & 1:
            result = _secp_add(result, pt)
        pt = _secp_add(pt, pt)
        k >>= 1
    return result


_SECP256K1_P = 2**256 - 2**32 - 977
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _keccak256(data) -> bytes:
    return Keccak256(data).digest()


def _eip191_digest(message: str) -> bytes:
    raw = message.encode("utf-8")
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(raw)).encode("ascii")
    return _keccak256(prefix + raw)


def _ecrecover(msg_hash: bytes, r: int, s: int, v: int):
    try:
        recid = (v - 27) & 3
        z = int.from_bytes(msg_hash, "big")
        x = r + (recid >> 1) * _SECP256K1_N
        if x >= _SECP256K1_P:
            return None
        y2 = (pow(x, 3, _SECP256K1_P) + 7) % _SECP256K1_P
        y = pow(y2, (_SECP256K1_P + 1) // 4, _SECP256K1_P)
        if (y & 1) != (recid & 1):
            y = _SECP256K1_P - y
        R = (x, y)
        rinv = _secp_inv(r, _SECP256K1_N)
        sR = _secp_mul(s, R)
        zG = _secp_mul(z % _SECP256K1_N, (_SECP256K1_GX, _SECP256K1_GY))
        neg_zG = (zG[0], (-zG[1]) % _SECP256K1_P)
        Q = _secp_mul(rinv, _secp_add(sR, neg_zG))
        if Q is None:
            return None
        if Q[0] >= _SECP256K1_P or Q[1] >= _SECP256K1_P:
            return None
        pub = bytes([4]) + Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big")
        return "0x" + _keccak256(pub[1:])[12:].hex()
    except Exception:
        return None


def _signer_of(sign_msg: str, signature: str):
    if not signature or not signature.startswith("0x"):
        return None
    try:
        sig_bytes = bytes.fromhex(signature[2:])
    except ValueError:
        return None
    if len(sig_bytes) != 65:
        return None
    r = int.from_bytes(sig_bytes[:32], "big")
    s = int.from_bytes(sig_bytes[32:64], "big")
    v = sig_bytes[64]
    msg_hash = _eip191_digest(sign_msg)
    recovered = _ecrecover(msg_hash, r, s, v)
    return recovered.lower().replace("0x", "") if recovered else None


_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_BLOCKED_HOST_RE = re.compile(r"(localhost|127\.0\.0\.1|0\.0\.0\.0|\.internal|\.local|metadata\.googleapis|169\.254\.)", re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _validate_url(url: str) -> bool:
    if not url or len(url) > MAX_URL_CHARS:
        return False
    if not _URL_RE.match(url):
        return False
    if _CONTROL_RE.search(url):
        return False
    if _BLOCKED_HOST_RE.search(url):
        return False
    return True


def _score_proof(purpose: str, proof_content: str) -> int:
    prompt = f"""Score this proof of impact for a charitable pledge.

Pledge purpose: {purpose}

Proof content: {proof_content}

Score 0-100 based on:
- Demonstrates real impact (0-30)
- Relevant to stated purpose (0-30)
- Specific and verifiable (0-20)
- Not vague or generic (0-20)

Return ONLY JSON: {{"score": 0-100}}"""
    try:
        out = gl.nondet.exec_prompt(prompt, response_format="json")
    except Exception:
        raise gl.vm.UserError(ERROR_LLM + "Proof scoring failed")
    if not isinstance(out, dict) or "score" not in out:
        raise gl.vm.UserError(ERROR_LLM + "Invalid proof scoring")
    try:
        return max(0, min(100, int(out["score"])))
    except (ValueError, TypeError):
        raise gl.vm.UserError(ERROR_LLM + "Invalid score")


@allow_storage
@dataclass
class Recipient:
    address: Address
    registered_ts: u256
    pledge_count: u256


@allow_storage
@dataclass
class Pledge:
    pledge_id: str
    donor: Address
    recipient: Address
    amount: u256
    purpose: str
    deadline: u256
    status: str
    released: bool
    proof_score: u256
    created_ts: u256


@allow_storage
@dataclass
class Proof:
    pledge_id: str
    submitter: Address
    url: str
    description: str
    content_snippet: str
    submitted_ts: u256


class PledgeVerify(gl.Contract):
    recipients: TreeMap[str, Recipient]
    pledges: TreeMap[str, Pledge]
    proofs: TreeMap[str, Proof]
    pledge_seq: TreeMap[str, u256]

    def __init__(self):
        pass

    @gl.public.write
    def register_recipient(self, signature: str) -> None:
        if not signature or len(signature) > 200 or not signature.startswith("0x"):
            raise gl.vm.UserError("signature must be 0x-prefixed hex string")
        sign_msg = "PledgeVerify:register"
        signer = _signer_of(sign_msg, signature)
        if signer is None:
            raise gl.vm.UserError("invalid signature")
        addr_hex = signer.lower().replace("0x", "")
        if addr_hex in self.recipients:
            raise gl.vm.UserError("already registered")
        sender = gl.message.sender_address
        ts = _now_ts()
        self.recipients[addr_hex] = Recipient(address=sender, registered_ts=ts, pledge_count=0)

    @gl.public.write
    def create_pledge(self, recipient: Address, amount: int, purpose: str, deadline_ts: int) -> str:
        if not purpose or len(purpose) > MAX_PURPOSE_CHARS:
            raise gl.vm.UserError(f"purpose must be 1-{MAX_PURPOSE_CHARS} characters")
        if amount <= 0:
            raise gl.vm.UserError("amount must be positive")
        if deadline_ts <= _now_ts():
            raise gl.vm.UserError("deadline must be in the future")
        if not hasattr(recipient, "as_bytes"):
            recipient = Address(recipient)
        recipient_hex = _addr_hex(recipient)
        if recipient_hex not in self.recipients:
            raise gl.vm.UserError("recipient not registered")
        sender = gl.message.sender_address
        seq = int(self.pledge_seq.get(recipient_hex, 0))
        pledge_id = f"{recipient_hex}:{seq}"
        ts = _now_ts()
        self.pledges[pledge_id] = Pledge(
            pledge_id=pledge_id,
            donor=sender,
            recipient=recipient,
            amount=amount,
            purpose=purpose,
            deadline=deadline_ts,
            status="pending",
            released=False,
            proof_score=0,
            created_ts=ts,
        )
        self.pledge_seq[recipient_hex] = seq + 1
        rec = self.recipients[recipient_hex]
        rec.pledge_count = rec.pledge_count + 1
        self.recipients[recipient_hex] = rec
        return pledge_id

    @gl.public.write
    def submit_proof(self, pledge_id: str, url: str, description: str, signature: str) -> None:
        if pledge_id not in self.pledges:
            raise gl.vm.UserError("pledge not found")
        pledge = self.pledges[pledge_id]
        if pledge.status != "pending":
            raise gl.vm.UserError("pledge not pending")
        if not _validate_url(url):
            raise gl.vm.UserError("invalid url")
        if not description or len(description) > MAX_DESCRIPTION_CHARS:
            raise gl.vm.UserError("description must be 1-500 characters")
        recipient_hex = _addr_hex(pledge.recipient)
        if recipient_hex not in self.recipients:
            raise gl.vm.UserError("recipient not registered")
        sender = gl.message.sender_address
        if not _addr_eq(sender, pledge.recipient):
            raise gl.vm.UserError("only recipient can submit proof")
        proof_key = f"{pledge_id}:proof"
        if proof_key in self.proofs:
            raise gl.vm.UserError("proof already submitted")
        sign_msg = f"PledgeVerify:proof:{pledge_id}:{url}:{description[:50]}"
        signer = _signer_of(sign_msg, signature)
        if signer is None or signer.lower() != recipient_hex:
            raise gl.vm.UserError("invalid proof signature")
        ts = _now_ts()
        self.proofs[proof_key] = Proof(
            pledge_id=pledge_id,
            submitter=sender,
            url=url,
            description=description,
            content_snippet="",
            submitted_ts=ts,
        )
        pledge.status = "proof_submitted"
        self.pledges[pledge_id] = pledge

    @gl.public.write
    def verify_pledge(self, pledge_id: str) -> None:
        if pledge_id not in self.pledges:
            raise gl.vm.UserError("pledge not found")
        pledge = self.pledges[pledge_id]
        if pledge.status != "proof_submitted":
            raise gl.vm.UserError("proof not submitted")
        proof_key = f"{pledge_id}:proof"
        if proof_key not in self.proofs:
            raise gl.vm.UserError("proof not found")
        proof = self.proofs[proof_key]
        result = _run_pledge_consensus(pledge_id, pledge, proof)
        ts = _now_ts()
        pledge.proof_score = result["proof_score"]
        if result["verified"] and _now_ts() <= int(pledge.deadline):
            pledge.status = "verified"
            pledge.released = True
        else:
            pledge.status = "rejected"
            pledge.released = False
        self.pledges[pledge_id] = pledge

    @gl.public.view
    def get_pledge(self, pledge_id: str) -> dict:
        if pledge_id not in self.pledges:
            return {}
        p = self.pledges[pledge_id]
        return {
            "pledge_id": p.pledge_id,
            "donor": _addr_hex(p.donor),
            "recipient": _addr_hex(p.recipient),
            "amount": p.amount,
            "purpose": p.purpose,
            "deadline": p.deadline,
            "status": p.status,
            "released": p.released,
            "proof_score": p.proof_score,
            "created_ts": p.created_ts,
        }

    @gl.public.view
    def get_proof(self, pledge_id: str) -> dict:
        key = f"{pledge_id}:proof"
        if key not in self.proofs:
            return {}
        p = self.proofs[key]
        return {
            "pledge_id": p.pledge_id,
            "submitter": _addr_hex(p.submitter),
            "url": p.url,
            "description": p.description,
            "submitted_ts": p.submitted_ts,
        }

    @gl.public.view
    def get_recipient_pledges(self, recipient: Address) -> list:
        addr_hex = _addr_hex(recipient)
        pledges = []
        for k, p in self.pledges.items():
            if _addr_hex(p.recipient) == addr_hex:
                pledges.append({
                    "pledge_id": p.pledge_id,
                    "donor": _addr_hex(p.donor),
                    "amount": p.amount,
                    "purpose": p.purpose,
                    "status": p.status,
                    "released": p.released,
                    "proof_score": p.proof_score,
                })
        return pledges


def _run_pledge_consensus(pledge_id: str, pledge: Pledge, proof: Proof) -> dict:
    def leader_fn():
        purpose = pledge.purpose
        content = f"url: {proof.url}\ndescription: {proof.description}"
        score = _score_proof(purpose, content)
        verified = score >= MIN_SCORE
        return {
            "verified": verified,
            "proof_score": score,
        }

    def _decision_fields(data: dict) -> tuple:
        return (data.get("verified"), int(data.get("proof_score", 0)))

    def validator_fn(leader_result):
        if not isinstance(leader_result, gl.vm.Return):
            return _reproduce_leader_error(leader_result, leader_fn)
        leader_data = leader_result.calldata
        if not isinstance(leader_data, dict):
            return False
        my = leader_fn()
        return _decision_fields(my) == _decision_fields(leader_data)

    return gl.vm.run_nondet_unsafe(leader_fn, validator_fn)


def _reproduce_leader_error(leader_result, leader_fn) -> bool:
    leader_msg = getattr(leader_result, "message", "") or ""
    try:
        leader_fn()
        return False
    except gl.vm.UserError as e:
        v_msg = e.message if hasattr(e, "message") else str(e)
        if v_msg.startswith(ERROR_EXPECTED) or v_msg.startswith(ERROR_EXTERNAL):
            return v_msg == leader_msg
        if v_msg.startswith(ERROR_TRANSIENT) and leader_msg.startswith(ERROR_TRANSIENT):
            return True
        return False
    except Exception:
        return False
