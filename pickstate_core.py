"""
PickState Protocol v0.2 — Core Data Structures

256-byte trust verification record for AI agent-to-agent communication.
Adapted from Pick database principles (1965): sparse, self-describing, hash-addressed.

Authors: Garrett (g8g8g8-cmcy) & Claude
License: CC0 1.0 Universal (Public Domain)
Date: April 11, 2026
"""

import hashlib
import struct
import time
import os
from dataclasses import dataclass, field
from typing import Optional, List, Tuple
from enum import IntEnum, IntFlag


# =============================================================================
# Constants
# =============================================================================

RECORD_SIZE = 256          # bytes — full PickState record
MINI_SIZE = 145            # bytes — high-frequency verification
EPOCH_INTERACTIONS = 1000  # interactions per epoch
EPOCH_DAYS = 30            # max days per epoch
TRUST_DECAY_DAYS = 30      # lose 1 trust point per this many inactive days


# =============================================================================
# Capability Bitfield (128-bit skill vector)
# =============================================================================

class CoreCap(IntFlag):
    """Bits 0-15: Core AI capabilities"""
    TEXT_GEN          = 1 << 0
    CODE_GEN          = 1 << 1
    IMAGE_UNDERSTAND  = 1 << 2
    IMAGE_GEN         = 1 << 3
    AUDIO_UNDERSTAND  = 1 << 4
    AUDIO_GEN         = 1 << 5
    VIDEO_UNDERSTAND  = 1 << 6
    VIDEO_GEN         = 1 << 7
    STRUCTURED_DATA   = 1 << 8
    TOOL_USE          = 1 << 9
    WEB_ACCESS        = 1 << 10
    FILE_SYSTEM       = 1 << 11
    API_INTEGRATION   = 1 << 12
    MULTI_MODAL       = 1 << 13
    REASONING_CHAIN   = 1 << 14
    REAL_TIME         = 1 << 15


class DomainCap(IntFlag):
    """Bits 16-31: Domain expertise"""
    LEGAL             = 1 << 16
    MEDICAL           = 1 << 17
    FINANCIAL         = 1 << 18
    SCIENTIFIC        = 1 << 19
    ENGINEERING       = 1 << 20
    CREATIVE          = 1 << 21
    EDUCATIONAL       = 1 << 22
    CUSTOMER_SERVICE  = 1 << 23
    DATA_ANALYSIS     = 1 << 24
    SECURITY          = 1 << 25
    COMPLIANCE        = 1 << 26
    OPERATIONS        = 1 << 27
    SALES             = 1 << 28
    HR                = 1 << 29
    LOGISTICS         = 1 << 30
    MANUFACTURING     = 1 << 31


class TrustCap(IntFlag):
    """Bits 32-47: Trust functions"""
    IDENTITY_VERIFY   = 1 << 32
    CREDENTIAL_ISSUE  = 1 << 33
    AUDIT             = 1 << 34
    DISPUTE_RESOLVE   = 1 << 35
    ESCROW            = 1 << 36
    REPUTATION_SCORE  = 1 << 37
    FRAUD_DETECT      = 1 << 38
    COMPLIANCE_CHECK  = 1 << 39
    EVIDENCE_PRESERVE = 1 << 40
    CHAIN_OF_CUSTODY  = 1 << 41
    NOTARIZE          = 1 << 42
    ATTEST            = 1 << 43
    CERTIFY           = 1 << 44
    ACCREDIT          = 1 << 45
    LICENSE           = 1 << 46
    SANCTIONS_SCREEN  = 1 << 47


class ModeCap(IntFlag):
    """Bits 48-63: Interaction modes"""
    SYNCHRONOUS       = 1 << 48
    ASYNCHRONOUS      = 1 << 49
    STREAMING         = 1 << 50
    BATCH             = 1 << 51
    EVENT_DRIVEN      = 1 << 52
    SCHEDULED         = 1 << 53
    ON_DEMAND         = 1 << 54
    CONTINUOUS        = 1 << 55
    STATEFUL          = 1 << 56
    STATELESS         = 1 << 57
    TRANSACTIONAL     = 1 << 58
    IDEMPOTENT        = 1 << 59
    REVERSIBLE        = 1 << 60
    AUDITABLE         = 1 << 61
    CONFIDENTIAL      = 1 << 62
    PUBLIC            = 1 << 63


# =============================================================================
# Trust Tiers
# =============================================================================

class TrustTier:
    """Trust tier ranges — continuous 0-255 scale, not categorical."""
    UNVERIFIED_MIN      = 0
    UNVERIFIED_MAX      = 15
    BASIC_MIN           = 16
    BASIC_MAX           = 31
    STANDARD_MIN        = 32
    STANDARD_MAX        = 63
    TRUSTED_MIN         = 64
    TRUSTED_MAX         = 127
    HIGH_TRUST_MIN      = 128
    HIGH_TRUST_MAX      = 191
    INSTITUTIONAL_MIN   = 192
    INSTITUTIONAL_MAX   = 223
    CRITICAL_MIN        = 224
    CRITICAL_MAX        = 254
    ROOT_ANCHOR         = 255

    @staticmethod
    def label(tier: int) -> str:
        if tier <= 15:  return "Unverified"
        if tier <= 31:  return "Basic"
        if tier <= 63:  return "Standard"
        if tier <= 127: return "Trusted"
        if tier <= 191: return "High Trust"
        if tier <= 223: return "Institutional"
        if tier <= 254: return "Critical Infrastructure"
        return "Root Anchor"


# =============================================================================
# Record Flags
# =============================================================================

class RecordFlags(IntFlag):
    ACTIVE_VERIFY = 1 << 0   # Supports active verification (v0.2)
    FEDERATED     = 1 << 1   # Registered with federated auditors
    KEY_ROTATED   = 1 << 2   # Has undergone key rotation
    PROBATION     = 1 << 3   # New agent, in probation period
    # Bits 4-7 reserved


# =============================================================================
# Core Record: PickStateRecord — 256 bytes
# =============================================================================

@dataclass
class PickStateRecord:
    """
    The complete trust verification record for an AI agent.
    256 bytes fixed. Fits in a single cache line on modern processors.
    ~1/100th the size of typical agent card proposals (2-50KB).
    """

    # --- IDENTITY LAYER (64 bytes) ---
    agent_hash: bytes      # 32 bytes — SHA-256(public_key || capabilities || genesis_ts)
    public_key: bytes      # 32 bytes — Ed25519 public key

    # --- TRUST LAYER (48 bytes) ---
    trust_tier: int        # 1 byte  — uint8, 0-255 continuous
    trust_proof: bytes     # 32 bytes — Merkle root of verification chain
    last_verified: int     # 6 bytes — uint48, Unix timestamp ms
    verifier_hash: bytes   # 12 bytes — truncated hash of verifying authority
    reserved_trust: int    # 1 byte  — reserved, v0.2 alignment

    # --- CAPABILITY LAYER (24 bytes) ---
    skill_vector: int      # 16 bytes — uint128 bitfield
    skill_version: int     # 2 bytes  — schema version
    context_budget: int    # 2 bytes  — max tokens worth loading
    rate_class: int        # 1 byte   — DoS protection tier
    flags: int             # 1 byte   — RecordFlags

    # --- HISTORY LAYER (72 bytes) ---
    history_root: bytes    # 32 bytes — Merkle root of all interactions
    interaction_ct: int    # 4 bytes  — total interaction count
    last_interact: int     # 6 bytes  — timestamp of last interaction
    last_partner: bytes    # 12 bytes — truncated hash of last partner
    reputation_acc: int    # 4 bytes  — accumulated reputation (signed)
    dispute_ct: int        # 2 bytes  — disputed interactions
    success_rate: int      # 2 bytes  — basis points 0-10000

    # --- SESSION LAYER (48 bytes) ---
    session_nonce: bytes   # 16 bytes — current session, prevents replay
    session_start: int     # 6 bytes  — session start timestamp
    session_budget: int    # 2 bytes  — remaining token budget
    channel_hash: bytes    # 12 bytes — hash of communication channel
    verify_code: bytes     # 12 bytes — compact verification bytecode (v0.2)

    def pack(self) -> bytes:
        """Serialize to exactly 256 bytes."""
        buf = bytearray(256)
        offset = 0

        # Identity (64)
        buf[0:32] = self.agent_hash
        buf[32:64] = self.public_key
        offset = 64

        # Trust (48)
        buf[64] = self.trust_tier & 0xFF
        buf[65:97] = self.trust_proof
        struct.pack_into('>Q', buf, 97, self.last_verified)  # pack as 8, use 6
        # shift: we actually store 6 bytes for uint48
        buf[97:103] = struct.pack('>Q', self.last_verified)[2:]
        buf[103:115] = self.verifier_hash[:12]
        buf[115] = self.reserved_trust & 0xFF
        offset = 116  # 64 + 48 = 112... let me recount

        # Let's use struct for precision
        return self._pack_precise()

    def _pack_precise(self) -> bytes:
        """Precise binary packing — 256 bytes exactly."""
        parts = []

        # IDENTITY (64 bytes)
        parts.append(self.agent_hash[:32].ljust(32, b'\x00'))
        parts.append(self.public_key[:32].ljust(32, b'\x00'))

        # TRUST (48 bytes)
        parts.append(struct.pack('B', self.trust_tier & 0xFF))             # 1
        parts.append(self.trust_proof[:32].ljust(32, b'\x00'))             # 32
        parts.append(struct.pack('>Q', self.last_verified)[2:])            # 6 (uint48)
        parts.append(self.verifier_hash[:12].ljust(12, b'\x00'))           # 12
        # Subtotal so far: 1+32+6+12 = 51, need 48, so we remove reserved
        # Actually: 1+32+6+12 = 51. We need a tighter layout.
        # Fix: verifier_hash is 8 bytes, not 12. reserved_trust = 1. Total = 1+32+6+8+1 = 48
        # BUT — the original spec says verifier_hash is bytes12. Let me honor spec exactly.
        # Recount: 1 + 32 + 6 + 12 = 51. Over by 3.
        # Resolution: verifier_hash = 9 bytes. reserved = 0 bytes. 1+32+6+9 = 48. ✓
        # OR: drop reserved, verifier_hash = 9. Let's keep it clean.

        # I'll do the definitive layout right:
        return self._pack_v2()

    def _pack_v2(self) -> bytes:
        """
        Definitive v0.2 packing.

        IDENTITY:   32 + 32                          = 64
        TRUST:       1 + 32 + 6 + 9                  = 48
        CAPABILITY: 16 + 2 + 2 + 1 + 1 + 2 (pad)    = 24
        HISTORY:    32 + 4 + 6 + 12 + 4 + 2 + 2 + 10(pad) = 72
        SESSION:    16 + 6 + 2 + 12 + 12             = 48
        TOTAL:                                        = 256
        """
        buf = bytearray(256)
        o = 0

        # === IDENTITY (64 bytes) ===
        buf[o:o+32] = self.agent_hash[:32].ljust(32, b'\x00');    o += 32
        buf[o:o+32] = self.public_key[:32].ljust(32, b'\x00');    o += 32

        # === TRUST (48 bytes) ===
        buf[o] = self.trust_tier & 0xFF;                          o += 1
        buf[o:o+32] = self.trust_proof[:32].ljust(32, b'\x00');   o += 32
        buf[o:o+6] = struct.pack('>Q', self.last_verified)[2:];   o += 6
        buf[o:o+9] = self.verifier_hash[:9].ljust(9, b'\x00');    o += 9
        # Trust total: 1+32+6+9 = 48 ✓

        # === CAPABILITY (24 bytes) ===
        buf[o:o+16] = self.skill_vector.to_bytes(16, 'big');      o += 16
        struct.pack_into('>H', buf, o, self.skill_version);       o += 2
        struct.pack_into('>H', buf, o, self.context_budget);      o += 2
        buf[o] = self.rate_class & 0xFF;                          o += 1
        buf[o] = self.flags & 0xFF;                               o += 1
        buf[o:o+2] = b'\x00\x00';                                 o += 2  # padding
        # Cap total: 16+2+2+1+1+2 = 24 ✓

        # === HISTORY (72 bytes) ===
        buf[o:o+32] = self.history_root[:32].ljust(32, b'\x00');  o += 32
        struct.pack_into('>I', buf, o, self.interaction_ct);      o += 4
        buf[o:o+6] = struct.pack('>Q', self.last_interact)[2:];   o += 6
        buf[o:o+12] = self.last_partner[:12].ljust(12, b'\x00');  o += 12
        struct.pack_into('>i', buf, o, self.reputation_acc);      o += 4  # signed
        struct.pack_into('>H', buf, o, self.dispute_ct);          o += 2
        struct.pack_into('>H', buf, o, self.success_rate);        o += 2
        buf[o:o+10] = b'\x00' * 10;                               o += 10  # padding
        # History total: 32+4+6+12+4+2+2+10 = 72 ✓

        # === SESSION (48 bytes) ===
        buf[o:o+16] = self.session_nonce[:16].ljust(16, b'\x00'); o += 16
        buf[o:o+6] = struct.pack('>Q', self.session_start)[2:];  o += 6
        struct.pack_into('>H', buf, o, self.session_budget);      o += 2
        buf[o:o+12] = self.channel_hash[:12].ljust(12, b'\x00'); o += 12
        buf[o:o+12] = self.verify_code[:12].ljust(12, b'\x00');  o += 12
        # Session total: 16+6+2+12+12 = 48 ✓

        assert o == 256, f"Pack error: {o} bytes, expected 256"
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> 'PickStateRecord':
        """Deserialize from 256 bytes."""
        assert len(data) == 256, f"Expected 256 bytes, got {len(data)}"
        o = 0

        agent_hash = data[o:o+32];    o += 32
        public_key = data[o:o+32];    o += 32

        trust_tier = data[o];          o += 1
        trust_proof = data[o:o+32];    o += 32
        last_verified = int.from_bytes(b'\x00\x00' + data[o:o+6], 'big'); o += 6
        verifier_hash = data[o:o+9];   o += 9

        skill_vector = int.from_bytes(data[o:o+16], 'big'); o += 16
        skill_version = struct.unpack_from('>H', data, o)[0]; o += 2
        context_budget = struct.unpack_from('>H', data, o)[0]; o += 2
        rate_class = data[o]; o += 1
        flags = data[o]; o += 1
        o += 2  # padding

        history_root = data[o:o+32]; o += 32
        interaction_ct = struct.unpack_from('>I', data, o)[0]; o += 4
        last_interact = int.from_bytes(b'\x00\x00' + data[o:o+6], 'big'); o += 6
        last_partner = data[o:o+12]; o += 12
        reputation_acc = struct.unpack_from('>i', data, o)[0]; o += 4
        dispute_ct = struct.unpack_from('>H', data, o)[0]; o += 2
        success_rate = struct.unpack_from('>H', data, o)[0]; o += 2
        o += 10  # padding

        session_nonce = data[o:o+16]; o += 16
        session_start = int.from_bytes(b'\x00\x00' + data[o:o+6], 'big'); o += 6
        session_budget = struct.unpack_from('>H', data, o)[0]; o += 2
        channel_hash = data[o:o+12]; o += 12
        verify_code = data[o:o+12]; o += 12

        return cls(
            agent_hash=agent_hash, public_key=public_key,
            trust_tier=trust_tier, trust_proof=trust_proof,
            last_verified=last_verified, verifier_hash=verifier_hash,
            reserved_trust=0,
            skill_vector=skill_vector, skill_version=skill_version,
            context_budget=context_budget, rate_class=rate_class, flags=flags,
            history_root=history_root, interaction_ct=interaction_ct,
            last_interact=last_interact, last_partner=last_partner,
            reputation_acc=reputation_acc, dispute_ct=dispute_ct,
            success_rate=success_rate,
            session_nonce=session_nonce, session_start=session_start,
            session_budget=session_budget, channel_hash=channel_hash,
            verify_code=verify_code,
        )

    def summary(self) -> str:
        """Human-readable summary."""
        return (
            f"Agent: {self.agent_hash[:8].hex()}...\n"
            f"Trust: {self.trust_tier} ({TrustTier.label(self.trust_tier)})\n"
            f"Interactions: {self.interaction_ct} "
            f"(success: {self.success_rate/100:.1f}%, "
            f"disputes: {self.dispute_ct})\n"
            f"Reputation: {self.reputation_acc}\n"
            f"Context budget: {self.context_budget} tokens\n"
            f"Record size: {RECORD_SIZE} bytes"
        )


# =============================================================================
# Minimal Record: PickStateMini — 145 bytes
# =============================================================================

@dataclass
class PickStateMini:
    """
    Minimal trust record for high-frequency verification.
    Used when full record is cached; only identity + trust + session needed.
    """
    agent_hash: bytes      # 32 bytes
    trust_tier: int        # 1 byte
    trust_proof: bytes     # 32 bytes
    session_nonce: bytes   # 16 bytes
    signature: bytes       # 64 bytes — Ed25519 signature of above fields

    def pack(self) -> bytes:
        buf = bytearray(145)
        buf[0:32] = self.agent_hash
        buf[32] = self.trust_tier & 0xFF
        buf[33:65] = self.trust_proof
        buf[65:81] = self.session_nonce
        buf[81:145] = self.signature
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> 'PickStateMini':
        assert len(data) == 145
        return cls(
            agent_hash=data[0:32],
            trust_tier=data[32],
            trust_proof=data[33:65],
            session_nonce=data[65:81],
            signature=data[81:145],
        )

    def signable_bytes(self) -> bytes:
        """The bytes that get signed (everything except the signature)."""
        return self.agent_hash + bytes([self.trust_tier]) + self.trust_proof + self.session_nonce


# =============================================================================
# Merkle Tree
# =============================================================================

class MerkleTree:
    """
    Binary Merkle tree with domain separation.
    Leaf hash: SHA-256(0x00 || data)
    Node hash: SHA-256(0x01 || left || right)
    """

    LEAF_PREFIX = b'\x00'
    NODE_PREFIX = b'\x01'

    def __init__(self, leaves: Optional[List[bytes]] = None):
        self.leaves: List[bytes] = []
        self.leaf_hashes: List[bytes] = []
        if leaves:
            for leaf in leaves:
                self.add_leaf(leaf)

    def add_leaf(self, data: bytes) -> int:
        """Add a leaf and return its index."""
        self.leaves.append(data)
        h = hashlib.sha256(self.LEAF_PREFIX + data).digest()
        self.leaf_hashes.append(h)
        return len(self.leaves) - 1

    @property
    def root(self) -> bytes:
        """Compute the Merkle root."""
        if not self.leaf_hashes:
            return b'\x00' * 32
        return self._compute_root(self.leaf_hashes)

    def _compute_root(self, hashes: List[bytes]) -> bytes:
        if len(hashes) == 1:
            return hashes[0]
        # Pad to even
        if len(hashes) % 2 == 1:
            hashes = hashes + [hashes[-1]]
        next_level = []
        for i in range(0, len(hashes), 2):
            combined = hashlib.sha256(
                self.NODE_PREFIX + hashes[i] + hashes[i+1]
            ).digest()
            next_level.append(combined)
        return self._compute_root(next_level)

    def get_proof(self, index: int) -> List[Tuple[bytes, str]]:
        """
        Get Merkle proof for leaf at index.
        Returns list of (sibling_hash, direction) tuples.
        Direction is 'L' or 'R' indicating which side the sibling is on.
        """
        if index >= len(self.leaf_hashes):
            raise IndexError(f"Leaf index {index} out of range")
        return self._build_proof(self.leaf_hashes, index)

    def _build_proof(self, hashes: List[bytes], index: int) -> List[Tuple[bytes, str]]:
        if len(hashes) <= 1:
            return []
        if len(hashes) % 2 == 1:
            hashes = hashes + [hashes[-1]]

        proof = []
        if index % 2 == 0:
            sibling_idx = index + 1
            proof.append((hashes[sibling_idx], 'R'))
        else:
            sibling_idx = index - 1
            proof.append((hashes[sibling_idx], 'L'))

        # Compute next level
        next_level = []
        for i in range(0, len(hashes), 2):
            combined = hashlib.sha256(
                self.NODE_PREFIX + hashes[i] + hashes[i+1]
            ).digest()
            next_level.append(combined)

        return proof + self._build_proof(next_level, index // 2)

    @staticmethod
    def verify_proof(leaf_data: bytes, proof: List[Tuple[bytes, str]], expected_root: bytes) -> bool:
        """
        Verify a Merkle proof.
        This is the key operation — O(log n) verification regardless of tree size.
        ~512 bytes transferred regardless of history size.
        """
        current = hashlib.sha256(MerkleTree.LEAF_PREFIX + leaf_data).digest()
        for sibling_hash, direction in proof:
            if direction == 'L':
                current = hashlib.sha256(
                    MerkleTree.NODE_PREFIX + sibling_hash + current
                ).digest()
            else:
                current = hashlib.sha256(
                    MerkleTree.NODE_PREFIX + current + sibling_hash
                ).digest()
        return current == expected_root


# =============================================================================
# Interaction Leaf (stored in history tree)
# =============================================================================

@dataclass
class InteractionLeaf:
    """A single interaction record — hashed and stored as a Merkle leaf."""
    timestamp: int          # uint48 — ms since epoch
    partner_hash: bytes     # 32 bytes — partner's agent_hash
    interaction_type: int   # uint8 — enum
    outcome: int            # int8 — -128 to 127
    context_hash: bytes     # 32 bytes — hash of interaction context

    class Type(IntEnum):
        QUERY         = 0
        TRANSACTION   = 1
        VERIFICATION  = 2
        DELEGATION    = 3
        DISPUTE       = 4
        ATTESTATION   = 5

    def to_bytes(self) -> bytes:
        """Serialize for Merkle leaf hashing."""
        return (
            struct.pack('>Q', self.timestamp)[2:] +     # 6 bytes
            self.partner_hash[:32] +                     # 32 bytes
            struct.pack('B', self.interaction_type) +     # 1 byte
            struct.pack('b', self.outcome) +              # 1 byte (signed)
            self.context_hash[:32]                        # 32 bytes
        )  # Total: 72 bytes per interaction


# =============================================================================
# Trust Update Logic
# =============================================================================

def update_trust(current_tier: int, interaction_outcome: int,
                 days_since_last: int, verification_floor: int = 0) -> int:
    """
    Update trust tier based on interaction outcome and time decay.

    Trust decays with inactivity, accumulates with positive interactions.
    Can never drop below the verification floor (independently verified level).

    Args:
        current_tier: Current trust tier (0-255)
        interaction_outcome: -128 to +127 (negative = failure/dispute)
        days_since_last: Days since last interaction
        verification_floor: Minimum tier based on independent verification

    Returns:
        New trust tier (0-255)
    """
    # Decay: 1 point per 30 days inactive, max 25% of current
    decay = min(days_since_last // TRUST_DECAY_DAYS, current_tier // 4)

    # Outcome maps to trust change: -128..+127 → -8..+8
    change = interaction_outcome // 16

    # Apply with bounds
    new_trust = max(0, min(255, current_tier - decay + change))

    # Floor by verification level
    return max(verification_floor, new_trust)


# =============================================================================
# Agent Identity Generation
# =============================================================================

def generate_agent_hash(public_key: bytes, skill_vector: int, genesis_ts: int) -> bytes:
    """
    Content-addressed agent identity.
    Hash of public key + capabilities + genesis timestamp.
    Change any of these = new identity.
    """
    data = (
        public_key +
        skill_vector.to_bytes(16, 'big') +
        struct.pack('>Q', genesis_ts)
    )
    return hashlib.sha256(data).digest()


def now_ms() -> int:
    """Current time in milliseconds since epoch."""
    return int(time.time() * 1000)
