#!/usr/bin/env python3
"""
PickState Protocol v0.2 — Working Demonstration

Shows the complete flow:
1. Create two agents with different capabilities and trust levels
2. Register them with the three-node trust harness
3. Run verification (Gatekeeper → Proxy → Auditor)
4. Log interactions and update history
5. Demonstrate Section 5.3: Third-party verification without disclosure
6. Show trust decay and accumulation
7. Demonstrate the 256-byte record pack/unpack roundtrip

Authors: Garrett (g8g8g8-cmcy) & Claude
License: CC0 1.0 Universal (Public Domain)
"""

import hashlib
import os
import time
import sys

from pickstate_core import (
    PickStateRecord, PickStateMini, MerkleTree, InteractionLeaf,
    TrustTier, RecordFlags, CoreCap, DomainCap, TrustCap, ModeCap,
    update_trust, generate_agent_hash, now_ms, RECORD_SIZE,
)
from pickstate_harness import TrustHarness

try:
    from nacl.signing import SigningKey
    HAS_NACL = True
except ImportError:
    HAS_NACL = False


def separator(title: str):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def main():
    separator("PickState Protocol v0.2 — Working Demo")

    print("Core insight: Don't pass state. Pass proofs of state.")
    print("Adapted from Pick database principles (Dick Pick, 1965).")
    print(f"Record size: {RECORD_SIZE} bytes (vs 2-50KB for current agent cards)\n")

    # =========================================================================
    # 1. CREATE AGENTS
    # =========================================================================
    separator("1. Creating Agents")

    # Agent A: A legal research agent (high trust, law firm deployment)
    if HAS_NACL:
        sk_a = SigningKey.generate()
        pk_a = bytes(sk_a.verify_key)
    else:
        pk_a = os.urandom(32)
        sk_a = None

    caps_a = (
        CoreCap.TEXT_GEN | CoreCap.REASONING_CHAIN | CoreCap.TOOL_USE |
        CoreCap.WEB_ACCESS | CoreCap.STRUCTURED_DATA |
        DomainCap.LEGAL | DomainCap.DATA_ANALYSIS | DomainCap.COMPLIANCE |
        ModeCap.SYNCHRONOUS | ModeCap.AUDITABLE | ModeCap.CONFIDENTIAL
    )

    genesis_a = now_ms()
    hash_a = generate_agent_hash(pk_a, caps_a, genesis_a)

    record_a = PickStateRecord(
        agent_hash=hash_a,
        public_key=pk_a,
        trust_tier=128,  # High trust — verified by multiple authorities
        trust_proof=hashlib.sha256(b'verification_chain_a').digest(),
        last_verified=now_ms(),
        verifier_hash=os.urandom(9),
        reserved_trust=0,
        skill_vector=caps_a,
        skill_version=1,
        context_budget=2048,
        rate_class=2,
        flags=RecordFlags.ACTIVE_VERIFY,
        history_root=b'\x00' * 32,  # Empty history
        interaction_ct=0,
        last_interact=0,
        last_partner=b'\x00' * 12,
        reputation_acc=0,
        dispute_ct=0,
        success_rate=10000,  # 100% (basis points)
        session_nonce=os.urandom(16),
        session_start=now_ms(),
        session_budget=2048,
        channel_hash=os.urandom(12),
        verify_code=b'\x00' * 12,  # v0.2 placeholder
    )

    print("Agent A — Legal Research Agent:")
    print(record_a.summary())
    print(f"  Capabilities: legal, data_analysis, compliance, text_gen, reasoning")

    # Agent B: A forensic data agent (institutional grade)
    if HAS_NACL:
        sk_b = SigningKey.generate()
        pk_b = bytes(sk_b.verify_key)
    else:
        pk_b = os.urandom(32)
        sk_b = None

    caps_b = (
        CoreCap.TEXT_GEN | CoreCap.STRUCTURED_DATA | CoreCap.FILE_SYSTEM |
        CoreCap.API_INTEGRATION |
        DomainCap.LEGAL | DomainCap.SECURITY | DomainCap.COMPLIANCE |
        TrustCap.EVIDENCE_PRESERVE | TrustCap.CHAIN_OF_CUSTODY |
        ModeCap.TRANSACTIONAL | ModeCap.AUDITABLE
    )

    genesis_b = now_ms()
    hash_b = generate_agent_hash(pk_b, caps_b, genesis_b)

    record_b = PickStateRecord(
        agent_hash=hash_b,
        public_key=pk_b,
        trust_tier=192,  # Institutional grade
        trust_proof=hashlib.sha256(b'verification_chain_b').digest(),
        last_verified=now_ms(),
        verifier_hash=os.urandom(9),
        reserved_trust=0,
        skill_vector=caps_b,
        skill_version=1,
        context_budget=4096,
        rate_class=3,
        flags=RecordFlags.ACTIVE_VERIFY | RecordFlags.FEDERATED,
        history_root=b'\x00' * 32,
        interaction_ct=0,
        last_interact=0,
        last_partner=b'\x00' * 12,
        reputation_acc=500,
        dispute_ct=0,
        success_rate=9950,  # 99.5%
        session_nonce=os.urandom(16),
        session_start=now_ms(),
        session_budget=4096,
        channel_hash=os.urandom(12),
        verify_code=b'\x00' * 12,
    )

    print(f"\nAgent B — Forensic Data Agent:")
    print(record_b.summary())
    print(f"  Capabilities: legal, security, evidence_preserve, chain_of_custody")

    # =========================================================================
    # 2. PACK/UNPACK ROUNDTRIP — Prove it's exactly 256 bytes
    # =========================================================================
    separator("2. Record Serialization — 256 Bytes")

    packed_a = record_a.pack()
    print(f"Agent A packed: {len(packed_a)} bytes")
    print(f"  Hex (first 64 bytes): {packed_a[:64].hex()}")
    print(f"  Hex (last 32 bytes):  {packed_a[-32:].hex()}")

    unpacked_a = PickStateRecord.unpack(packed_a)
    repacked_a = unpacked_a.pack()
    roundtrip_ok = packed_a == repacked_a
    print(f"\n  Roundtrip pack → unpack → pack: {'PASS ✓' if roundtrip_ok else 'FAIL ✗'}")
    print(f"  Record size: exactly {len(packed_a)} bytes")
    print(f"  Compare: A2A agent cards are typically 2,000 - 50,000 bytes")
    print(f"  Ratio: ~1/{50000 // len(packed_a)}th the size")

    # =========================================================================
    # 3. THREE-NODE VERIFICATION
    # =========================================================================
    separator("3. Three-Node Trust Verification")

    harness = TrustHarness(trust_threshold=0, max_budget=8192)
    harness.register(record_a)
    harness.register(record_b)

    print("Registered both agents with Gatekeeper, Proxy, and Auditor.")
    print("  Gatekeeper holds: agent_hash + trust_tier + trust_proof (81 bytes)")
    print("  Proxy holds:      skill_vector + context_budget + rate_class (19 bytes)")
    print("  Auditor holds:    history_root + interaction_ct (44 bytes)")
    print("  No node holds the full 256-byte record.\n")

    # Create a PickStateMini for Agent A to present
    nonce_a = os.urandom(16)
    if HAS_NACL and sk_a:
        signable = hash_a + bytes([record_a.trust_tier]) + record_a.trust_proof + nonce_a
        signature_a = bytes(sk_a.sign(signable).signature)
    else:
        signature_a = os.urandom(64)  # placeholder without Ed25519

    mini_a = PickStateMini(
        agent_hash=hash_a,
        trust_tier=record_a.trust_tier,
        trust_proof=record_a.trust_proof,
        session_nonce=nonce_a,
        signature=signature_a,
    )

    print(f"Agent A presents PickStateMini: {len(mini_a.pack())} bytes")

    # Verify with required legal + compliance capabilities
    required_caps = DomainCap.LEGAL | DomainCap.COMPLIANCE
    result = harness.verify_and_authorize(
        mini_a,
        required_capabilities=required_caps,
        required_trust=64,  # Need at least "Trusted" tier
    )

    print(f"\nVerification result:")
    print(f"  Allowed: {result['allowed']}")
    if result['allowed']:
        print(f"  Trust tier: {result['trust_tier']} ({TrustTier.label(result['trust_tier'])})")
        print(f"  Budget allocated: {result['allocated_budget']} tokens")
        print(f"  Session token: {result['session_token'][:8].hex()}...")
    else:
        print(f"  Rejected at: {result['stage']}")
        print(f"  Reason: {result['reason']}")

    # =========================================================================
    # 4. INTERACTION LOGGING
    # =========================================================================
    separator("4. Interaction Logging")

    print("Simulating 5 interactions between Agent A and Agent B...\n")

    for i in range(5):
        context = hashlib.sha256(f"interaction_{i}_context_data".encode()).digest()
        outcome = 100 if i != 3 else -50  # One negative interaction

        new_root = harness.record_interaction(
            agent_a_hash=hash_a,
            agent_b_hash=hash_b,
            interaction_type=InteractionLeaf.Type.QUERY,
            outcome=outcome,
            context_hash=context,
        )

        status = "positive" if outcome > 0 else "DISPUTE"
        print(f"  Interaction {i+1}: {status} (outcome: {outcome:+d})")
        print(f"    New history root: {new_root[:8].hex()}...")

    # =========================================================================
    # 5. SECTION 5.3 — VERIFICATION WITHOUT LOADING
    # =========================================================================
    separator("5. Section 5.3 — Verification Without Disclosure")

    print('"Prove it happened without showing what happened."\n')

    # Third party C wants to verify interaction #2 occurred
    target_index = 2
    print(f"Third party C wants to verify interaction #{target_index + 1} occurred.")
    print(f"C does NOT see what Agent A and Agent B discussed.")
    print(f"C only sees: proof that the interaction happened and was valid.\n")

    # Get the Merkle proof
    proof = harness.auditor.get_proof(hash_a, target_index)
    if proof:
        # Get the interaction data (in real scenario, A provides this)
        tree = harness.auditor._interaction_trees[hash_a]
        leaf_data = tree.leaves[target_index]

        # Get current history root (from Auditor's public state)
        current_root = tree.root

        # Verify
        verified = MerkleTree.verify_proof(leaf_data, proof, current_root)

        print(f"Merkle proof steps: {len(proof)}")
        proof_size = len(proof) * 33  # 32 bytes hash + 1 byte direction
        print(f"Proof size: ~{proof_size} bytes")
        print(f"History size: {len(tree.leaves)} interactions")
        print(f"Verification result: {'VERIFIED ✓' if verified else 'FAILED ✗'}")
        print(f"\nKey insight: proof size is O(log n) regardless of history size.")
        print(f"  5 interactions:        ~{proof_size} bytes transferred")
        print(f"  50,000 interactions:   ~{17 * 33} bytes transferred")
        print(f"  5,000,000 interactions: ~{23 * 33} bytes transferred")
        print(f"\nThe verifier never sees interaction content — only the proof path.")

    # =========================================================================
    # 6. TRUST DYNAMICS
    # =========================================================================
    separator("6. Trust Decay and Accumulation")

    current = 128  # High trust
    print(f"Starting trust: {current} ({TrustTier.label(current)})")

    # Positive interaction
    current = update_trust(current, interaction_outcome=100, days_since_last=1)
    print(f"After positive interaction (+100, 1 day):  {current} ({TrustTier.label(current)})")

    # Another positive
    current = update_trust(current, interaction_outcome=80, days_since_last=5)
    print(f"After positive interaction (+80, 5 days):  {current} ({TrustTier.label(current)})")

    # 90 days inactive
    current = update_trust(current, interaction_outcome=0, days_since_last=90)
    print(f"After 90 days inactive:                    {current} ({TrustTier.label(current)})")

    # Negative interaction (dispute)
    current = update_trust(current, interaction_outcome=-100, days_since_last=1)
    print(f"After dispute (-100, 1 day):               {current} ({TrustTier.label(current)})")

    # With verification floor
    current_floored = update_trust(80, interaction_outcome=-128, days_since_last=365,
                                    verification_floor=64)
    print(f"\nWith verification floor of 64:")
    print(f"  Tier 80, worst outcome, 1 year inactive: {current_floored} ({TrustTier.label(current_floored)})")
    print(f"  Trust can't drop below independently verified level.")

    # =========================================================================
    # 7. REPLAY PROTECTION
    # =========================================================================
    separator("7. Replay Protection")

    # Try to replay the same mini
    replay_result = harness.verify_and_authorize(mini_a)
    print(f"Replaying Agent A's previous PickStateMini:")
    print(f"  Allowed: {replay_result['allowed']}")
    print(f"  Reason: {replay_result.get('reason', 'N/A')}")
    print(f"  Session nonce was already consumed by Gatekeeper's LRU cache.")

    # Fresh nonce works
    fresh_nonce = os.urandom(16)
    if HAS_NACL and sk_a:
        signable = hash_a + bytes([record_a.trust_tier]) + record_a.trust_proof + fresh_nonce
        fresh_sig = bytes(sk_a.sign(signable).signature)
    else:
        fresh_sig = os.urandom(64)

    fresh_mini = PickStateMini(
        agent_hash=hash_a,
        trust_tier=record_a.trust_tier,
        trust_proof=record_a.trust_proof,
        session_nonce=fresh_nonce,
        signature=fresh_sig,
    )
    fresh_result = harness.verify_and_authorize(fresh_mini)
    print(f"\nFresh nonce:")
    print(f"  Allowed: {fresh_result['allowed']}")

    # =========================================================================
    # 8. CAPABILITY MATCHING
    # =========================================================================
    separator("8. Capability Matching — O(1) Bitwise Operation")

    # Agent A tries to do something requiring medical capability
    medical_caps = DomainCap.MEDICAL | CoreCap.REASONING_CHAIN
    fresh_nonce2 = os.urandom(16)
    if HAS_NACL and sk_a:
        signable = hash_a + bytes([record_a.trust_tier]) + record_a.trust_proof + fresh_nonce2
        sig2 = bytes(sk_a.sign(signable).signature)
    else:
        sig2 = os.urandom(64)

    mini_medical = PickStateMini(
        agent_hash=hash_a,
        trust_tier=record_a.trust_tier,
        trust_proof=record_a.trust_proof,
        session_nonce=fresh_nonce2,
        signature=sig2,
    )

    medical_result = harness.verify_and_authorize(
        mini_medical,
        required_capabilities=medical_caps,
    )
    print(f"Agent A (legal specialist) requests medical + reasoning access:")
    print(f"  Allowed: {medical_result['allowed']}")
    print(f"  Stage: {medical_result.get('stage', 'all passed')}")
    print(f"  Reason: {medical_result.get('reason', 'N/A')}")
    print(f"\n  Agent A has reasoning_chain but NOT medical capability.")
    print(f"  Single bitwise AND operation catches this in O(1).")

    # =========================================================================
    # 9. SIZE COMPARISON
    # =========================================================================
    separator("9. Protocol Size Comparison")

    comparisons = [
        ("OAuth token (typical)",          "1,000 - 10,000 bytes"),
        ("A2A Agent Card (Google)",         "2,000 - 50,000 bytes"),
        ("W3C Verifiable Credential",      "1,000 - 5,000 bytes"),
        ("PickState Full Record",          f"{RECORD_SIZE} bytes"),
        ("PickState Mini (high-freq)",     "145 bytes"),
        ("PickState Verification proof",   "~512 bytes (regardless of history)"),
    ]

    for name, size in comparisons:
        arrow = "  ◄── THIS" if "PickState" in name else ""
        print(f"  {name:40s} {size:>30s}{arrow}")

    print(f"\n  1000 agents verified with PickState: {RECORD_SIZE * 1000 // 1024} KB context overhead")
    print(f"  1000 agents verified with A2A cards:  ~25,000 KB context overhead")

    # =========================================================================
    # DONE
    # =========================================================================
    separator("Done")

    print("PickState Protocol v0.2 — Reference Implementation")
    print("CC0 1.0 Universal (Public Domain)")
    print()
    print("What this demonstrates:")
    print("  ✓ 256-byte trust records (vs 2-50KB industry proposals)")
    print("  ✓ Three-node architecture (no node holds full record)")
    print("  ✓ O(1) capability matching via bitfield operations")
    print("  ✓ O(log n) history verification via Merkle proofs")
    print("  ✓ Verification without disclosure (Section 5.3)")
    print("  ✓ Replay protection via session nonces")
    print("  ✓ Trust decay/accumulation with verification floor")
    print("  ✓ Ed25519 signatures (when PyNaCl available)")
    print()
    print("Core principle: Don't pass state. Pass proofs of state.")
    print("From Dick Pick (1965) to AI agent trust (2026).")
    print()
    print("Repository: github.com/g8g8g8-cmcy/ai2ai-trust-framework")


if __name__ == '__main__':
    main()
