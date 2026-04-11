"""
PickState Protocol v0.2 — Three-Node Trust Harness

Gatekeeper: Identity verification + replay protection
Proxy:      Capability matching + resource allocation
Auditor:    History verification + interaction logging

No node holds the full 256-byte record.
Compromise of any single node reveals only partial information.
Verification requires combining proofs across nodes.

Authors: Garrett (g8g8g8-cmcy) & Claude
License: CC0 1.0 Universal (Public Domain)
"""

import hashlib
import os
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple

from pickstate_core import (
    PickStateRecord, PickStateMini, MerkleTree, InteractionLeaf,
    TrustTier, RecordFlags, update_trust, now_ms, generate_agent_hash,
)

try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.exceptions import BadSignatureError
    HAS_NACL = True
except ImportError:
    HAS_NACL = False


# =============================================================================
# Result Types
# =============================================================================

@dataclass
class GatekeeperResult:
    allowed: bool
    reason: str = ""
    trust_tier: int = 0
    session_token: bytes = b''

@dataclass
class ProxyResult:
    authorized: bool
    reason: str = ""
    allocated_budget: int = 0
    capabilities: int = 0
    missing_caps: int = 0

@dataclass
class AuditResult:
    verified: bool
    reason: str = ""
    is_new: bool = False
    last_verified: int = 0
    interaction_gap: int = 0


# =============================================================================
# LRU Cache for Nonce Replay Protection
# =============================================================================

class LRUCache:
    """Simple LRU cache for session nonce tracking."""

    def __init__(self, max_size: int = 100_000):
        self.max_size = max_size
        self._cache: OrderedDict = OrderedDict()

    def contains(self, key: bytes) -> bool:
        if key in self._cache:
            self._cache.move_to_end(key)
            return True
        return False

    def add(self, key: bytes):
        if key in self._cache:
            self._cache.move_to_end(key)
        else:
            self._cache[key] = True
            if len(self._cache) > self.max_size:
                self._cache.popitem(last=False)


# =============================================================================
# Gatekeeper Node — Identity + Trust + Replay Protection
# =============================================================================

class Gatekeeper:
    """
    First contact. Verifies identity and trust level.
    Holds: agent_hash, trust_tier, trust_proof, session_nonce (81 bytes per agent)

    This node answers one question: "Are you who you say you are,
    and are you trusted enough?"
    """

    def __init__(self, trust_threshold: int = 0):
        self.threshold = trust_threshold
        self.nonce_cache = LRUCache(max_size=100_000)
        # Known agent trust records (in production, this would be a database)
        self._known_agents: Dict[bytes, dict] = {}

    def register_agent(self, record: PickStateRecord):
        """Register an agent's trust data with the Gatekeeper."""
        self._known_agents[record.agent_hash] = {
            'trust_tier': record.trust_tier,
            'trust_proof': record.trust_proof,
            'public_key': record.public_key,
        }

    def verify(self, mini: PickStateMini, required_tier: Optional[int] = None) -> GatekeeperResult:
        """
        Verify an incoming agent request.

        Checks:
        1. Session nonce not replayed
        2. Signature is valid (if Ed25519 available)
        3. Trust tier meets threshold
        4. Trust proof is known/valid
        """
        threshold = required_tier if required_tier is not None else self.threshold

        # 1. Replay check
        if self.nonce_cache.contains(mini.session_nonce):
            return GatekeeperResult(allowed=False, reason="replay_detected")

        # 2. Signature verification
        if HAS_NACL and mini.agent_hash in self._known_agents:
            try:
                pk_bytes = self._known_agents[mini.agent_hash]['public_key']
                verify_key = VerifyKey(pk_bytes)
                verify_key.verify(mini.signable_bytes(), mini.signature)
            except (BadSignatureError, Exception) as e:
                return GatekeeperResult(allowed=False, reason=f"invalid_signature: {e}")

        # 3. Trust level check
        if mini.trust_tier < threshold:
            return GatekeeperResult(
                allowed=False,
                reason=f"insufficient_trust: {mini.trust_tier} < {threshold}",
                trust_tier=mini.trust_tier,
            )

        # 4. Trust proof consistency (check against known record)
        if mini.agent_hash in self._known_agents:
            known = self._known_agents[mini.agent_hash]
            if mini.trust_proof != known['trust_proof']:
                return GatekeeperResult(allowed=False, reason="trust_proof_mismatch")

        # All checks passed
        self.nonce_cache.add(mini.session_nonce)
        session_token = os.urandom(32)

        return GatekeeperResult(
            allowed=True,
            trust_tier=mini.trust_tier,
            session_token=session_token,
        )


# =============================================================================
# Proxy Node — Capability Matching + Resource Allocation
# =============================================================================

class Proxy:
    """
    Capability matching and resource allocation.
    Holds: skill_vector, context_budget, rate_class (19 bytes per agent)

    This node answers: "Can you do what's needed, and how much
    context are you worth?"
    """

    def __init__(self, max_context_budget: int = 4096):
        self.max_budget = max_context_budget
        self._active_sessions: Dict[bytes, dict] = {}
        self._agent_caps: Dict[bytes, dict] = {}
        self._rate_limits: Dict[bytes, List[float]] = {}

    def register_agent(self, record: PickStateRecord):
        """Register an agent's capability data with the Proxy."""
        self._agent_caps[record.agent_hash] = {
            'skill_vector': record.skill_vector,
            'context_budget': record.context_budget,
            'rate_class': record.rate_class,
        }

    def authorize(self, session_token: bytes, agent_hash: bytes,
                  required_capabilities: int = 0) -> ProxyResult:
        """
        Check capabilities and allocate resources.

        Checks:
        1. Agent has required capabilities (bitfield AND)
        2. Rate limit not exceeded
        3. Allocate context budget
        """
        if agent_hash not in self._agent_caps:
            return ProxyResult(authorized=False, reason="unknown_agent")

        caps = self._agent_caps[agent_hash]

        # 1. Capability check — single bitwise AND operation, O(1)
        if required_capabilities:
            if (caps['skill_vector'] & required_capabilities) != required_capabilities:
                missing = required_capabilities & ~caps['skill_vector']
                return ProxyResult(
                    authorized=False,
                    reason="missing_capabilities",
                    missing_caps=missing,
                )

        # 2. Rate limit check
        if self._is_rate_limited(agent_hash, caps['rate_class']):
            return ProxyResult(authorized=False, reason="rate_limited")

        # 3. Allocate budget
        allocated = min(caps['context_budget'], self.max_budget)

        self._active_sessions[session_token] = {
            'agent': agent_hash,
            'budget': allocated,
            'used': 0,
            'started': time.time(),
        }

        # Record rate limit hit
        if agent_hash not in self._rate_limits:
            self._rate_limits[agent_hash] = []
        self._rate_limits[agent_hash].append(time.time())

        return ProxyResult(
            authorized=True,
            allocated_budget=allocated,
            capabilities=caps['skill_vector'],
        )

    def consume_budget(self, session_token: bytes, tokens_used: int) -> bool:
        """Track token consumption against budget."""
        if session_token not in self._active_sessions:
            return False
        session = self._active_sessions[session_token]
        session['used'] += tokens_used
        return session['used'] <= session['budget']

    def _is_rate_limited(self, agent_hash: bytes, rate_class: int) -> bool:
        """Check if agent has exceeded its rate limit."""
        if agent_hash not in self._rate_limits:
            return False
        # Rate class 0 = 10 req/min, each class doubles
        max_per_minute = 10 * (2 ** rate_class)
        cutoff = time.time() - 60
        recent = [t for t in self._rate_limits[agent_hash] if t > cutoff]
        self._rate_limits[agent_hash] = recent  # cleanup
        return len(recent) >= max_per_minute


# =============================================================================
# Auditor Node — History Verification + Interaction Logging
# =============================================================================

class Auditor:
    """
    History verification and interaction logging.
    Holds: history_root, interaction_ct, last_interact (44 bytes per agent)
    Never loads full history; works only with Merkle proofs.

    This node answers: "Has this agent behaved as claimed?"
    """

    def __init__(self):
        self._agent_state: Dict[bytes, dict] = {}
        self._interaction_trees: Dict[bytes, MerkleTree] = {}
        self._completed_log: List[dict] = []  # append-only

    def register_agent(self, record: PickStateRecord):
        """Register an agent's history data with the Auditor."""
        self._agent_state[record.agent_hash] = {
            'history_root': record.history_root,
            'interaction_ct': record.interaction_ct,
            'last_interact': record.last_interact,
        }
        # Initialize empty interaction tree for this agent
        if record.agent_hash not in self._interaction_trees:
            self._interaction_trees[record.agent_hash] = MerkleTree()

    def verify_history(self, agent_hash: bytes,
                       claimed_history_root: bytes,
                       claimed_interaction_ct: int) -> AuditResult:
        """
        Verify an agent's claimed history.
        Never loads full history — only checks against last known state.
        """
        if agent_hash not in self._agent_state:
            # New agent — accept but flag as new
            # v0.2: New agents start at tier 0, so accepting initial state is safe
            self._agent_state[agent_hash] = {
                'history_root': claimed_history_root,
                'interaction_ct': claimed_interaction_ct,
                'last_interact': now_ms(),
            }
            return AuditResult(verified=True, is_new=True, last_verified=now_ms())

        known = self._agent_state[agent_hash]

        # Interaction count can only increase
        if claimed_interaction_ct < known['interaction_ct']:
            return AuditResult(
                verified=False,
                reason=f"interaction_count_decreased: "
                       f"claimed {claimed_interaction_ct} < known {known['interaction_ct']}",
            )

        # If count matches, root must match
        if (claimed_interaction_ct == known['interaction_ct'] and
                claimed_history_root != known['history_root']):
            return AuditResult(
                verified=False,
                reason="history_root_mismatch_at_same_count",
            )

        return AuditResult(
            verified=True,
            last_verified=now_ms(),
            interaction_gap=claimed_interaction_ct - known['interaction_ct'],
        )

    def log_interaction(self, agent_a: bytes, agent_b: bytes,
                        interaction: InteractionLeaf) -> bytes:
        """
        Log a completed interaction and update the agent's history tree.
        Returns the new history root.
        """
        # Add to agent A's Merkle tree
        if agent_a not in self._interaction_trees:
            self._interaction_trees[agent_a] = MerkleTree()

        tree = self._interaction_trees[agent_a]
        tree.add_leaf(interaction.to_bytes())
        new_root = tree.root

        # Update known state
        self._agent_state[agent_a] = {
            'history_root': new_root,
            'interaction_ct': len(tree.leaves),
            'last_interact': interaction.timestamp,
        }

        # Append-only log
        self._completed_log.append({
            'agent_a': agent_a,
            'agent_b': agent_b,
            'timestamp': interaction.timestamp,
            'type': interaction.interaction_type,
            'outcome': interaction.outcome,
            'new_root': new_root,
        })

        return new_root

    def get_proof(self, agent_hash: bytes, interaction_index: int) -> Optional[List[Tuple[bytes, str]]]:
        """
        Get a Merkle proof for a specific interaction.
        This is what enables Section 5.3: Verification Without Loading.
        ~512 bytes regardless of history size.
        """
        if agent_hash not in self._interaction_trees:
            return None
        tree = self._interaction_trees[agent_hash]
        if interaction_index >= len(tree.leaves):
            return None
        return tree.get_proof(interaction_index)

    def verify_interaction_proof(self, interaction_data: bytes,
                                 proof: List[Tuple[bytes, str]],
                                 expected_root: bytes) -> bool:
        """
        Third-party verification: prove an interaction occurred
        without loading the agent's full history.

        "Prove it happened without showing what happened."
        """
        return MerkleTree.verify_proof(interaction_data, proof, expected_root)


# =============================================================================
# Trust Harness — Orchestrates the Three Nodes
# =============================================================================

class TrustHarness:
    """
    Orchestrates Gatekeeper + Proxy + Auditor for complete verification.

    Full three-node verification target: <10ms
    - Gatekeeper: <1ms
    - Proxy: <1ms
    - Auditor: <5ms
    """

    def __init__(self, trust_threshold: int = 0, max_budget: int = 4096):
        self.gatekeeper = Gatekeeper(trust_threshold)
        self.proxy = Proxy(max_budget)
        self.auditor = Auditor()

    def register(self, record: PickStateRecord):
        """Register an agent across all three nodes."""
        self.gatekeeper.register_agent(record)
        self.proxy.register_agent(record)
        self.auditor.register_agent(record)

    def verify_and_authorize(self, mini: PickStateMini,
                             required_capabilities: int = 0,
                             required_trust: Optional[int] = None,
                             claimed_history_root: Optional[bytes] = None,
                             claimed_interaction_ct: int = 0
                             ) -> dict:
        """
        Complete three-node verification flow.

        1. Gatekeeper: Identity + trust + replay
        2. Proxy: Capabilities + budget
        3. Auditor: History verification

        Returns combined result dict.
        """
        # Step 1: Gatekeeper
        gate_result = self.gatekeeper.verify(mini, required_trust)
        if not gate_result.allowed:
            return {
                'allowed': False,
                'stage': 'gatekeeper',
                'reason': gate_result.reason,
            }

        # Step 2: Proxy
        proxy_result = self.proxy.authorize(
            gate_result.session_token,
            mini.agent_hash,
            required_capabilities,
        )
        if not proxy_result.authorized:
            return {
                'allowed': False,
                'stage': 'proxy',
                'reason': proxy_result.reason,
            }

        # Step 3: Auditor
        if claimed_history_root:
            audit_result = self.auditor.verify_history(
                mini.agent_hash,
                claimed_history_root,
                claimed_interaction_ct,
            )
            if not audit_result.verified:
                return {
                    'allowed': False,
                    'stage': 'auditor',
                    'reason': audit_result.reason,
                }
        else:
            audit_result = AuditResult(verified=True)

        return {
            'allowed': True,
            'session_token': gate_result.session_token,
            'trust_tier': gate_result.trust_tier,
            'allocated_budget': proxy_result.allocated_budget,
            'capabilities': proxy_result.capabilities,
            'is_new_agent': audit_result.is_new,
        }

    def record_interaction(self, agent_a_hash: bytes, agent_b_hash: bytes,
                           interaction_type: int, outcome: int,
                           context_hash: bytes) -> bytes:
        """Record a completed interaction. Returns new history root for agent A."""
        interaction = InteractionLeaf(
            timestamp=now_ms(),
            partner_hash=agent_b_hash,
            interaction_type=interaction_type,
            outcome=outcome,
            context_hash=context_hash,
        )
        return self.auditor.log_interaction(agent_a_hash, agent_b_hash, interaction)
