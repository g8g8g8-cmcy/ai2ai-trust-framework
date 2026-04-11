# PickState Protocol v0.2

## A Memory-Efficient Trust Verification Protocol for AI Agent-to-Agent Communication

**256 bytes.** That's the entire trust record for an AI agent.
Compare to current agent card proposals: 2,000 - 50,000 bytes.

### Core Insight

Modern AI agents face 1970s memory constraints — not in RAM, but in context window tokens and inference cost. The solution is the same one Dick Pick found in 1965: **don't store data, store proofs of data.**

An agent doesn't need another agent's full history. It needs cryptographic proof that the history exists and was verified.

### What This Does

- **256-byte trust record** — fits in a single cache line, ~1/200th the size of A2A agent cards
- **Three-node architecture** — Gatekeeper (identity), Proxy (capability), Auditor (history) — no node holds the full record
- **O(1) capability matching** — single bitwise AND operation
- **O(log n) history verification** — Merkle proofs, ~512 bytes regardless of history size
- **Verification without disclosure** — prove an interaction happened without revealing what was discussed
- **Ed25519 signatures** — fast, small, battle-tested cryptography
- **Trust decay and accumulation** — continuous 0-255 scale, not categorical tiers
- **Replay protection** — session nonces with LRU cache

### Run the Demo

```bash
pip install pynacl
python demo.py
```

PyNaCl is optional — the demo runs without it using placeholder signatures.

### Files

| File | What It Does |
|------|-------------|
| `pickstate_core.py` | Data structures: 256-byte record, PickStateMini, Merkle tree, capability bitfields, trust tiers |
| `pickstate_harness.py` | Three-node trust harness: Gatekeeper, Proxy, Auditor + orchestrator |
| `demo.py` | Working demonstration of the complete protocol |

### The Key Sentence

> "Prove it happened without showing what happened."

Section 5.3 — third-party verification of agent interactions without disclosing content. Uses basic Merkle trees (technology from 1979). No heavy cryptography required. The structure itself creates the privacy boundary.

### Origin

Pick (1965): Don't store redundant data.
Merkle (1979): Trees can prove membership without revealing content.
PickState (2026): These principles solve AI agent trust, verification privacy, and inference cost simultaneously.

### License

CC0 1.0 Universal (Public Domain). Anyone may use, modify, and build upon this work without restriction.

### References

1. Pick, D. (1973). PICK Operating System
2. Google A2A Protocol Specification (2025)
3. Anthropic MCP Specification (2024)
4. W3C Verifiable Credentials Data Model (2022)
5. Merkle, R. (1979). "A Digital Signature Based on a Conventional Encryption Function"
6. Bernstein, D.J. et al. (2012). "High-speed high-security signatures" (Ed25519)
7. KNOW:TECH — "Pick Database" (https://youtu.be/s1zAoweW95c)
8. KNOW:TECH — "Blockchain Centralization" (https://youtu.be/Q521lI56hl8)
9. KNOW:TECH — "Cloud Repatriation" (https://youtu.be/DzOkotpHdX8)
