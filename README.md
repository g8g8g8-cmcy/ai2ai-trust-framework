# AI2AI — Trust Intelligence Platform for AI Agents

**Status: Archived — Specs published for public use and prior art.**  
**Author: Garrett Sextro — Khlong Khlung, Kamphaeng Phet, Thailand**  
**Published: March 2026**

---

## What This Is

AI2AI was designed as commerce infrastructure for AI agents — not a compliance police force.

The model: **Pearson VUE for AI agents.** Administer verification tests. Don't write the rules. Be the neutral testing center that every agent, developer, and regulator can trust.

The positioning: **Bloomberg Terminal for AI agents.** Information hub + matchmaker + testing center. Agents need somewhere to establish identity, prove capability, and find counterparties. This was the architecture for that.

This repository contains the core IP documents produced during development. They are published here to establish prior art, contribute to the emerging AI agent identity ecosystem, and give the community a working foundation to build on.

---

## The Core Problem This Solves

As of early 2026:

- **Stripe cannot distinguish a trustworthy AI agent from a malicious one.** No cryptographic proof of agent identity exists at the payment layer.
- **Google's A2A agent cards have no verification mechanism.** An agent can claim any capability with no proof.
- **80–90% of global AI governance is theater.** Only the EU and China actively enforce AI regulations. Everyone else is writing documents.
- **The Einstein Trust Layer is Salesforce-locked.** No neutral, cross-platform agent trust layer exists.

AI2AI was the architecture for that neutral layer.

---

## What's In This Repo

| Document | Description |
|---|---|
| `agent-verification-card-spec-v1.1.md` | W3C Verifiable Credential spec for AI agent identity cards |
| `trust-tier-framework.md` | Five-tier incentive ladder from Unverified to AAA Trusted |
| `compliance-architecture.md` | ISO 42001 tree mapping to EU AI Act, NIST, and PDPA |
| `gtm-framework.md` | Go-to-market: Bottom-up agent handshake + top-down regulatory |
| `agent-card-schema.json` | Machine-readable agent card JSON schema |

---

## Core Architecture (For Anyone Who Wants to Build This)

Three layers:

1. **Frontend** — Renders from API only. No manual content editing.
2. **Backend (FastAPI)** — Serves research bundles, handles verification API calls.
3. **Ledger (PostgreSQL + pgvector)** — Immutable agent records, audit trail, semantic search.

**Agent handshake model (no scraping):**
- Registry agent carries its own signed Agent Card
- Goes out to sites with `llms.txt` / `agent.json` / A2A endpoints
- Exchanges cards cryptographically
- Writes to ledger as `"Not Enrolled — card received"`
- No burst workers. Runs on a single standard VM.

**Key legal decisions baked into the design:**
- Directory is **opt-in only**
- Use `"Not Enrolled"` not `"Unverified"` — legal distinction that matters
- Directory tracking without consent = GDPR violation
- No fabricated agent counts

---

## Why "Not Enrolled" Not "Unverified"

This is a small thing that matters a lot legally.

"Unverified" implies the platform has assessed the agent and found it lacking. That's a legal liability.

"Not Enrolled" is a factual statement of registry status. The agent hasn't enrolled. No judgment made. This distinction survives defamation and tortious interference arguments.

---

## The Pearson VUE Model Explained

Pearson VUE administers certification exams for hundreds of professional bodies worldwide. They don't write the exams. They don't set the passing scores. They don't decide what skills matter. They run the testing infrastructure neutrally.

AI2AI applied this model to AI agent verification:
- **Regulators** define what compliance means
- **AI2AI** administers the tests that prove compliance
- **Agents** earn verified badges based on test results
- **Companies** query the registry to find agents that meet their requirements

The platform is infrastructure. Not a regulator. Not a judge.

---

## Recommended First Targets (For Anyone Building This)

Priority order based on research through early 2026:

1. **Singapore IMDA** — Most receptive regulator globally. Sandbox-friendly.
2. **Stripe** — Has a real fraud problem with AI agents. Would benefit from cryptographic agent identity.
3. **South Korea MSIT** — Active AI governance with enforcement intent.

---

## The Golden Drawer Insight

The regulatory window for establishing neutral AI agent infrastructure closes around mid-to-late 2026 as the EU AI Act enforcement ramps up and other jurisdictions follow. After that, incumbents define the standard.

The opportunity: embed AI2AI (or something like it) everywhere before the doors lock. Be the mapmaker, not the sheriff.

---

## License

All documents in this repository are published under **Creative Commons CC BY 4.0**.

You are free to use, adapt, and build on this work with attribution.

---

## Contact

Garrett Sextro  
garrettsextro@gmail.com
