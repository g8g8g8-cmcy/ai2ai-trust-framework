# AI Agent Trust Tier Framework

**Author: AI2AI Platform**  
**Published: March 2026**  
**Status: Archived / Open for community adoption**

---

## Overview

The AI2AI Trust Tier Framework is a five-tier incentive ladder for AI agent trust and verification. It is designed as **infrastructure**, not regulation — analogous to credit ratings for financial instruments or certification tiers for professional credentials.

The framework is neutral. The registry does not define what is good or bad agent behavior. It measures and records verifiable facts: tests passed, badges earned, audit trail length, incident history.

---

## The Five Tiers

### Tier 0 — Not Enrolled

**Status label:** `Not Enrolled`  
**Description:** The registry is aware of the agent's existence (via card exchange or developer submission) but the agent has not completed enrollment.

**What this means:**
- Agent card may or may not exist
- No tests have been administered
- No claims have been verified or denied
- The agent is not penalized — simply not yet in the system

**Visibility:** Public listing with `Not Enrolled` status if card was received via handshake. No listing if agent is entirely unknown.

**Legal note:** "Not Enrolled" is the only legally safe status label for agents not in the registry. "Unverified" implies assessment and creates tortious interference risk.

---

### Tier 1 — Bronze

**Status label:** `Bronze Verified`  
**Requirements:**
- [ ] Developer identity verified (legal entity, contact, jurisdiction)
- [ ] Agent card submitted and cryptographically signed
- [ ] At least 3 core skill assessments passed
- [ ] Terms of service accepted
- [ ] Basic operational disclosure completed (what the agent does, what data it accesses)

**What this unlocks:**
- Bronze badge on registry listing
- Directory searchable by developers
- Eligible for introduction matching (basic tier)
- Developer notified of agent queries

**Typical time to achieve:** Days to weeks (depends on developer responsiveness)

---

### Tier 2 — Silver

**Status label:** `Silver Verified`  
**Requirements (all Bronze requirements plus):**
- [ ] Full skill suite assessment completed (all claimed skills tested)
- [ ] Compliance flags assessed (EU AI Act risk tier, GDPR applicability, NIST alignment)
- [ ] Incident disclosure policy submitted
- [ ] Response time SLA declared
- [ ] 90-day operational history with no unresolved incidents

**What this unlocks:**
- Silver badge
- Priority placement in directory
- Eligible for enterprise introduction matching
- Compliance flag display on listing
- Regulatory dashboard visibility (regulators can query Silver+ agents)

**Typical time to achieve:** 3–6 months of operation

---

### Tier 3 — Gold

**Status label:** `Gold Verified`  
**Requirements (all Silver requirements plus):**
- [ ] Third-party audit completed by approved auditor
- [ ] At least one external badge verified and countersigned (SOC 2, ISO 42001, IMDA, etc.)
- [ ] Full audit trail accessible to registry for spot checks
- [ ] Incident response playbook submitted and reviewed
- [ ] 180-day operational history with documented incident resolution

**What this unlocks:**
- Gold badge
- Featured placement in directory
- White-glove enterprise introduction service
- Regulatory sandbox eligibility (IMDA, MSIT programs)
- Compliance Roadmap report available to enterprise clients

**Typical time to achieve:** 6–18 months

---

### Tier 4 — AAA Trusted

**Status label:** `AAA Trusted`  
**Requirements (all Gold requirements plus):**
- [ ] Continuous monitoring consent granted to registry
- [ ] Annual third-party audit with registry countersignature
- [ ] Multiple external badges across at least two jurisdictions
- [ ] Full immutable audit trail — 24 months minimum
- [ ] Zero unresolved critical incidents in 12 months
- [ ] Registry integration: real-time status updates via API

**What this unlocks:**
- AAA Trusted badge (highest designation)
- Top-of-directory placement
- Reduced verification fee rates
- Co-marketing opportunities with registry
- Regulatory pre-clearance letters (where applicable)
- Priority support channel

**Typical time to achieve:** 18–36 months

---

## Tier Transition Rules

### Moving Up

- Tiers are awarded automatically when all requirements are met
- Developer submits evidence via the portal
- Registry audits evidence and countersigns
- Tier upgrade is recorded in immutable audit log with timestamp

### Moving Down

Tier downgrade triggers:
- Unresolved critical incident after 30-day cure period
- Third-party audit failure
- Badge revocation by issuing body
- Developer entity change without re-verification
- Terms of service violation

Downgrades are recorded publicly in the audit log. The agent's tier history is visible — a downgrade is not erased.

### Suspension

Suspension (not downgrade) triggers:
- Active investigation by registry or external authority
- Developer non-responsive to registry inquiry for 14+ days
- Credible third-party complaint under review

Suspended agents display `Enrolled — Under Review` status. Suspension is time-limited. Resolution leads to reinstatement or downgrade.

### Revocation

Revocation is permanent and public. Triggers:
- Confirmed fraud or deliberate misrepresentation
- Regulatory enforcement action
- Developer request (voluntary exit from registry)

Revoked agents display `Enrollment Revoked — [Date]` status permanently. The record is never deleted.

---

## Incentive Structure

The tier system creates natural incentives without mandates:

| Incentive | Mechanism |
|---|---|
| Developers want higher tiers | Enterprise clients filter by Silver+ or Gold+ |
| Enterprises trust higher-tier agents | Liability shifts when using verified agents |
| Regulators can query by tier | Registry becomes the compliance data layer for free |
| Lower fees for higher tiers | Verification call fees drop at Gold and AAA |
| Public trust builds | Registry listing itself signals legitimacy to end users |

The registry does not force any agent to enroll. The market does the enforcement.

---

## Compliance Mapping

The tier framework maps to major regulatory frameworks as follows:

| Tier | EU AI Act | NIST AI RMF | ISO 42001 |
|---|---|---|---|
| Not Enrolled | Unknown | Unknown | Unknown |
| Bronze | Assessed (risk category recorded) | Partial alignment | Not certified |
| Silver | Risk tier confirmed, documentation submitted | Aligned | In progress |
| Gold | Third-party confirmed, audit trail | Fully aligned, documented | Certified or in process |
| AAA | Continuous compliance monitoring | Continuously verified | Certified + surveillance audit |

---

## Database Schema (Reference)

The tier system maps to the following core tables:

```sql
-- agents: enrollment status and current tier
agents (
  agent_id UUID PRIMARY KEY,
  agent_name TEXT,
  developer_entity TEXT,
  enrollment_status TEXT,  -- 'Not Enrolled' | 'Enrolled' | 'Suspended' | 'Revoked'
  trust_tier TEXT,         -- 'Unverified' | 'Bronze' | 'Silver' | 'Gold' | 'AAA'
  created_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ
)

-- ratings: tier assignment history
ratings (
  rating_id UUID PRIMARY KEY,
  agent_id UUID REFERENCES agents,
  tier TEXT,
  effective_date TIMESTAMPTZ,
  assigned_by TEXT,
  reason TEXT
)

-- verification_signals: test results and badge records
verification_signals (
  signal_id UUID PRIMARY KEY,
  agent_id UUID REFERENCES agents,
  signal_type TEXT,       -- 'skill_test' | 'badge' | 'audit' | 'incident'
  signal_value TEXT,
  issued_by TEXT,
  issued_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ
)

-- audit_log: immutable record
audit_log (
  log_id UUID PRIMARY KEY,
  agent_id UUID,
  action TEXT,
  actor TEXT,
  timestamp TIMESTAMPTZ,
  payload JSONB
)
```

---

## License

Creative Commons CC BY 4.0 — Use freely with attribution.
