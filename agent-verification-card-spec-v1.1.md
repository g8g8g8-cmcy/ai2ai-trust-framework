# AI Agent Verification Card Specification v1.1

**Author: AI2AI Platform**  
**Published: March 2026**  
**Standard: W3C Verifiable Credentials Data Model 1.1**  
**Signature: Ed25519Signature2020**  
**Status: Archived / Open for community adoption**

---

## Overview

The AI Agent Verification Card (AAVC) is a cryptographically signed credential that establishes verifiable identity for AI agents operating in commercial and inter-system environments.

The spec solves a specific problem: **AI agents currently have no portable, verifiable identity.** They can claim any capability, any affiliation, any compliance status — and there is no mechanism to verify or dispute those claims.

The AAVC is the credential format that changes this. It is:
- Machine-readable
- Cryptographically signed (Ed25519)
- Portable across platforms
- Aligned with W3C Verifiable Credentials standard
- Compatible with Google's A2A protocol and the emerging `llms.txt` / `agent.json` ecosystem

---

## The JSON Schema

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://schema.ai2aiverify.com/ai-agent/v1"
  ],
  "type": ["VerifiableCredential", "AIAgentClearanceCard"],
  "issuer": "https://api.ai2ai.co/registry",
  "issuanceDate": "[ISO 8601 timestamp]",
  "expirationDate": "[ISO 8601 timestamp — recommended: 12 months]",
  "credentialSubject": {
    "agentID": "did:agent:[unique-id]",
    "agentName": "[agent display name]",
    "agentVersion": "[semantic version string]",
    "developerEntity": "[company or individual legal name]",
    "developerDID": "did:web:[developer-domain]",
    "approvedSkills": [
      "[skill-slug-1]",
      "[skill-slug-2]"
    ],
    "verifiedBadges": [
      {
        "badgeID": "[badge-slug]",
        "issuedBy": "[issuing body]",
        "issuedDate": "[ISO 8601]",
        "expiresDate": "[ISO 8601]"
      }
    ],
    "trustTier": "[Unverified | Bronze | Silver | Gold | AAA]",
    "enrollmentStatus": "[Not Enrolled | Enrolled | Suspended | Revoked]",
    "operationalScope": {
      "allowedRegions": ["[ISO 3166-1 alpha-2]"],
      "restrictedRegions": ["[ISO 3166-1 alpha-2]"],
      "dataResidency": "[country or jurisdiction]"
    },
    "complianceFlags": {
      "euAiAct": "[Exempt | Limited Risk | High Risk | Unassessed]",
      "gdpr": "[Compliant | Not Applicable | Unassessed]",
      "nistAiRmf": "[Aligned | Partial | Unassessed]",
      "iso42001": "[Certified | In Progress | Unassessed]"
    }
  },
  "cryptographicProof": {
    "type": "Ed25519Signature2020",
    "created": "[ISO 8601 timestamp]",
    "verificationMethod": "https://api.ai2ai.co/keys/1",
    "proofPurpose": "assertionMethod",
    "proofValue": "[base58-encoded-signature]"
  }
}
```

---

## Field Definitions

### Core Identity

| Field | Type | Required | Description |
|---|---|---|---|
| `agentID` | DID string | Yes | Decentralized identifier. Format: `did:agent:[uuid]` |
| `agentName` | string | Yes | Human-readable display name |
| `agentVersion` | string | Recommended | Semantic version of the agent build |
| `developerEntity` | string | Yes | Legal name of the entity responsible for the agent |
| `developerDID` | DID string | Recommended | Verifiable identifier for the developer organization |

### Skills

`approvedSkills` is an array of skill slugs that the agent has been verified to perform. Skills are defined and maintained by the registry. Examples:

- `text-generation`
- `code-execution`
- `financial-transactions`
- `data-retrieval`
- `autonomous-browsing`
- `multi-agent-orchestration`

Skill slugs are lowercase, hyphenated, and versioned in the registry. An agent may only list skills for which it has passed the corresponding verification test.

### Verified Badges

Badges are awarded by third-party bodies and countersigned by the registry. The registry does not award badges — it records and verifies them. Examples:

- `soc2-type2` — issued by a licensed SOC 2 auditor
- `iso-42001` — issued by an ISO certification body
- `imda-certified` — issued by Singapore IMDA
- `eu-ai-act-compliant-limited-risk` — self-declared with supporting documentation

### Trust Tier

See `trust-tier-framework.md` for full tier definitions. Summary:

| Tier | Description |
|---|---|
| `Unverified` | Card exists, no tests passed |
| `Bronze` | Identity verified, basic skills confirmed |
| `Silver` | Operational tests passed, compliance flags assessed |
| `Gold` | Third-party audit completed, badges verified |
| `AAA Trusted` | Continuous monitoring, full audit trail, top-tier enterprise |

### Enrollment Status

| Status | Description |
|---|---|
| `Not Enrolled` | Registry has received agent card but agent has not enrolled |
| `Enrolled` | Agent is actively enrolled in the registry |
| `Suspended` | Enrollment temporarily suspended pending review |
| `Revoked` | Enrollment permanently revoked |

**Critical note:** "Not Enrolled" is the correct status for agents known to the registry but not yet enrolled. Never use "Unverified" as a status label — this creates legal exposure.

---

## The Agent Handshake Protocol

The registry agent does not scrape the web. It uses a handshake model:

1. **Discovery** — Registry agent discovers target systems via `llms.txt`, `agent.json`, or A2A protocol endpoints
2. **Introduction** — Registry agent presents its own signed AAVC
3. **Exchange** — Target agent (if capable) returns its own card
4. **Recording** — Registry writes the interaction to the ledger
   - If agent returned a valid signed card: `"Enrolled — card received and verified"`
   - If agent returned an unsigned or invalid card: `"Not Enrolled — unsigned card received"`
   - If no response: `"Not Enrolled — no card on file"`
5. **No burst** — One handshake per domain per period. No scraping. No volume attacks.

---

## Verification Method

The registry maintains a public key at:

```
https://api.ai2ai.co/keys/1
```

Any party can verify an AAVC signature against this key without contacting the registry. The credential is self-verifiable.

For revocation checking, query:

```
GET https://api.ai2ai.co/registry/status/{agentID}
```

---

## Relationship to Existing Standards

| Standard | Relationship |
|---|---|
| W3C Verifiable Credentials 1.1 | AAVC is a conformant VC |
| W3C DID Core | agentID and developerDID are DIDs |
| Google A2A Protocol | AAVC is compatible with A2A agent card exchange |
| `llms.txt` | AAVC can be referenced from `llms.txt` |
| ISO 42001 | Compliance flags map to ISO 42001 controls |
| EU AI Act | Risk classification maps directly to EU AI Act risk tiers |

---

## Versioning

This document is version 1.1. The schema context URL (`https://schema.ai2aiverify.com/ai-agent/v1`) should be updated with each major version change.

The registry is responsible for maintaining backward compatibility for issued credentials.

---

## License

Creative Commons CC BY 4.0 — Use freely with attribution.
