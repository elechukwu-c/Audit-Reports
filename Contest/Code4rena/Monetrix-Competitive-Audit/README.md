# Monetrix Competitive Audit

My first public smart contract security contest participation.

This repository contains:
- personal research notes
- attack-surface mapping
- protocol understanding
- auditing workflow practice
- lessons learned during review

⚠️ Important:
To respect responsible disclosure and ongoing judging/mitigation processes, this repository intentionally excludes:
- exploit details
- proof-of-concepts (PoCs)
- unpatched vulnerability writeups
- sensitive attack paths
- undisclosed findings

Detailed reports and retrospective analysis may be published after the contest and mitigation process are fully completed.

---

## Focus Areas Explored

During this review, I explored and practiced analysis around:

- accounting assumptions
- encoding/decoding logic
- settlement flows
- access control paths
- emergency execution logic
- precision and rounding behavior
- state transition invariants
- trust boundaries
- privileged role interactions
- protocol solvency assumptions

---

## Methodology Used

My workflow during the contest included:

1. Protocol architecture mapping
2. Flow tracing across critical paths
3. State invariant analysis
4. Trust assumption verification
5. Adversarial thinking ("attacker lens")
6. Edge-case exploration
7. Differential reasoning between expected vs actual behavior
8. Writing structured vulnerability hypotheses
9. Building mental exploit paths before implementation

---

## What I Learned

This contest helped me improve:
- protocol comprehension speed
- threat modeling
- invariant thinking
- smart contract tracing
- identifying hidden assumptions
- structured reporting
- distinguishing impact from root cause

It also showed me the importance of:
- precision in vulnerability claims
- proving exploitability clearly
- understanding protocol intent deeply
- responsible disclosure practices

---

## Tools & Workflow

Examples of tools and techniques practiced:
- Foundry
- Solidity tracing
- manual code review
- grep/ripgrep (`rg`)
- invariant reasoning
- flow decomposition
- state transition analysis

---

## Status

Contest grading and mitigation are still ongoing.

Additional sanitized educational materials may be added over time.