# Learning Log — Monetrix Audit

## Key Takeaways

### 1. Assumptions are attack surface

Many vulnerabilities are not obvious bugs.
Sometimes the real issue is:
- incorrect assumptions
- broken invariants
- trust placed in external state
- accounting expectations that can drift

---

### 2. Emergency logic deserves deep scrutiny

Emergency systems often bypass normal assumptions.

Questions I practiced asking:
- What validations are skipped?
- Can emergency paths desync accounting?
- Can temporary states become permanent?
- Are invariants preserved during bypass flows?

---

### 3. Encoding logic can hide dangerous edge cases

Important areas:
- truncation
- overflow/underflow
- malformed payloads
- decoding assumptions
- mismatched wire formats

---

### 4. State transitions matter more than isolated functions

Instead of reviewing functions individually, I practiced tracing:
- before state
- transition
- after state

Main question:
"What invariant changed unexpectedly?"

---

### 5. Duplicate/invalid findings still teach valuable lessons

Even rejected findings helped improve:
- precision
- exploit reasoning
- proof construction
- understanding intended behavior
- communication clarity

The process itself improved my auditing skill.