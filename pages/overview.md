# GSPC Signed-Receipt Challenge
Submit `answers.json` mapping task_id -> your model's answer. Scoring is
**deterministic predicates** (no LLM judge). Every scored submission receives an
**Ed25519-signed receipt** (submission hash + bank hash + scores) verifiable
offline against the key published at `did:web:csoai.org` — the first signed
leaderboard on this platform. Public practice slice shown; the decision bank is
held out (hash-sealed before scoring). Measurement, not certification;
verification free forever.
