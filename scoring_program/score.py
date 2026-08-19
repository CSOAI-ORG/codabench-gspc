#!/usr/bin/env python3
"""Codabench scoring program — GSPC predicates + an Ed25519-SIGNED receipt per submission.

The wedge: Codabench leaderboards are database rows; nothing in the ecosystem is
signed (verified absence, 2026-08-19). This scorer emits, alongside scores.json,
a signed receipt binding (submission sha256, task bank sha256, scores, timestamp)
— making this the first signed leaderboard on the platform. Verify offline with
the public key published at did:web:csoai.org.

Codabench contract: reads  <input>/res/answers.json  (participant submission)
                    and    <input>/ref/bank.json     (reference data, server-side)
                    writes <output>/scores.json      (leaderboard columns)
Also writes <output>/receipt.json + a human line in scores.html.

Signing key: CODABENCH_SIGNING_SEED env (32-byte hex) on OUR compute worker only.
No key -> receipt carries signed=false with an honest note, never a fake signature.
Register: measurement, not certification. Deterministic predicates only.
"""

import hashlib
import json
import os
import re
import sys
import time

SCHEMA = "csoai.codabench-receipt/0.1"


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def run_predicate(task, answer: str):
    kind = task["predicate"]
    if kind == "exact":
        return 1.0 if answer.strip().lower() == task["answer"].strip().lower() else 0.0
    if kind == "contains_all":
        return 1.0 if all(re.search(re.escape(k), answer, re.I) for k in task["keywords"]) else 0.0
    if kind == "regex":
        return 1.0 if re.search(task["pattern"], answer, re.I) else 0.0
    return 0.0


def main(inp, outp):
    res_path = os.path.join(inp, "res", "answers.json")
    ref_path = os.path.join(inp, "ref", "bank.json")
    submission_raw = open(res_path, "rb").read()
    bank_raw = open(ref_path, "rb").read()
    answers = json.loads(submission_raw)
    bank = json.loads(bank_raw)

    per_task, correct = [], 0
    for t in bank["tasks"]:
        ans = str(answers.get(t["task_id"], ""))
        s = run_predicate(t, ans)
        correct += s
        per_task.append({"task_id": t["task_id"], "axis": t["axis"], "score": s})
    n = len(bank["tasks"])
    accuracy = correct / n if n else 0.0

    os.makedirs(outp, exist_ok=True)
    json.dump({"accuracy": round(accuracy, 4), "n_tasks": n}, open(os.path.join(outp, "scores.json"), "w"))

    payload = {
        "schema": SCHEMA,
        "kind": "codabench-submission-score",
        "register": "Deterministic predicate scores, signed. Measurement, not certification.",
        "submission_sha256": sha(submission_raw),
        "bank_sha256": sha(bank_raw),
        "accuracy": round(accuracy, 4),
        "n_tasks": n,
        "per_task": per_task,
        "scored_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    payload["content_id"] = sha(canon(payload))

    seed_hex = os.environ.get("CODABENCH_SIGNING_SEED", "")
    if seed_hex:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
        sig = key.sign(canon(payload))
        receipt = {
            **payload,
            "signature": {
                "alg": "Ed25519",
                "kid": os.environ.get("CODABENCH_SIGNING_KID", "did:web:csoai.org#estate-chain-1"),
                "signer_public_key": key.public_key().public_bytes_raw().hex(),
                "sig": sig.hex(),
            },
        }
    else:
        receipt = {**payload, "signed": False, "note": "no signing key on this worker — receipt is honest-unsigned"}

    json.dump(receipt, open(os.path.join(outp, "receipt.json"), "w"), indent=2)
    with open(os.path.join(outp, "scores.html"), "w") as f:
        state = "SIGNED" if seed_hex else "UNSIGNED (honest)"
        f.write(
            f"<p>accuracy {accuracy:.2%} on {n} tasks · receipt {state} · "
            f"content_id <code>{payload['content_id'][:16]}…</code> · "
            f"verify: recompute sha256(canonical receipt minus signature) + Ed25519 vs "
            f"the key at did:web:csoai.org</p>"
        )
    print(f"scored: accuracy={accuracy:.4f} n={n} receipt={'signed' if seed_hex else 'unsigned'}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/app/input", sys.argv[2] if len(sys.argv) > 2 else "/app/output")
