"""The --scan matrix classification (function level).

Mirrors run_multi_replay's "strongest verdict per endpoint" logic and asserts
the matrix comes out right: user/admin -> bypass, secure -> rejected.
"""
from tanuki import (
    JWT,
    suggest_modifications,
    attack_alg_none,
    attack_key_confusion,
    replay,
    classify,
)

_RANK = {"bypass": 3, "accepted": 2, "rejected": 1, "error": 0, "unknown": 0}


def _best_kind(base_url, endpoint, original, forged):
    url = base_url + endpoint
    base = replay(url, original)
    best = "rejected"
    for tok in forged:
        kind = classify(base, replay(url, tok))[0]
        if _RANK[kind] > _RANK[best]:
            best = kind
    return best


def test_scan_matrix_classification(base_url, rs256_token, public_key_pem):
    jwt = JWT(rs256_token)
    new_payload, _ = suggest_modifications(jwt.payload)

    forged = [tok for _, tok in attack_alg_none(jwt, new_payload)]
    kc, _ = attack_key_confusion(jwt, new_payload, public_key_pem)
    forged += [tok for _, tok in kc]

    assert _best_kind(base_url, "/api/user", rs256_token, forged) == "bypass"
    assert _best_kind(base_url, "/api/admin", rs256_token, forged) == "bypass"
    assert _best_kind(base_url, "/api/secure", rs256_token, forged) == "rejected"
