# tanuki + jwt-demo-lab

A JWT attack automator (`tanuki`) and a deliberately-vulnerable Flask target
(`lab/`) it was built to exercise, packaged together with an automated pytest
suite.

**Authorised security testing / CTF / lab use only.** The lab under `lab/` is
intentionally insecure and must only ever run on localhost.

---

## Layout

```
.
├── tanuki/            # the tool — an installable package (console script: `tanuki`)
│   ├── tanuki.py      #   the whole tool, one self-contained file (drop it on a box as-is)
│   ├── __init__.py      #   thin wrapper re-exporting the API for `import tanuki`
│   └── __main__.py      #   enables `python -m tanuki`
├── lab/                 # the deliberately-vulnerable Flask app (the target)
│   ├── app.py
│   └── targets.txt      #   endpoint list for `--scan`
├── tests/               # pytest suite (+ fixtures, tiny wordlist, lab launcher)
│   └── data/wordlist.txt
├── examples/            # sample Burp request / scan files
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
├── Makefile
└── README.md
```

`tanuki/tanuki.py` is deliberately kept as a single self-contained file: a
pentester can copy just that one file onto a target box and run
`python3 tanuki.py <TOKEN> ...` with no install. The package around it only
adds a `pip install`-able wrapper, a `tanuki` console entry point, and an
import surface for the tests.

---

## Quick start (Kali)

Python on Kali is externally managed (PEP 668), so everything lives in a venv.

```bash
make venv      # python3 -m venv venv
make install   # deps (incl. gmpy2) + editable install; verifies the gmpy2 fast path
make test      # run the suite
```

Run the lab on its own (localhost:5000):

```bash
make lab
```

### gmpy2 (the key-recovery accelerator)

`gmpy2` is a declared dependency (in `requirements.txt`), so `make install` pulls
it in. It accelerates RSA key recovery (`--derive-key`) — a 2048-bit `e=65537`
recovery takes **~30s with gmpy2 vs ~hours without**. PyPI ships manylinux wheels
that bundle GMP/MPFR/MPC, so `pip install` normally needs no system packages. If
pip has to build it from source (no wheel for your platform), `make install`
automatically runs `make deps` to `apt-get install -y libgmp-dev libmpfr-dev
libmpc-dev`, then retries. If that shell has no root/sudo, it stops with the exact
manual command rather than continuing silently. `make install` ends by importing
gmpy2 and telling you whether the fast path is active.

The single file still runs **without** gmpy2 (`python3 tanuki.py …`): derivation
falls back to pure Python, prints an up-front warning, and is bounded by
`--derive-timeout` so it never hangs.

---

## Using tanuki

```bash
# decode + run every offline attack against a token
venv/bin/tanuki <TOKEN>

# full auto against a live endpoint: JWKS discovery, forge, replay, classify
venv/bin/tanuki <TOKEN> -u http://127.0.0.1:5000/api/admin --http

# multi-endpoint scan -> attack/endpoint matrix
venv/bin/tanuki <TOKEN> --scan lab/targets.txt --http --pubkey lab/keys/public.pem

# passively discover endpoints, then forge + scan them all in one command
venv/bin/tanuki <TOKEN> --discover http://127.0.0.1:5000 --yes

# recon only — print the discovered surface and exit (no token needed)
venv/bin/tanuki --discover http://127.0.0.1:5000 --discover-only

# merge an endpoint list from another tool (ffuf / feroxbuster / gau / …)
venv/bin/tanuki <TOKEN> --url http://127.0.0.1:5000 --import found.txt --yes

# recover the RSA public key from TWO tokens (no --pubkey, no JWKS) then confuse
venv/bin/tanuki <TOKEN> --derive-key <SECOND_TOKEN> -u https://target/api/me
venv/bin/tanuki <TOKEN> --derive-key <SECOND_TOKEN> --derive-only   # just print the PEMs

# PlainJWT-in-JWE (CVE-2026-29000, pac4j-jwt) — UNAUTHENTICATED, no token needed
venv/bin/tanuki --jwe --jwks-url https://target/api/auth/jwks \
    --claims sub=admin,role=ROLE_ADMIN -u https://target/api/dashboard

# jku injection — forge the token AND print a hosting kit for the JWKS
venv/bin/tanuki <TOKEN> --jku-url https://exploit-server/.well-known/jwks.json --claims sub=administrator

# replay against a saved Burp/raw request file (token swapped in place)
venv/bin/tanuki -r examples/example_request.txt --http

# HS256 secret cracking (pick a backend; default auto = hashcat→john→builtin)
venv/bin/tanuki <HS256_TOKEN> -u http://127.0.0.1:5000/api/hs256 --http \
    --cracker builtin -w tests/data/wordlist.txt --claims role=admin
```

Equivalent invocations: `venv/bin/tanuki ...`, `python -m tanuki ...`, or the
raw single file `python tanuki/tanuki.py ...`.

---

## Passive endpoint discovery (`--discover`)

Turns the workflow into one command: **discover endpoints → forge → replay → matrix.**
It is *passive* — no wordlists, no path brute-forcing. It only records routes the
app already advertises:

- `<script src>` bundles and inline scripts on the base page — parsed for
  `fetch()`, `axios.get/post/…`, `$.ajax({url})`, `XMLHttpRequest.open()`, bare
  `/api/…` and `/v1/…` path literals, and same-origin absolute URLs;
- OpenAPI/Swagger docs at the common paths (`/openapi.json`, `/swagger.json`, …) —
  every path + method;
- HAL / JSON:API `href` / `url` / `_links` fields in any JSON seen.

Safety is built in, not optional:

- **Same-origin only** — off-host URLs are listed as *external references* and
  never fetched or scanned.
- **Destructive routes are excluded by default** — anything matching
  `delete/remove/drop/reset/revoke/logout/signout` (or a `DELETE` method) is
  listed under *skipped: destructive* and left out of the auto-scan. Override
  with `--include-destructive`.
- **Templated paths** (`:id`, `{id}`, `${id}`, `<id>`) are collapsed to a safe
  value (`1`) and flagged.
- On a TTY it **asks before scanning**; pass `--yes` for automation.

Related flags: `--discover <url>`, `--discover-only` (recon, prints the grouped
surface and exits; needs no token), `--import <file>` (merge another tool's
endpoint list through the same filter), `--include-destructive`, `-y/--yes`.

## Public-key recovery (`--derive-key`)

For RS256→HS256 key confusion you need the server's RSA public key. When it isn't
exposed (no `--pubkey`, JWKS discovery fails), you can **recover it from two JWTs
signed by the same key**: for an RSA signature `sig^e ≡ m (mod n)` (m is the
PKCS#1 v1.5 EMSA-padded hash), both `sig0^e − m0` and `sig1^e − m1` are multiples
of `n`, so `gcd(...)` yields `n` (a small spurious factor is divided out and each
candidate verified with `pow(sig, e, n) == m`). `e` is tried as 3 then 65537.

- `--derive-key <TOKEN2>` (alias `--second-token`): the second JWT. It triggers
  automatically when the token is RS*, confusion is in scope, no `--pubkey` was
  given and JWKS discovery failed; the recovered key then feeds the **existing**
  key-confusion + replay pipeline. Without a second token you get a clear hint.
- `--derive-only`: print the recovered key as both **PKCS#1** (`BEGIN RSA PUBLIC
  KEY`) and **SPKI/X.509** (`BEGIN PUBLIC KEY`) PEM, and exit.
- `--derive-timeout <secs>` (default **120**, `0` = no limit): abort derivation
  rather than hang, so a demo never stalls. The recovery runs in a child process
  that is killed when the budget is exceeded (a single big-int power is one atomic
  operation a signal can't interrupt mid-flight).

The encoding is hand-rolled pure Python (builtin `pow` for verification, a PKCS#1
v1.5 EMSA padder + a small DER/PEM encoder). The one expensive step — the
**unmodulated** `sig**e`, its subtraction, and the GCD — is accelerated with
[`gmpy2`](https://pypi.org/project/gmpy2/) when present. It can't be a *modular*
pow: the modulus `n` is exactly what we're recovering.

**Performance:** `e=3` is instant at any key size. `e=65537` raises to the
65537th power and GCDs multi-megabit integers:

| key size | `e=65537`, with gmpy2 | `e=65537`, pure Python |
|----------|-----------------------|------------------------|
| 2048-bit | ~30s                  | ~hours                 |

So the supported setup (gmpy2 installed by `make install`) handles the live
2048-bit PortSwigger lab comfortably inside the default 120s timeout. Copied
standalone onto a box without gmpy2, tanuki still works — it warns, uses the
pure-Python path, and the `--derive-timeout` bounds it.

## jku injection + hosting kit (`--jku-url`)

`--jku-url <URL>` forges a token whose `jku` header points the verifier at a JWKS
you host, signed with a freshly generated key (the `kid` in the token header and
the emitted JWKS always match). Alongside the forged token it prints a **hosting
kit** so you can serve the JWKS in any context:

1. **Hosting-form fields** — host the JWKS wherever the target can reach it; if your
   host uses a response form (a VPS hosting form, PortSwigger's exploit server,
   etc.), paste these: *File* (the URL's path, e.g. `/.well-known/jwks.json`),
   *Content-Type* (`application/json`), and *Body* (the JWKS JSON).
2. **Local / standalone server** — a complete self-host runbook: write the JWKS to
   the right path and serve it (`python3 -m http.server`; the port comes from the
   jku URL, or `--jku-port`, default 8000), confirm it's reachable (`curl` the jku
   URL), then fire the attack with the **real forged token** against the real
   target/cookie (from `-u`/`--cookie`). It carries a prominent caveat that this
   path only applies when `--jku-url` is *your* reachable address — if you host via
   a form instead, use option 1.
3. **Reachability reminder** — ngrok / interactsh / foothold options for when the
   target can't reach your IP directly.

The private key is only printed with `--show-private` (the tool signs with it
internally, so you normally don't need it).

## PlainJWT-in-JWE (`--jwe`, CVE-2026-29000)

Catches the **pac4j-jwt `JwtAuthenticator` bypass** (pac4j-jwt < 4.5.9 / 5.7.9 /
6.3.3). When the library decrypts a JWE whose inner token is an unsigned
**PlainJWT** (`alg:none`), `toSignedJWT()` returns null, signature verification is
skipped, and the claims are trusted. tanuki builds an `alg:none` PlainJWT with
attacker claims and wraps it in a **JWE encrypted to the server's RSA public key**,
forging one envelope per `(alg, enc)` combination (the public PoC's confirmed
`RSA-OAEP-256` / `A128GCM` is tried first):

- key management (`alg`): `RSA-OAEP-256`, `RSA-OAEP`, `RSA1_5`
- content encryption (`enc`): `A128GCM`, `A256GCM`, `A128CBC-HS256`, `A256CBC-HS512`

Each JWE is a 5-part compact token (`protected.key.iv.ciphertext.tag`) whose
protected header carries **`cty:"JWT"`** (what makes pac4j parse the plaintext as a
nested JWT and reach the vulnerable path), labelled by combination and fed through
the normal replay/classify pipeline. Built with the `cryptography` library
(RSA-OAEP / PKCS#1v1.5 key-wrap, AES-GCM and AES-CBC+HMAC content encryption) — no
hand-rolled crypto, no new dependency.

**This attack is unauthenticated — it needs no input token.** Given only a public
key and `--claims`, it mints the inner PlainJWT from scratch:

```bash
# no token at all — fetch the key from the JWKS, mint the claims, forge, replay
venv/bin/tanuki --jwe --jwks-url https://target/api/auth/jwks \
    --claims sub=admin,role=ROLE_ADMIN -u https://target/api/dashboard
```

Key sourcing: **`--jwks-url`** (fetch directly from a JWKS endpoint), `--pubkey`
(PEM file), or JWKS auto-discovery at the target origin (the path list includes
`/api/auth/jwks`). When the key comes from a JWKS, its **`kid` is echoed into the
JWE header** (`enc`-use keys are preferred), and the minted PlainJWT gets a default
**`iat` and near-future `exp`** so freshness checks pass — giving the header shape
confirmed against the live lab:
`{"alg":"RSA-OAEP-256","enc":"A128GCM","kid":…,"cty":"JWT"}`.

It also runs **by default whenever an RSA key is available** in a normal token run;
`--jwe` forces it on (and enables the no-token mode), `--no-jwe` suppresses it. With
no RSA key it skips with a clear note.

## The lab endpoints

| Endpoint      | Verification                     | Breaks via                   |
|---------------|----------------------------------|------------------------------|
| `/api/user`   | trusts `alg` header              | alg:none, key confusion      |
| `/api/admin`  | trusts `alg` header + admin gate | access bypass (403→200)      |
| `/api/hs256`  | HS256 weak secret                | secret cracking              |
| `/api/kid`    | `kid` selects the key            | alg:none, kid path traversal |
| `/api/secure` | RS256 pinned (PyJWT)             | nothing — secure control     |

Token-issuing routes: `POST /login` (RS256), `POST /login-hs256`,
`POST /login-kid`. Public key at `GET /.well-known/jwks.json`.

---

## Tests

```bash
make test                 # everything, verbose
venv/bin/pytest -v
venv/bin/pytest -m hashcat # only the hashcat-backed cracking test
venv/bin/pytest -m john    # only the john-backed cracking test
```

The suite boots the lab on a random free port in a session-scoped fixture. The
`hashcat` / `john` cracking tests run only when those binaries are on `PATH`
(gated with `shutil.which`) and skip otherwise, so the suite stays green on any
box. Cracking tests use the tiny `tests/data/wordlist.txt` fixture — they do
**not** need rockyou.

---

## Safety

The code under `lab/` is vulnerable on purpose and exists solely as a target for
`tanuki` in a controlled environment. Do not deploy it. Only test systems you
are authorised to test.
