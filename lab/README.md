# jwt-demo-lab

A deliberately-vulnerable JWT app — the target `tanuki` was built to exercise.

> ⚠ **Intentionally insecure. Localhost only. Do not deploy.**

It exposes two faces over the **same** vulnerable verification code:

- a **JSON API** (`/api/user`, `/api/admin`, `/api/hs256`, `/api/kid`, `/api/secure`
  + the login routes and `/.well-known/jwks.json`) for automated attacks, and
- a **browsable web app** (`/login-page` → `/dashboard` → `/admin-panel`) so the
  privilege escalation can be demoed visually in a browser.

The web frontend is a cosmetic skin: identity is read from the `session` cookie's
JWT using the existing `verify_trusting_alg` (trusts-the-`alg`-header) routine, so a
forged token is honoured there exactly as it is on the API.

## Run it

```bash
make lab      # or: make site   (prints the web-app URL first)
```

- Web app: <http://127.0.0.1:5000/login-page>  — demo account **wiener / peter**
- API index: <http://127.0.0.1:5000/>

There is **no administrator login** — the admin area is reachable *only* by forging
a token. That's the point.

## Browser demo flow (PortSwigger-style privilege escalation)

1. **Log in** at `/login-page` as `wiener / peter`. You land on `/dashboard`.
   The **TOKEN INSPECTOR** (bottom-right, on every page) shows `role: user`.
   `/admin-panel` returns **403 — admin only**.

2. **Forge an admin token** with tanuki in the terminal. Grab the current cookie
   value from the browser (DevTools → Application → Cookies → `session`) and feed it
   back as a token — or just mint one against the API. For example, using key
   confusion against the web route:

   ```bash
   # low-priv token to work from
   TOKEN=$(curl -s -X POST http://127.0.0.1:5000/login \
     -H 'Content-Type: application/json' -d '{"user":"wiener"}' | jq -r .token)

   # forge an admin token and replay it against the web admin panel (cookie auth)
   venv/bin/tanuki "$TOKEN" \
     -u http://127.0.0.1:5000/admin-panel \
     --cookie session \
     --pubkey lab/keys/public.pem \
     --claims role=admin,sub=administrator --http
   ```

   (No public key exposed? Recover it from two tokens with
   `--derive-key <SECOND_TOKEN>` — see the top-level README.)

3. **Swap the cookie.** In DevTools, replace the `session` cookie value with the
   forged admin token and **refresh**. The inspector now reads `role: admin`, and
   `/admin-panel` renders — a user list (wiener, carlos, steve, administrator) with
   Delete buttons.

4. **Delete `carlos`.** The **✅ LAB SOLVED** banner appears (tracked in server
   state), mirroring PortSwigger's solved state.

## Key recovery: algorithm confusion with NO exposed key

The endpoints above expose the RSA public key at `/.well-known/jwks.json`, so
tanuki finds it instantly and never needs its **key-recovery** feature. To
exercise that (the PortSwigger "algorithm confusion, no exposed key" scenario)
there is a separate scenario signed by a **second, hidden** RSA keypair
(`keys/recovery_private.pem` / `recovery_public.pem`) that is **never served** —
not in any JWKS, route, header, or error.

> **Why a separate port?** tanuki's JWKS auto-discovery is *origin-wide*: it
> returns the first RSA key it finds at the origin, regardless of the token's
> `kid`. If this endpoint lived on the main lab (which serves a JWKS), the tool
> would just use the exposed main key and skip recovery. So this scenario runs as
> its **own app on port 5001 with no JWKS**, which makes discovery genuinely fail
> and forces derivation. (tanuki itself is unchanged.)

```bash
make lab-noexposedkey        # serves http://127.0.0.1:5001  (no JWKS)
```

### Demo flow

```bash
# 1. two logins -> two tokens from the SAME hidden key, with different signatures
T1=$(curl -s -X POST http://127.0.0.1:5001/login-noexposedkey \
  -H 'Content-Type: application/json' -d '{"user":"wiener"}' | jq -r .token)
T2=$(curl -s -X POST http://127.0.0.1:5001/login-noexposedkey \
  -H 'Content-Type: application/json' -d '{"user":"wiener"}' | jq -r .token)

# 2. recover the public key from the two signatures, forge, bypass
venv/bin/tanuki "$T1" --derive-key "$T2" \
  -u http://127.0.0.1:5001/api/noexposedkey \
  --cookie session --claims role=admin --http
```

What happens: JWKS discovery **fails** (correct — the key isn't exposed) → tanuki
derives the modulus from the two signatures (`e=3` then `e=65537`; ~30s for a
2048-bit key with `gmpy2`) → forges an admin token → RS256→HS256 confusion with the
recovered key → `403 → 200`, returning `FLAG{no_exposed_key_recovered}`.

| Route (port 5001)                | Purpose                                            |
|----------------------------------|----------------------------------------------------|
| `POST /login-noexposedkey`       | issue an RS256 token from the hidden key (varies each call) |
| `GET /api/noexposedkey`          | trusts-alg verify vs the hidden key; admin-gated   |

## Endpoints (API)

| Endpoint      | Verification                     | Breaks via                   |
|---------------|----------------------------------|------------------------------|
| `/api/user`   | trusts `alg` header              | alg:none, key confusion      |
| `/api/admin`  | trusts `alg` header + admin gate | access bypass (403→200)      |
| `/api/hs256`  | HS256 weak secret                | secret cracking              |
| `/api/kid`    | `kid` selects the key            | alg:none, kid path traversal |
| `/api/secure` | RS256 pinned (PyJWT)             | nothing — secure control     |

Token-issuing routes: `POST /login` (RS256), `POST /login-hs256`, `POST /login-kid`.
Public key: `GET /.well-known/jwks.json`.

## Web routes

| Route                         | Purpose                                                     |
|-------------------------------|-------------------------------------------------------------|
| `GET/POST /login-page`        | login form → sets the `session` cookie → `/dashboard`       |
| `GET /dashboard`              | logged-in user view + live token inspector                  |
| `GET /admin-panel`            | admin area if the token is admin, else **403**              |
| `POST /admin-panel/delete/<user>` | admin-only; deleting `carlos` sets the solved state     |
| `GET /logout`                 | clears the `session` cookie                                 |

Test-support (not vulnerabilities): `GET /_debug/hits`, `GET /_debug/state`,
`POST /_debug/reset`.
