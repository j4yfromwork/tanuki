"""Tests for the Burp/raw HTTP request parser (HTTPRequest).

A JWT in a request lives in exactly one of three places — an Authorization-style
header, a specific cookie, or a JSON body. The parser must find it, remember
where, and swap it there (and only there) when replaying.
"""
from tanuki import HTTPRequest, parse_request_file, encode_segment

OLD = (
    encode_segment({"alg": "RS256", "typ": "JWT", "kid": "key-1"})
    + "."
    + encode_segment({"sub": "wiener", "role": "user"})
    + ".OLDSIG"
)
NEW = (
    encode_segment({"alg": "none", "typ": "JWT"})
    + "."
    + encode_segment({"sub": "wiener", "role": "admin"})
    + "."
)


def test_token_in_authorization_header():
    raw = (
        "GET /api/me HTTP/1.1\r\n"
        "Host: api.target.com\r\n"
        f"Authorization: Bearer {OLD}\r\n"
        "Accept: application/json\r\n"
        "\r\n"
    )
    req = HTTPRequest(raw)
    assert req.token_location[0] == "header"
    assert req.token_value == OLD
    assert req.method == "GET"
    assert req.host == "api.target.com"

    headers, body, cookies = req.with_token(NEW)
    assert headers["Authorization"] == f"Bearer {NEW}"
    assert headers["Accept"] == "application/json"  # untouched
    assert cookies == {}
    assert body == ""


def test_token_in_specific_cookie_siblings_survive():
    raw = (
        "GET /dashboard HTTP/1.1\r\n"
        "Host: api.target.com\r\n"
        f"Cookie: theme=dark; session={OLD}; csrf=abc123\r\n"
        "\r\n"
    )
    req = HTTPRequest(raw)
    assert req.token_location == ("cookie", "session")
    assert req.token_value == OLD

    headers, body, cookies = req.with_token(NEW)
    # the JWT-bearing cookie is swapped ...
    assert cookies["session"] == NEW
    # ... and the sibling cookies are preserved untouched
    assert cookies["theme"] == "dark"
    assert cookies["csrf"] == "abc123"
    # the token must not leak into a header
    assert "Authorization" not in headers


def test_token_in_json_body():
    body_json = '{"token":"%s","remember":true}' % OLD
    raw = (
        "POST /api/refresh HTTP/1.1\r\n"
        "Host: api.target.com\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body_json)}\r\n"
        "\r\n"
        f"{body_json}"
    )
    req = HTTPRequest(raw)
    assert req.token_location == ("body", None)
    assert req.token_value == OLD
    assert req.method == "POST"

    headers, body, cookies = req.with_token(NEW)
    assert NEW in body
    assert OLD not in body
    assert '"remember":true' in body  # rest of the body intact
    # Content-Length is dropped so requests recomputes it
    assert "Content-Length" not in headers


def test_header_precedence_over_cookie_and_body():
    # when a JWT appears in several places, the header wins (first located)
    raw = (
        "POST /x HTTP/1.1\r\n"
        "Host: h\r\n"
        f"Authorization: Bearer {OLD}\r\n"
        f"Cookie: session={OLD}\r\n"
        "\r\n"
        f'{{"token":"{OLD}"}}'
    )
    req = HTTPRequest(raw)
    assert req.token_location[0] == "header"


def test_parse_request_file(tmp_path):
    p = tmp_path / "req.txt"
    p.write_text(
        "GET /api/me HTTP/1.1\n"
        "Host: api.target.com\n"
        f"Authorization: Bearer {OLD}\n"
        "\n"
    )
    req = parse_request_file(str(p))
    assert req.token_value == OLD
    assert req.url == "https://api.target.com/api/me"


def test_force_http_scheme(tmp_path):
    p = tmp_path / "req.txt"
    p.write_text(
        "GET /api/me HTTP/1.1\n"
        "Host: 127.0.0.1:5000\n"
        f"Authorization: Bearer {OLD}\n"
        "\n"
    )
    req = parse_request_file(str(p), force_https=False)
    assert req.url == "http://127.0.0.1:5000/api/me"
