import pytest

from webob.cors import (
    CORSMiddleware,
    CORSPolicy,
    merge_vary,
    normalize_origin,
    parse_origin_header,
)
from webob.exc import HTTPNotFound
from webob.request import Request
from webob.response import Response

GOOD = "https://good.example"
OTHER = "https://other.example"
EVIL = "https://evil.example"


def make_app(calls, body="ok", headers=None, exc=None):
    def app(environ, start_response):
        calls.append(environ["PATH_INFO"])
        if exc is not None:
            raise exc
        response = Response(text=body)
        if headers:
            for name, value in headers.items():
                response.headers[name] = value
        return response(environ, start_response)

    return app


def make_middleware(calls, **app_kw):
    api_policy = CORSPolicy(
        allow_origins=(GOOD, "null"),
        allow_methods=("GET", "POST"),
        allow_headers=("Content-Type", "X-Token"),
        expose_headers=("X-Request-Id",),
        allow_credentials=True,
        max_age=600,
    )
    public_policy = CORSPolicy(
        allow_origins=("*",),
        allow_methods=("GET",),
        expose_headers=("X-Public",),
        max_age=3600,
    )
    app = make_app(calls, **app_kw)
    return CORSMiddleware(
        app, [("/api", api_policy), ("/public", public_policy)]
    )


def do_request(mw, path, method="GET", headers=None):
    request = Request.blank(path, method=method, headers=headers or {})
    return request.get_response(mw)


def preflight(mw, path, origin, method="POST", request_headers=None):
    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": method,
    }
    if request_headers is not None:
        headers["Access-Control-Request-Headers"] = request_headers
    return do_request(mw, path, method="OPTIONS", headers=headers)


class TestHelpers:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("https://example.com", "https://example.com"),
            ("https://example.com:443", "https://example.com"),
            ("http://example.com:80", "http://example.com"),
            ("http://example.com:8080", "http://example.com:8080"),
            ("HTTPS://EXAMPLE.COM/", "https://example.com"),
            ("null", "null"),
            ("not-an-origin", None),
            ("", None),
            (None, None),
        ],
    )
    def test_normalize_origin(self, value, expected):
        assert normalize_origin(value) == expected

    def test_parse_origin_header_rejects_duplicates(self):
        assert parse_origin_header(None) is None
        assert parse_origin_header("") is None
        assert parse_origin_header(GOOD) == GOOD
        # Servers fold duplicate Origin headers into one comma-joined
        # value; that is ambiguous and must not be honored.
        assert parse_origin_header("%s, %s" % (GOOD, EVIL)) is None

    def test_merge_vary_preserves_existing(self):
        assert merge_vary(None, "Origin") == "Origin"
        assert merge_vary("Accept-Encoding", "Origin") == (
            "Accept-Encoding, Origin"
        )
        assert merge_vary("origin", "Origin") == "origin"
        assert merge_vary("*", "Origin") == "*"


class TestPolicySelection:
    def test_longest_prefix_wins(self):
        calls = []
        mw = make_middleware(calls)
        response = do_request(mw, "/api/data", headers={"Origin": GOOD})
        assert response.headers["Access-Control-Allow-Origin"] == GOOD
        response = do_request(mw, "/public/data", headers={"Origin": GOOD})
        assert response.headers["Access-Control-Allow-Origin"] == "*"

    def test_unmatched_path_passes_through_untouched(self):
        calls = []
        mw = make_middleware(calls)
        response = do_request(mw, "/internal", headers={"Origin": GOOD})
        assert calls == ["/internal"]
        assert "Access-Control-Allow-Origin" not in response.headers
        assert "Vary" not in response.headers

    def test_prefix_does_not_match_partial_segment(self):
        calls = []
        mw = make_middleware(calls)
        response = do_request(mw, "/apix", headers={"Origin": GOOD})
        assert "Access-Control-Allow-Origin" not in response.headers


class TestPreflight:
    def test_successful_preflight_short_circuits_app(self):
        calls = []
        mw = make_middleware(calls)
        response = preflight(
            mw, "/api/data", GOOD, method="POST",
            request_headers="Content-Type, X-Token",
        )
        assert calls == []  # business app never runs
        assert response.status_code == 200
        h = response.headers
        assert h["Access-Control-Allow-Origin"] == GOOD
        assert h["Access-Control-Allow-Credentials"] == "true"
        assert h["Access-Control-Allow-Methods"] == "GET, POST"
        assert h["Access-Control-Allow-Headers"] == "Content-Type, X-Token"
        assert h["Access-Control-Max-Age"] == "600"

    def test_preflight_is_cacheable_but_varies_per_origin(self):
        calls = []
        mw = make_middleware(calls)
        response = preflight(mw, "/api/data", GOOD, method="POST")
        assert response.headers["Access-Control-Max-Age"] == "600"
        vary = {v.strip().lower() for v in response.headers["Vary"].split(",")}
        assert {
            "origin",
            "access-control-request-method",
            "access-control-request-headers",
        } <= vary

    def test_disallowed_origin_is_explicitly_denied(self):
        calls = []
        mw = make_middleware(calls)
        response = preflight(mw, "/api/data", EVIL, method="POST")
        assert calls == []
        assert response.status_code == 403
        assert "Access-Control-Allow-Origin" not in response.headers

    def test_disallowed_method_is_explicitly_denied(self):
        calls = []
        mw = make_middleware(calls)
        response = preflight(mw, "/api/data", GOOD, method="DELETE")
        assert calls == []
        assert response.status_code == 405

    def test_disallowed_header_is_explicitly_denied(self):
        calls = []
        mw = make_middleware(calls)
        response = preflight(
            mw, "/api/data", GOOD, method="POST",
            request_headers="X-Injected",
        )
        assert calls == []
        assert response.status_code == 403

    def test_duplicate_origin_is_rejected(self):
        calls = []
        mw = make_middleware(calls)
        response = preflight(mw, "/api/data", "%s, %s" % (GOOD, EVIL))
        assert calls == []
        assert response.status_code == 400

    def test_default_port_origin_matches(self):
        calls = []
        mw = make_middleware(calls)
        response = preflight(mw, "/api/data", GOOD + ":443", method="POST")
        assert response.status_code == 200
        assert (
            response.headers["Access-Control-Allow-Origin"] == GOOD + ":443"
        )

    def test_null_origin_denied_unless_listed(self):
        calls = []
        mw = make_middleware(calls)
        # /api lists "null" explicitly.
        response = preflight(mw, "/api/data", "null", method="POST")
        assert response.status_code == 200
        assert response.headers["Access-Control-Allow-Origin"] == "null"
        # /public uses the wildcard, which does not cover "null" when
        # credentials are involved; here it is allowed without them.
        response = preflight(mw, "/public/data", "null", method="GET")
        assert response.headers["Access-Control-Allow-Origin"] == "*"

    def test_wildcard_preflight_has_no_credentials(self):
        calls = []
        mw = make_middleware(calls)
        response = preflight(mw, "/public/data", EVIL, method="GET")
        assert response.status_code == 200
        assert response.headers["Access-Control-Allow-Origin"] == "*"
        assert "Access-Control-Allow-Credentials" not in response.headers


class TestActualRequest:
    def test_expose_headers_and_vary_added(self):
        calls = []
        mw = make_middleware(calls)
        response = do_request(mw, "/api/data", headers={"Origin": GOOD})
        h = response.headers
        assert h["Access-Control-Allow-Origin"] == GOOD
        assert h["Access-Control-Allow-Credentials"] == "true"
        assert h["Access-Control-Expose-Headers"] == "X-Request-Id"
        assert "Origin" in h["Vary"]

    def test_credentials_never_combined_with_wildcard(self):
        calls = []
        policy = CORSPolicy(allow_origins=(GOOD, "*"), allow_credentials=True)
        mw = CORSMiddleware(make_app(calls), [("/", policy)])
        response = do_request(mw, "/x", headers={"Origin": GOOD})
        # Even though "*" is listed, credentials force reflection of the
        # concrete origin.
        assert response.headers["Access-Control-Allow-Origin"] == GOOD
        assert response.headers["Access-Control-Allow-Credentials"] == "true"
        response = do_request(mw, "/x", headers={"Origin": EVIL})
        assert "Access-Control-Allow-Origin" not in response.headers

    def test_disallowed_origin_gets_no_cors_headers(self):
        calls = []
        mw = make_middleware(calls)
        response = do_request(mw, "/api/data", headers={"Origin": EVIL})
        assert calls == ["/api/data"]  # actual requests still run
        assert "Access-Control-Allow-Origin" not in response.headers

    def test_duplicate_origin_gets_no_cors_headers(self):
        calls = []
        mw = make_middleware(calls)
        response = do_request(
            mw, "/api/data", headers={"Origin": "%s, %s" % (GOOD, EVIL)}
        )
        assert "Access-Control-Allow-Origin" not in response.headers

    def test_existing_vary_is_merged_not_overwritten(self):
        calls = []
        mw = make_middleware(calls, headers={"Vary": "Accept-Encoding"})
        response = do_request(mw, "/api/data", headers={"Origin": GOOD})
        assert response.headers["Vary"] == "Accept-Encoding, Origin"

    def test_app_set_cors_headers_are_not_overwritten(self):
        calls = []
        mw = make_middleware(
            calls,
            headers={
                "Access-Control-Allow-Origin": "https://app.example",
                "Access-Control-Expose-Headers": "X-App",
            },
        )
        response = do_request(mw, "/api/data", headers={"Origin": GOOD})
        h = response.headers
        assert h["Access-Control-Allow-Origin"] == "https://app.example"
        assert h["Access-Control-Expose-Headers"] == "X-App"
        assert "Access-Control-Allow-Credentials" not in h

    def test_exception_responses_carry_cors_headers(self):
        calls = []
        mw = make_middleware(calls, exc=HTTPNotFound())
        response = do_request(mw, "/api/missing", headers={"Origin": GOOD})
        assert response.status_code == 404
        assert response.headers["Access-Control-Allow-Origin"] == GOOD
        assert "Origin" in response.headers["Vary"]


class NaiveCache:
    """A broken shared cache that keys responses on URL alone."""

    def __init__(self, app):
        self.app = app
        self.store = {}

    def __call__(self, environ, start_response):
        key = (environ["REQUEST_METHOD"], environ["PATH_INFO"])
        if key in self.store:
            status, headers, body = self.store[key]
            start_response(status, headers)
            return [body]
        captured = []

        def capture(status, headers, exc_info=None):
            captured.append((status, headers))

        body = b"".join(self.app(environ, capture))
        self.store[key] = (captured[0][0], captured[0][1], body)
        start_response(*captured[0])
        return [body]


class VaryAwareCache:
    """A shared cache that honors the response's Vary header."""

    def __init__(self, app):
        self.app = app
        self.store = {}
        self.hits = 0

    def __call__(self, environ, start_response):
        key = (environ["REQUEST_METHOD"], environ["PATH_INFO"])
        for vary_pairs, status, headers, body in self.store.get(key, []):
            if all(
                environ.get("HTTP_" + name.upper().replace("-", "_"))
                == value
                for name, value in vary_pairs
            ):
                self.hits += 1
                start_response(status, headers)
                return [body]
        captured = []

        def capture(status, headers, exc_info=None):
            captured.append((status, headers))

        body = b"".join(self.app(environ, capture))
        status, headers = captured[0]
        vary = dict(headers).get("Vary", "")
        vary_pairs = tuple(
            (
                name.strip(),
                environ.get(
                    "HTTP_" + name.strip().upper().replace("-", "_")
                ),
            )
            for name in vary.split(",")
            if name.strip()
        )
        self.store.setdefault(key, []).append(
            (vary_pairs, status, headers, body)
        )
        start_response(status, headers)
        return [body]


def wsgi_request(app, path, method="GET", headers=None):
    request = Request.blank(path, method=method, headers=headers or {})
    return request.get_response(app)


class TestCacheIsolation:
    """Two resource policies + cacheable preflights: prove that one
    origin's cached response is never served to another origin."""

    def setup_method(self, method):
        self.calls = []
        self.mw = make_middleware(self.calls)

    def test_naive_url_cache_would_poison(self):
        # Demonstrates the attack the Vary header defends against: a
        # cache keyed on URL alone serves origin A's preflight to B.
        cached = NaiveCache(self.mw)
        first = preflight(cached, "/api/data", GOOD, method="POST")
        assert first.headers["Access-Control-Allow-Origin"] == GOOD
        poisoned = preflight(cached, "/api/data", EVIL, method="POST")
        # The naive cache replays A's response to B...
        assert poisoned.headers["Access-Control-Allow-Origin"] == GOOD
        # ...which is exactly why the middleware emits Vary: Origin.
        assert "Origin" in first.headers["Vary"]

    def test_vary_aware_cache_isolates_origins(self):
        cached = VaryAwareCache(self.mw)
        response_a = preflight(cached, "/api/data", GOOD, method="POST")
        assert response_a.headers["Access-Control-Allow-Origin"] == GOOD
        # Same URL, different origin: the cached entry must not match.
        response_b = preflight(cached, "/api/data", EVIL, method="POST")
        assert response_b.status_code == 403
        assert "Access-Control-Allow-Origin" not in response_b.headers
        # A second request from origin A is served straight from the
        # cache and is still correct.
        again = preflight(cached, "/api/data", GOOD, method="POST")
        assert again.headers["Access-Control-Allow-Origin"] == GOOD
        assert cached.hits == 1

    def test_actual_responses_isolated_per_origin(self):
        cached = VaryAwareCache(self.mw)
        response_a = wsgi_request(
            cached, "/api/data", headers={"Origin": GOOD}
        )
        assert response_a.headers["Access-Control-Allow-Origin"] == GOOD
        response_b = wsgi_request(
            cached, "/api/data", headers={"Origin": EVIL}
        )
        assert "Access-Control-Allow-Origin" not in response_b.headers
        # Both responses were computed by the middleware; the cache
        # could not confuse them because of Vary: Origin.
        assert cached.hits == 0
        repeat = wsgi_request(cached, "/api/data", headers={"Origin": GOOD})
        assert repeat.headers["Access-Control-Allow-Origin"] == GOOD
        assert cached.hits == 1

    def test_two_policies_do_not_share_cache_entries(self):
        cached = VaryAwareCache(self.mw)
        api = preflight(cached, "/api/data", GOOD, method="POST")
        public = preflight(cached, "/public/data", GOOD, method="GET")
        assert api.headers["Access-Control-Allow-Origin"] == GOOD
        assert api.headers["Access-Control-Max-Age"] == "600"
        assert public.headers["Access-Control-Allow-Origin"] == "*"
        assert public.headers["Access-Control-Max-Age"] == "3600"
