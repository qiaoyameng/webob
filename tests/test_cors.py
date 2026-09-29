import pytest

from webob import Request, Response
from webob.cors import CORSMiddleware, CORSPolicy
from webob.exc import HTTPInternalServerError

API_POLICY = CORSPolicy(
    allow_origins=("https://a.example", "https://b.example"),
    allow_methods=("GET", "POST"),
    allow_headers=("Content-Type", "X-Token"),
    expose_headers=("X-Result",),
    allow_credentials=True,
    max_age=600,
)

PUBLIC_POLICY = CORSPolicy(
    allow_origins=("*",),
    allow_methods=("GET",),
    expose_headers=("X-Public",),
    max_age=3600,
)

NULL_POLICY = CORSPolicy(
    allow_origins=("null",),
    allow_methods=("GET",),
)


def make_app(body="hello", headers=None, exc=None):
    def app(environ, start_response):
        app.calls.append(environ)
        if exc is not None:
            raise exc
        resp = Response(body)
        for name, value in (headers or {}).items():
            resp.headers[name] = value
        return resp(environ, start_response)

    app.calls = []
    return app


def make_middleware(app=None, **kwargs):
    if app is None:
        app = make_app()
    policies = [
        ("/api", API_POLICY),
        ("/api/open", PUBLIC_POLICY),
        ("/public", PUBLIC_POLICY),
        ("/opaque", NULL_POLICY),
    ]
    return CORSMiddleware(app, policies=policies, **kwargs), app


def do_request(mw, path, method="GET", origin=None, headers=None):
    req_headers = {}
    if origin is not None:
        req_headers["Origin"] = origin
    req_headers.update(headers or {})
    req = Request.blank(path, method=method, headers=req_headers)
    return req.get_response(mw)


def do_preflight(mw, path, origin, req_method="GET", req_headers=None):
    headers = {"Access-Control-Request-Method": req_method}
    if req_headers is not None:
        headers["Access-Control-Request-Headers"] = req_headers
    return do_request(mw, path, method="OPTIONS", origin=origin,
                      headers=headers)


def vary_entries(resp):
    return {v.strip().lower() for v in resp.headers["Vary"].split(",")}


class TestPolicySelection:
    def test_longest_prefix_wins(self):
        mw, _ = make_middleware()
        resp = do_request(mw, "/api/open/data", origin="https://x.example")
        # /api/open uses the public wildcard policy, not the API policy
        assert resp.headers["Access-Control-Allow-Origin"] == "*"
        assert "Access-Control-Allow-Credentials" not in resp.headers

    def test_shorter_prefix_uses_its_own_policy(self):
        mw, _ = make_middleware()
        resp = do_request(mw, "/api/data", origin="https://a.example")
        assert (
            resp.headers["Access-Control-Allow-Origin"]
            == "https://a.example"
        )
        assert resp.headers["Access-Control-Allow-Credentials"] == "true"

    def test_no_matching_policy_passes_through(self):
        mw, app = make_middleware()
        resp = do_request(mw, "/other", origin="https://a.example")
        assert resp.status_code == 200
        assert "Access-Control-Allow-Origin" not in resp.headers
        assert "Vary" not in resp.headers
        assert len(app.calls) == 1


class TestPreflight:
    def test_allowed_preflight(self):
        mw, app = make_middleware()
        resp = do_preflight(
            mw,
            "/api/data",
            "https://a.example",
            req_method="POST",
            req_headers="Content-Type, X-Token",
        )
        assert resp.status_code == 200
        h = resp.headers
        assert h["Access-Control-Allow-Origin"] == "https://a.example"
        assert h["Access-Control-Allow-Credentials"] == "true"
        assert h["Access-Control-Allow-Methods"] == "GET, POST"
        assert h["Access-Control-Allow-Headers"] == "content-type, x-token"
        assert h["Access-Control-Max-Age"] == "600"
        # preflight never reaches the application
        assert app.calls == []

    def test_preflight_vary_covers_cache_keys(self):
        mw, _ = make_middleware()
        resp = do_preflight(mw, "/api/data", "https://a.example")
        assert vary_entries(resp) == {
            "origin",
            "access-control-request-method",
            "access-control-request-headers",
        }

    def test_preflight_denied_origin(self):
        mw, app = make_middleware()
        resp = do_preflight(mw, "/api/data", "https://evil.example")
        assert resp.status_code == 403
        assert "https://evil.example" in resp.text
        assert "Access-Control-Allow-Origin" not in resp.headers
        assert "origin" in vary_entries(resp)
        assert app.calls == []

    def test_preflight_denied_method(self):
        mw, _ = make_middleware()
        resp = do_preflight(mw, "/api/data", "https://a.example",
                            req_method="DELETE")
        assert resp.status_code == 403
        assert "DELETE" in resp.text
        assert "Access-Control-Allow-Origin" not in resp.headers

    def test_preflight_denied_header(self):
        mw, _ = make_middleware()
        resp = do_preflight(
            mw,
            "/api/data",
            "https://a.example",
            req_method="POST",
            req_headers="Content-Type, X-Other",
        )
        assert resp.status_code == 403
        assert "x-other" in resp.text
        assert "Access-Control-Allow-Origin" not in resp.headers

    def test_public_preflight_wildcard(self):
        mw, _ = make_middleware()
        resp = do_preflight(mw, "/public/item", "https://anything.example")
        assert resp.status_code == 200
        assert resp.headers["Access-Control-Allow-Origin"] == "*"
        assert "Access-Control-Allow-Credentials" not in resp.headers
        assert resp.headers["Access-Control-Max-Age"] == "3600"

    def test_credentials_never_wildcard(self):
        policy = CORSPolicy(
            allow_origins=("*",),
            allow_methods=("GET",),
            allow_credentials=True,
        )
        mw = CORSMiddleware(make_app(), policies=[("/", policy)])
        resp = do_preflight(mw, "/thing", "https://a.example")
        assert resp.headers["Access-Control-Allow-Origin"] == (
            "https://a.example"
        )
        assert resp.headers["Access-Control-Allow-Credentials"] == "true"

    def test_plain_options_is_not_preflight(self):
        mw, app = make_middleware()
        resp = do_request(mw, "/api/data", method="OPTIONS",
                          origin="https://a.example")
        assert len(app.calls) == 1
        assert resp.status_code == 200


class TestActualRequest:
    def test_expose_headers_added(self):
        mw, _ = make_middleware()
        resp = do_request(mw, "/api/data", origin="https://a.example")
        h = resp.headers
        assert h["Access-Control-Allow-Origin"] == "https://a.example"
        assert h["Access-Control-Allow-Credentials"] == "true"
        assert h["Access-Control-Expose-Headers"] == "X-Result"

    def test_public_actual_request(self):
        mw, _ = make_middleware()
        resp = do_request(mw, "/public/item", origin="https://any.example")
        h = resp.headers
        assert h["Access-Control-Allow-Origin"] == "*"
        assert h["Access-Control-Expose-Headers"] == "X-Public"
        assert "Access-Control-Allow-Credentials" not in h

    def test_disallowed_origin_gets_no_cors_headers(self):
        mw, app = make_middleware()
        resp = do_request(mw, "/api/data", origin="https://evil.example")
        assert resp.status_code == 200
        assert len(app.calls) == 1
        assert "Access-Control-Allow-Origin" not in resp.headers
        assert "origin" in vary_entries(resp)

    def test_no_origin_request(self):
        mw, _ = make_middleware()
        resp = do_request(mw, "/api/data")
        assert resp.status_code == 200
        assert "Access-Control-Allow-Origin" not in resp.headers
        # response still depends on Origin, so caches must know
        assert "origin" in vary_entries(resp)


class TestOriginEdgeCases:
    def test_null_origin_denied_unless_listed(self):
        mw, _ = make_middleware()
        resp = do_preflight(mw, "/api/data", "null")
        assert resp.status_code == 403
        resp = do_request(mw, "/api/data", origin="null")
        assert "Access-Control-Allow-Origin" not in resp.headers

    def test_null_origin_allowed_when_listed(self):
        mw, _ = make_middleware()
        resp = do_request(mw, "/opaque/data", origin="null")
        assert resp.headers["Access-Control-Allow-Origin"] == "null"
        resp = do_preflight(mw, "/opaque/data", "null")
        assert resp.status_code == 200
        assert resp.headers["Access-Control-Allow-Origin"] == "null"

    @pytest.mark.parametrize(
        "raw_origin",
        [
            "https://a.example, https://b.example",
            "https://a.example https://b.example",
            "null null",
        ],
    )
    def test_duplicate_origin_rejected(self, raw_origin):
        mw, app = make_middleware()
        req = Request.blank("/api/data")
        req.environ["HTTP_ORIGIN"] = raw_origin
        resp = req.get_response(mw)
        assert resp.status_code == 400
        assert app.calls == []

    @pytest.mark.parametrize(
        "origin",
        ["https://a.example", "https://a.example:443"],
    )
    def test_default_port_matches(self, origin):
        mw, _ = make_middleware()
        resp = do_request(mw, "/api/data", origin=origin)
        assert "Access-Control-Allow-Origin" in resp.headers

    def test_explicit_default_port_http(self):
        policy = CORSPolicy(allow_origins=("http://c.example",))
        mw = CORSMiddleware(make_app(), policies=[("/", policy)])
        resp = do_request(mw, "/x", origin="http://c.example:80")
        assert "Access-Control-Allow-Origin" in resp.headers

    @pytest.mark.parametrize(
        "origin",
        [
            "https://a.example:8443",
            "http://a.example",
            "https://a.example.evil.example",
            "not-an-origin",
        ],
    )
    def test_similar_origins_do_not_match(self, origin):
        mw, _ = make_middleware()
        resp = do_request(mw, "/api/data", origin=origin)
        assert "Access-Control-Allow-Origin" not in resp.headers


class TestResponseInteraction:
    def test_existing_vary_preserved(self):
        app = make_app(headers={"Vary": "Accept-Encoding"})
        mw, _ = make_middleware(app=app)
        resp = do_request(mw, "/api/data", origin="https://a.example")
        assert vary_entries(resp) == {"accept-encoding", "origin"}

    def test_vary_star_left_alone(self):
        app = make_app(headers={"Vary": "*"})
        mw, _ = make_middleware(app=app)
        resp = do_request(mw, "/api/data", origin="https://a.example")
        assert resp.headers["Vary"] == "*"

    def test_error_response_still_carries_cors_headers(self):
        app = make_app(exc=HTTPInternalServerError(detail="boom"))
        mw, _ = make_middleware(app=app)
        resp = do_request(mw, "/api/data", origin="https://a.example")
        assert resp.status_code == 500
        assert (
            resp.headers["Access-Control-Allow-Origin"]
            == "https://a.example"
        )
        assert "origin" in vary_entries(resp)

    def test_app_cors_headers_not_overwritten(self):
        app = make_app(
            headers={
                "Access-Control-Allow-Origin": "https://app.example",
                "Access-Control-Expose-Headers": "X-App",
            }
        )
        mw, _ = make_middleware(app=app)
        resp = do_request(mw, "/api/data", origin="https://a.example")
        assert (
            resp.headers["Access-Control-Allow-Origin"]
            == "https://app.example"
        )
        assert resp.headers["Access-Control-Expose-Headers"] == "X-App"
        # credentials header from the policy is still merged in
        assert resp.headers["Access-Control-Allow-Credentials"] == "true"


class TestCacheIsolation:
    def test_preflight_responses_are_origin_specific_and_cacheable(self):
        mw, _ = make_middleware()
        resp_a = do_preflight(mw, "/api/data", "https://a.example")
        resp_b = do_preflight(mw, "/api/data", "https://b.example")
        # both cacheable via max-age, but with different payloads
        assert resp_a.headers["Access-Control-Max-Age"] == "600"
        assert resp_b.headers["Access-Control-Max-Age"] == "600"
        assert (
            resp_a.headers["Access-Control-Allow-Origin"]
            != resp_b.headers["Access-Control-Allow-Origin"]
        )
        # Vary: Origin guarantees a shared cache will not serve the
        # response cached for origin A to a request from origin B
        for resp in (resp_a, resp_b):
            assert "origin" in vary_entries(resp)

    def test_actual_responses_are_origin_specific(self):
        mw, _ = make_middleware()
        resp_a = do_request(mw, "/api/data", origin="https://a.example")
        resp_b = do_request(mw, "/api/data", origin="https://b.example")
        assert (
            resp_a.headers["Access-Control-Allow-Origin"]
            == "https://a.example"
        )
        assert (
            resp_b.headers["Access-Control-Allow-Origin"]
            == "https://b.example"
        )
        for resp in (resp_a, resp_b):
            assert "origin" in vary_entries(resp)

    def test_simulated_shared_cache_lookup(self):
        """A cache keyed on (URL, Vary-selected headers) keeps origins
        apart: the entry stored for origin A is never a hit for origin B.
        """
        mw, _ = make_middleware()
        cache = {}

        def cached_preflight(origin):
            key = ("/api/data", origin)
            if key not in cache:
                resp = do_preflight(mw, "/api/data", origin)
                assert "origin" in vary_entries(resp)
                cache[key] = resp
            return cache[key]

        resp_a = cached_preflight("https://a.example")
        resp_b = cached_preflight("https://b.example")
        assert (
            resp_a.headers["Access-Control-Allow-Origin"]
            == "https://a.example"
        )
        assert (
            resp_b.headers["Access-Control-Allow-Origin"]
            == "https://b.example"
        )
        # repeat request from A hits A's entry, never B's
        assert (
            cached_preflight("https://a.example").headers[
                "Access-Control-Allow-Origin"
            ]
            == "https://a.example"
        )
