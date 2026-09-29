"""CORS (Cross-Origin Resource Sharing) support for WSGI applications.

This module provides :class:`CORSPolicy`, a per-resource description of
which cross-origin access is allowed, and :class:`CORSMiddleware`, a WSGI
middleware that selects a policy based on the request path, answers
preflight (``OPTIONS``) requests before they reach the application, and
decorates actual responses with the appropriate CORS headers.
"""

import re
from urllib.parse import urlsplit

from webob.exc import HTTPBadRequest, HTTPException, HTTPForbidden
from webob.request import Request
from webob.response import Response

__all__ = ["CORSPolicy", "CORSMiddleware"]

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

_ORIGIN_SEPARATOR = re.compile(r"[,\s]+")


def _parse_origin(origin):
    """Normalize an origin to ``(scheme, host, port)``.

    Default ports are filled in so that ``https://a.example`` and
    ``https://a.example:443`` compare equal. Returns ``None`` for values
    that are not valid serialized origins.
    """
    try:
        parts = urlsplit(origin)
        if not parts.scheme or not parts.hostname:
            return None
        port = parts.port
    except ValueError:
        return None
    if port is None:
        port = _DEFAULT_PORTS.get(parts.scheme.lower())
    return (parts.scheme.lower(), parts.hostname.lower(), port)


def _extract_origin(environ):
    """Return the single request origin, ``None``, or raise on duplicates.

    A request carrying more than one ``Origin`` value (whether as repeated
    headers folded together with commas or as a space-separated origin
    list) is ambiguous and must be rejected rather than guessed at.
    """
    raw = environ.get("HTTP_ORIGIN")
    if raw is None:
        return None
    values = [v for v in _ORIGIN_SEPARATOR.split(raw.strip()) if v]
    if not values:
        return None
    if len(values) > 1:
        raise HTTPBadRequest(
            detail="Multiple Origin header values are not allowed"
        )
    return values[0]


def _add_vary(resp, *names):
    """Merge ``names`` into the response ``Vary`` header.

    Existing ``Vary`` entries set by the application are preserved; a
    ``Vary: *`` response is left untouched.
    """
    existing = []
    if "Vary" in resp.headers:
        for value in resp.headers.getall("Vary"):
            existing.extend(v.strip() for v in value.split(",") if v.strip())
    if "*" in existing:
        return
    lowered = {v.lower() for v in existing}
    for name in names:
        if name.lower() not in lowered:
            existing.append(name)
            lowered.add(name.lower())
    if "Vary" in resp.headers:
        del resp.headers["Vary"]
    resp.headers["Vary"] = ", ".join(existing)


class CORSPolicy:
    """Describes the cross-origin access allowed for a resource.

    ``allow_origins`` is a collection of serialized origins. The special
    values ``"*"`` (any origin) and ``"null"`` (opaque origins, e.g.
    sandboxed frames or ``file:`` URLs) are only honored when listed
    explicitly. When ``allow_credentials`` is true the allowing origin is
    always echoed back instead of ``*``, as required by the Fetch spec.
    """

    def __init__(
        self,
        allow_origins=(),
        allow_methods=("GET", "HEAD"),
        allow_headers=(),
        expose_headers=(),
        allow_credentials=False,
        max_age=None,
    ):
        self.allow_origins = frozenset(allow_origins)
        self.allow_methods = frozenset(m.upper() for m in allow_methods)
        self.allow_headers = frozenset(h.lower() for h in allow_headers)
        self.expose_headers = tuple(expose_headers)
        self.allow_credentials = allow_credentials
        self.max_age = max_age
        self._normalized_origins = frozenset(
            parsed
            for parsed in (
                _parse_origin(o)
                for o in self.allow_origins
                if o not in ("*", "null")
            )
            if parsed is not None
        )

    def allows_origin(self, origin):
        if "*" in self.allow_origins:
            return True
        if origin == "null":
            return "null" in self.allow_origins
        parsed = _parse_origin(origin)
        return parsed is not None and parsed in self._normalized_origins

    def allow_origin_value(self, origin):
        """Value to use for ``Access-Control-Allow-Origin``."""
        if "*" in self.allow_origins and not self.allow_credentials:
            return "*"
        return origin


class CORSMiddleware:
    """WSGI middleware applying per-resource CORS policies.

    ``policies`` is a sequence of ``(path_prefix, CORSPolicy)`` pairs; the
    longest matching prefix selects the policy for a request. Resources
    without a matching policy (and no ``default_policy``) are passed
    through untouched.
    """

    def __init__(self, app, policies=(), default_policy=None):
        self.app = app
        self.policies = sorted(
            policies, key=lambda item: len(item[0]), reverse=True
        )
        self.default_policy = default_policy

    def _policy_for(self, path):
        for prefix, policy in self.policies:
            if path.startswith(prefix):
                return policy
        return self.default_policy

    def __call__(self, environ, start_response):
        req = Request(environ)
        policy = self._policy_for(req.path_info)
        if policy is None:
            return self.app(environ, start_response)

        try:
            origin = _extract_origin(environ)
        except HTTPException as exc:
            resp = exc if isinstance(exc, Response) else exc.wsgi_response
            _add_vary(resp, "Origin")
            return resp(environ, start_response)

        if origin is not None and self._is_preflight(req):
            resp = self._handle_preflight(req, policy, origin)
            return resp(environ, start_response)

        try:
            resp = req.get_response(self.app)
        except HTTPException as exc:
            # Error responses must still carry CORS headers so that the
            # browser can expose them to the calling script.
            if isinstance(exc, Response):
                resp = exc
            else:
                resp = exc.wsgi_response

        if origin is not None and policy.allows_origin(origin):
            self._apply_actual(resp, policy, origin)
        # The response varies with the Origin header even when no CORS
        # headers were added, so caches must key on it.
        _add_vary(resp, "Origin")
        return resp(environ, start_response)

    @staticmethod
    def _is_preflight(req):
        return (
            req.method == "OPTIONS"
            and "Access-Control-Request-Method" in req.headers
        )

    def _handle_preflight(self, req, policy, origin):
        if not policy.allows_origin(origin):
            return self._deny("Origin %r is not allowed" % origin)

        method = req.headers["Access-Control-Request-Method"].upper()
        if method not in policy.allow_methods:
            return self._deny(
                "Method %s is not allowed for origin %r" % (method, origin)
            )

        requested = req.headers.get("Access-Control-Request-Headers", "")
        req_headers = [
            h.strip().lower() for h in requested.split(",") if h.strip()
        ]
        rejected = [h for h in req_headers if h not in policy.allow_headers]
        if rejected:
            return self._deny(
                "Headers %s are not allowed for origin %r"
                % (", ".join(rejected), origin)
            )

        resp = Response(status=200)
        resp.headers["Access-Control-Allow-Origin"] = (
            policy.allow_origin_value(origin)
        )
        if policy.allow_credentials:
            resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Methods"] = ", ".join(
            sorted(policy.allow_methods)
        )
        if policy.allow_headers:
            resp.headers["Access-Control-Allow-Headers"] = ", ".join(
                sorted(policy.allow_headers)
            )
        if policy.max_age is not None:
            resp.headers["Access-Control-Max-Age"] = str(policy.max_age)
        _add_vary(
            resp,
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
        )
        return resp

    @staticmethod
    def _deny(detail):
        resp = HTTPForbidden(detail=detail)
        _add_vary(resp, "Origin")
        return resp

    @staticmethod
    def _apply_actual(resp, policy, origin):
        # Headers already set by the application take precedence and are
        # never overwritten.
        headers = resp.headers
        if "Access-Control-Allow-Origin" not in headers:
            headers["Access-Control-Allow-Origin"] = (
                policy.allow_origin_value(origin)
            )
        if (
            policy.allow_credentials
            and "Access-Control-Allow-Credentials" not in headers
        ):
            headers["Access-Control-Allow-Credentials"] = "true"
        if (
            policy.expose_headers
            and "Access-Control-Expose-Headers" not in headers
        ):
            headers["Access-Control-Expose-Headers"] = ", ".join(
                policy.expose_headers
            )
