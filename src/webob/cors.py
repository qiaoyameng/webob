"""
CORS (Cross-Origin Resource Sharing) support for WSGI applications.

This module provides :class:`CORSPolicy`, a per-resource description of
what cross-origin access is allowed, and :class:`CORSMiddleware`, a WSGI
middleware that applies those policies so that multiple WSGI services can
share a single, consistent CORS implementation.

The middleware:

* answers preflight (``OPTIONS``) requests before they reach the wrapped
  application, validating the ``Origin``, the requested method and the
  requested headers against the policy selected for the resource,
* adds ``Access-Control-Allow-Origin`` / ``Access-Control-Expose-Headers``
  (and friends) to actual responses according to the same policy,
* never emits ``Access-Control-Allow-Origin: *`` together with
  credentials; the concrete origin is reflected instead,
* treats ``null`` origins, duplicated ``Origin`` headers and default
  ports (``:80`` / ``:443``) explicitly,
* merges with, rather than overwrites, ``Vary`` headers and CORS headers
  already set by the wrapped application, and applies CORS headers to
  error responses (including :class:`webob.exc.HTTPException`) as well.

Because responses differ per origin, the middleware always adds ``Origin``
(and for preflights ``Access-Control-Request-Method`` /
``Access-Control-Request-Headers``) to ``Vary`` so that a shared cache
cannot serve one origin's response to another origin.
"""

from urllib.parse import urlsplit

from webob.exc import HTTPException
from webob.request import Request
from webob.response import Response

__all__ = ["CORSPolicy", "CORSMiddleware"]

_DEFAULT_PORTS = {"http": 80, "https": 443}

ALLOW_ORIGIN = "Access-Control-Allow-Origin"
ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials"
ALLOW_METHODS = "Access-Control-Allow-Methods"
ALLOW_HEADERS = "Access-Control-Allow-Headers"
EXPOSE_HEADERS = "Access-Control-Expose-Headers"
MAX_AGE = "Access-Control-Max-Age"
REQUEST_METHOD = "Access-Control-Request-Method"
REQUEST_HEADERS = "Access-Control-Request-Headers"


def normalize_origin(origin):
    """Normalize an origin for comparison.

    Lowercases scheme and host and strips the default port so that
    ``https://example.com:443`` and ``https://example.com`` compare
    equal.  The special origin ``null`` is returned unchanged.  Returns
    ``None`` when the value cannot be parsed as an origin at all.
    """
    if origin is None:
        return None
    origin = origin.strip()
    if origin == "null":
        return "null"
    try:
        parts = urlsplit(origin)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = parts.hostname.lower() if parts.hostname else None
    if not scheme or not host:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        return "%s://%s:%d" % (scheme, host, port)
    return "%s://%s" % (scheme, host)


def parse_origin_header(value):
    """Parse the ``Origin`` request header.

    Returns the single origin, or ``None`` when the header is missing,
    empty, or contains more than one origin (servers fold duplicate
    ``Origin`` headers into a comma-separated value, which is ambiguous
    and therefore rejected).
    """
    if not value:
        return None
    if "," in value:
        return None
    return value.strip() or None


def merge_vary(existing, *values):
    """Merge ``values`` into an existing ``Vary`` header value.

    The existing entries are preserved; a ``Vary: *`` is left untouched
    since it already disables caching for every request header.
    """
    items = []
    if existing:
        items = [item.strip() for item in existing.split(",") if item.strip()]
    lowered = {item.lower() for item in items}
    if "*" in lowered:
        return existing
    for value in values:
        if value.lower() not in lowered:
            items.append(value)
            lowered.add(value.lower())
    return ", ".join(items)


class CORSPolicy:
    """CORS policy for a single resource (or set of resources).

    ``allow_origins`` is a sequence of origins (``scheme://host[:port]``).
    It may contain ``"*"`` to allow any origin, and ``"null"`` to
    explicitly allow the ``null`` origin (sandboxed documents, ``file:``
    URLs, redirects).  Default ports are ignored when matching.

    When ``allow_credentials`` is true the policy never answers with
    ``Access-Control-Allow-Origin: *``; the concrete, allowed origin is
    reflected instead, as required by the CORS protocol.
    """

    def __init__(
        self,
        allow_origins=(),
        allow_methods=("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
        allow_headers=(),
        expose_headers=(),
        allow_credentials=False,
        max_age=None,
    ):
        self.allow_origins = tuple(allow_origins)
        self.allow_methods = tuple(m.upper() for m in allow_methods)
        self.allow_headers = tuple(allow_headers)
        self.expose_headers = tuple(expose_headers)
        self.allow_credentials = bool(allow_credentials)
        self.max_age = max_age
        self._normalized_origins = frozenset(
            normalized
            for normalized in (normalize_origin(o) for o in self.allow_origins)
            if normalized is not None
        )
        self._lowered_headers = frozenset(h.lower() for h in self.allow_headers)

    def allows_any_origin(self):
        return "*" in self.allow_origins

    def allows_any_header(self):
        return "*" in self.allow_headers

    def allowed_origin_value(self, origin):
        """Return the value for ``Access-Control-Allow-Origin``.

        Returns the origin to echo back, ``"*"``, or ``None`` when the
        origin is not allowed by this policy.
        """
        normalized = normalize_origin(origin)
        if normalized is None:
            return None
        if self.allow_credentials:
            # With credentials the wildcard is forbidden by the CORS
            # protocol; reflect the concrete origin only.
            if normalized in self._normalized_origins:
                return origin
            return None
        if self.allows_any_origin():
            return "*"
        if normalized in self._normalized_origins:
            return origin
        return None

    def method_allowed(self, method):
        return method.upper() in self.allow_methods

    def headers_allowed(self, headers):
        """Check a comma-separated ``Access-Control-Request-Headers`` value."""
        if not headers:
            return True
        if self.allows_any_header():
            return True
        requested = [h.strip().lower() for h in headers.split(",")]
        requested = [h for h in requested if h]
        return all(h in self._lowered_headers for h in requested)


class CORSMiddleware:
    """WSGI middleware applying per-resource CORS policies.

    ``policies`` is a sequence of ``(path_prefix, CORSPolicy)`` pairs;
    the longest matching prefix selects the policy for a request.
    Requests that match no prefix are passed through untouched unless a
    ``default_policy`` is given.
    """

    def __init__(self, app, policies, default_policy=None):
        self.app = app
        self.policies = sorted(
            policies, key=lambda item: len(item[0]), reverse=True
        )
        self.default_policy = default_policy

    def select_policy(self, path):
        for prefix, policy in self.policies:
            if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
                return policy
            if prefix == "/" and path.startswith("/"):
                return policy
        return self.default_policy

    def __call__(self, environ, start_response):
        request = Request(environ)
        policy = self.select_policy(request.path)
        if policy is None:
            return self.app(environ, start_response)
        if self._is_preflight(request):
            response = self._handle_preflight(request, policy)
        else:
            response = self._handle_actual(request, policy)
        return response(environ, start_response)

    @staticmethod
    def _is_preflight(request):
        return (
            request.method == "OPTIONS"
            and REQUEST_METHOD in request.headers
            and "Origin" in request.headers
        )

    def _handle_preflight(self, request, policy):
        origin = parse_origin_header(request.headers.get("Origin"))
        if origin is None:
            # Missing or duplicated Origin: the preflight is malformed.
            return Response(
                status=400,
                text="CORS preflight requires exactly one Origin header",
            )
        allowed = policy.allowed_origin_value(origin)
        if allowed is None:
            return Response(
                status=403,
                text="CORS origin %r is not allowed" % origin,
            )
        request_method = request.headers.get(REQUEST_METHOD, "")
        if not policy.method_allowed(request_method):
            return Response(
                status=405,
                text="CORS method %r is not allowed" % request_method,
            )
        request_headers = request.headers.get(REQUEST_HEADERS)
        if not policy.headers_allowed(request_headers):
            return Response(
                status=403,
                text="CORS request headers %r are not allowed"
                % (request_headers,),
            )
        response = Response(status=200)
        response.headers[ALLOW_ORIGIN] = allowed
        if policy.allow_credentials:
            response.headers[ALLOW_CREDENTIALS] = "true"
        response.headers[ALLOW_METHODS] = ", ".join(policy.allow_methods)
        if policy.allows_any_header() and request_headers:
            # Reflect the requested headers; "*" is not usable here when
            # credentials are involved, and echoing is always safe.
            response.headers[ALLOW_HEADERS] = request_headers
        elif policy.allow_headers:
            response.headers[ALLOW_HEADERS] = ", ".join(policy.allow_headers)
        if policy.max_age is not None:
            response.headers[MAX_AGE] = str(int(policy.max_age))
        response.headers["Vary"] = merge_vary(
            response.headers.get("Vary"),
            "Origin",
            REQUEST_METHOD,
            REQUEST_HEADERS,
        )
        return response

    def _handle_actual(self, request, policy):
        try:
            response = request.get_response(self.app)
        except HTTPException as exc:
            # Error responses carry CORS headers too, otherwise the
            # browser hides the real status from the frontend.
            response = exc
        origin = parse_origin_header(request.headers.get("Origin"))
        if origin is None:
            # No origin, or an ambiguous (duplicated) one: no CORS
            # headers are added, so the browser will block the response.
            return response
        allowed = policy.allowed_origin_value(origin)
        if allowed is None:
            return response
        headers = response.headers
        # CORS headers already set by the application win; the
        # middleware only fills in what is missing.
        if ALLOW_ORIGIN not in headers:
            headers[ALLOW_ORIGIN] = allowed
            if policy.allow_credentials:
                headers[ALLOW_CREDENTIALS] = "true"
        if policy.expose_headers and EXPOSE_HEADERS not in headers:
            headers[EXPOSE_HEADERS] = ", ".join(policy.expose_headers)
        headers["Vary"] = merge_vary(headers.get("Vary"), "Origin")
        return response
