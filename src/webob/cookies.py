import base64
import binascii
from collections.abc import MutableMapping
from datetime import date, datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
import string
import time
import warnings

from webob.datetime_utils import utcnow
from webob.util import bytes_, text_

__all__ = [
    "Cookie",
    "CookieProfile",
    "SignedCookieProfile",
    "SignedSerializer",
    "JSONSerializer",
    "Base64Serializer",
    "make_cookie",
    "SetCookie",
    "SetCookieAttribute",
    "SetCookieParseError",
    "parse_set_cookie",
    "parse_set_cookies",
]

_marker = object()

# Module flag to handle validation of SameSite attributes
# See the documentation for ``make_cookie`` for more information.
SAMESITE_VALIDATION = True


class RequestCookies(MutableMapping):
    _cache_key = "webob._parsed_cookies"

    def __init__(self, environ):
        self._environ = environ

    @property
    def _cache(self):
        env = self._environ
        header = env.get("HTTP_COOKIE", "")
        cache, cache_header = env.get(self._cache_key, ({}, None))

        if cache_header == header:
            return cache

        def d(b):
            return b.decode("utf8")

        cache = {d(k): d(v) for k, v in parse_cookie(header)}
        env[self._cache_key] = (cache, header)

        return cache

    def _mutate_header(self, name, value):
        header = self._environ.get("HTTP_COOKIE")
        had_header = header is not None
        header = header or ""

        header = header.encode("latin-1")
        bytes_name = bytes_(name, "ascii")

        if value is None:
            replacement = None
        else:
            bytes_val = _value_quote(bytes_(value, "utf-8"))
            replacement = bytes_name + b"=" + bytes_val
        matches = _rx_cookie.finditer(header)
        found = False

        for match in matches:
            start, end = match.span()
            match_name = match.group(1)

            if match_name == bytes_name:
                found = True

                if replacement is None:  # remove value
                    header = header[:start].rstrip(b" ;") + header[end:]
                else:  # replace value
                    header = header[:start] + replacement + header[end:]

                break
        else:
            if replacement is not None:
                if header:
                    header += b"; " + replacement
                else:
                    header = replacement

        if header:
            self._environ["HTTP_COOKIE"] = text_(header, "latin-1")
        elif had_header:
            self._environ["HTTP_COOKIE"] = ""

        return found

    def _valid_cookie_name(self, name):
        if not isinstance(name, str):
            raise TypeError(name, "cookie name must be a string")

        try:
            bytes_cookie_name = bytes_(name, "ascii")
        except UnicodeEncodeError:
            raise TypeError("cookie name must be encodable to ascii")

        if not _valid_cookie_name(bytes_cookie_name):
            raise TypeError("cookie name must be valid according to RFC 6265")

        return name

    def __setitem__(self, name, value):
        name = self._valid_cookie_name(name)

        if not isinstance(value, str):
            raise ValueError(value, "cookie value must be a string")

        self._mutate_header(name, value)

    def __getitem__(self, name):
        return self._cache[name]

    def get(self, name, default=None):
        return self._cache.get(name, default)

    def __delitem__(self, name):
        name = self._valid_cookie_name(name)
        found = self._mutate_header(name, None)

        if not found:
            raise KeyError(name)

    def keys(self):
        return self._cache.keys()

    def values(self):
        return self._cache.values()

    def items(self):
        return self._cache.items()

    def __contains__(self, name):
        return name in self._cache

    def __iter__(self):
        return self._cache.__iter__()

    def __len__(self):
        return len(self._cache)

    def clear(self):
        self._environ["HTTP_COOKIE"] = ""

    def __repr__(self):
        return f"<RequestCookies (dict-like) with values {self._cache!r}>"


class Cookie(dict):
    def __init__(self, input=None):
        if input:
            self.load(input)

    def load(self, data):
        morsel = {}

        for key, val in _parse_cookie(data):
            if key.lower() in _c_keys:
                morsel[key] = val
            else:
                morsel = self.add(key, val)

    def add(self, key, val):
        if not isinstance(key, bytes):
            key = key.encode("ascii", "replace")

        if not _valid_cookie_name(key):
            return {}
        r = Morsel(key, val)
        dict.__setitem__(self, key, r)

        return r

    __setitem__ = add

    def serialize(self, full=True):
        return "; ".join(m.serialize(full) for m in self.values())

    def values(self):
        return [m for _, m in sorted(self.items())]

    __str__ = serialize

    def __repr__(self):
        return "<{}: [{}]>".format(
            self.__class__.__name__,
            ", ".join(map(repr, self.values())),
        )


def _parse_cookie(data):
    data = data.encode("latin-1")

    for key, val in _rx_cookie.findall(data):
        yield key, _unquote(val)


def parse_cookie(data):
    """
    Parse cookies ignoring anything except names and values
    """

    return ((k, v) for k, v in _parse_cookie(data) if _valid_cookie_name(k))


def cookie_property(key, serialize=lambda v: v):
    def fset(self, v):
        self[key] = serialize(v)

    return property(lambda self: self[key], fset)


def serialize_max_age(v):
    if isinstance(v, timedelta):
        v = str(v.seconds + v.days * 24 * 60 * 60)
    elif isinstance(v, int):
        v = str(v)

    return bytes_(v)


def serialize_cookie_date(v):
    if v is None:
        return None
    elif isinstance(v, bytes):
        return v
    elif isinstance(v, str):
        return v.encode("ascii")
    elif isinstance(v, int):
        v = timedelta(seconds=v)

    if isinstance(v, timedelta):
        v = utcnow() + v

    if isinstance(v, datetime):
        # An aware datetime is converted to UTC; a naive one is assumed to
        # already be UTC, which is how WebOb has always treated them.
        if v.tzinfo is not None:
            v = v.astimezone(timezone.utc)
        v = v.timetuple()
    elif isinstance(v, date):
        v = v.timetuple()

    r = time.strftime("%%s, %d-%%s-%Y %H:%M:%S GMT", v)

    return bytes_(r % (weekdays[v[6]], months[v[1]]), "ascii")


def serialize_samesite(v):
    v = bytes_(v)

    if SAMESITE_VALIDATION:
        if v.lower() not in (b"strict", b"lax", b"none"):
            raise ValueError("SameSite must be 'strict', 'lax', or 'none'")

    return v


class Morsel(dict):
    __slots__ = ("name", "value")

    def __init__(self, name, value):
        self.name = bytes_(name, encoding="ascii")
        self.value = bytes_(value, encoding="ascii")
        assert _valid_cookie_name(self.name)
        self.update(dict.fromkeys(_c_keys, None))

    path = cookie_property(b"path")
    domain = cookie_property(b"domain")
    comment = cookie_property(b"comment")
    expires = cookie_property(b"expires", serialize_cookie_date)
    max_age = cookie_property(b"max-age", serialize_max_age)
    httponly = cookie_property(b"httponly", bool)
    secure = cookie_property(b"secure", bool)
    samesite = cookie_property(b"samesite", serialize_samesite)

    def __setitem__(self, k, v):
        k = bytes_(k.lower(), "ascii")

        if k in _c_keys:
            dict.__setitem__(self, k, v)

    def serialize(self, full=True):
        result = []
        add = result.append
        add(self.name + b"=" + _value_quote(self.value))

        if full:
            for k in _c_valkeys:
                v = self[k]

                if v:
                    info = _c_renames[k]
                    name = info["name"]
                    quoter = info["quoter"]
                    add(name + b"=" + quoter(v))
            expires = self[b"expires"]

            if expires:
                add(b"expires=" + expires)

            if self.secure:
                add(b"secure")

            if self.httponly:
                add(b"HttpOnly")

            if self.samesite:
                if not self.secure and self.samesite.lower() == b"none":
                    raise ValueError(
                        "Incompatible cookie attributes: "
                        "when the samesite equals 'none', then the secure must be True"
                    )
                add(b"SameSite=" + self.samesite)

        return text_(b"; ".join(result), "ascii")

    __str__ = serialize

    def __repr__(self):
        return "<{}: {}={!r}>".format(
            self.__class__.__name__,
            text_(self.name),
            text_(self.value),
        )


#
# parsing
#


_re_quoted = r'"(?:\\"|.)*?"'  # any doublequoted string
_legal_special_chars = "~!@#$%^&*()_+=-`.?|:/(){}<>'"
_re_legal_char = r"[\w\d%s]" % re.escape(_legal_special_chars)
_re_expires_val = r"\w{3},\s[\w\d-]{9,11}\s[\d:]{8}\sGMT"
_re_cookie_str_key = r"(%s+?)" % _re_legal_char
_re_cookie_str_equal = r"\s*=\s*"
_re_unquoted_val = r"(?:%s|\\(?:[0-3][0-7][0-7]|.))*" % _re_legal_char
_re_cookie_str_val = rf"({_re_quoted}|{_re_expires_val}|{_re_unquoted_val})"
_re_cookie_str = _re_cookie_str_key + _re_cookie_str_equal + _re_cookie_str_val

_rx_cookie = re.compile(bytes_(_re_cookie_str, "ascii"))
_rx_unquote = re.compile(bytes_(r"\\([0-3][0-7][0-7]|.)", "ascii"))


def _bchr(i):
    return bytes([i])


_ch_unquote_map = {bytes_("%03o" % i): _bchr(i) for i in range(256)}
_ch_unquote_map.update((v, v) for v in list(_ch_unquote_map.values()))

_b_dollar_sign = ord("$")
_b_quote_mark = ord('"')


def _unquote(v):
    # assert isinstance(v, bytes)

    if v and v[0] == v[-1] == _b_quote_mark:
        v = v[1:-1]

    return _rx_unquote.sub(_ch_unquote, v)


def _ch_unquote(m):
    return _ch_unquote_map[m.group(1)]


#
# serializing
#

# these chars can be in cookie value see
# http://tools.ietf.org/html/rfc6265#section-4.1.1 and
# https://github.com/Pylons/webob/pull/104#issuecomment-28044314
#
# ! (0x21), "#$%&'()*+" (0x25-0x2B), "-./0123456789:" (0x2D-0x3A),
# "<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[" (0x3C-0x5B),
# "]^_`abcdefghijklmnopqrstuvwxyz{|}~" (0x5D-0x7E)

_allowed_special_chars = "!#$%&'()*+-./:<=>?@[]^_`{|}~"
_allowed_cookie_chars = string.ascii_letters + string.digits + _allowed_special_chars
_allowed_cookie_bytes = bytes_(_allowed_cookie_chars)

# these are the characters accepted in cookie *names*
# From http://tools.ietf.org/html/rfc2616#section-2.2:
# token          = 1*<any CHAR except CTLs or separators>
# separators     = "(" | ")" | "<" | ">" | "@"
#                | "," | ";" | ":" | "\" | <">
#                | "/" | "[" | "]" | "?" | "="
#                | "{" | "}" | SP | HT
#
# CTL            = <any US-ASCII control character
#                         (octets 0 - 31) and DEL (127)>
#
_valid_token_chars = string.ascii_letters + string.digits + "!#$%&'*+-.^_`|~"
_valid_token_bytes = bytes_(_valid_token_chars)

# this is a map used to escape the values

_escape_noop_chars = _allowed_cookie_chars + " "
_escape_map = {chr(i): "\\%03o" % i for i in range(256)}
_escape_map.update(zip(_escape_noop_chars, _escape_noop_chars))

_escape_map = {ord(k): bytes_(v, "ascii") for k, v in _escape_map.items()}
_escape_char = _escape_map.__getitem__

weekdays = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
months = (
    None,
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)


# This is temporary, until we can remove this from _value_quote
_should_raise = None


def __warn_or_raise(text, warn_class, to_raise, raise_reason):
    if _should_raise:
        raise to_raise(raise_reason)

    else:
        warnings.warn(text, warn_class, stacklevel=2)


def _value_quote(v):
    # This looks scary, but is simple. We remove all valid characters from the
    # string, if we end up with leftovers (string is longer than 0, we have
    # invalid characters in our value)

    leftovers = v.translate(None, _allowed_cookie_bytes)

    if leftovers:
        __warn_or_raise(
            "Cookie value contains invalid bytes: (%r). Future versions "
            "will raise ValueError upon encountering invalid bytes." % (leftovers,),
            RuntimeWarning,
            ValueError,
            "Invalid characters in cookie value",
        )
        # raise ValueError('Invalid characters in cookie value')

        return b'"' + b"".join(map(_escape_char, v)) + b'"'

    return v


def _valid_cookie_name(key):
    return isinstance(key, bytes) and not (
        key.translate(None, _valid_token_bytes)
        # Not explicitly required by RFC6265, may consider removing later:
        or key[0] == _b_dollar_sign
        or key.lower() in _c_keys
    )


def _path_quote(v):
    return b"".join(map(_escape_char, v))


_domain_quote = _path_quote
_max_age_quote = _path_quote

_c_renames = {
    b"path": {"name": b"Path", "quoter": _path_quote},
    b"comment": {"name": b"Comment", "quoter": _value_quote},
    b"domain": {"name": b"Domain", "quoter": _domain_quote},
    b"max-age": {"name": b"Max-Age", "quoter": _max_age_quote},
}
_c_valkeys = sorted(_c_renames)
_c_keys = set(_c_renames)
_c_keys.update([b"expires", b"secure", b"httponly", b"samesite"])


#
# Lossless Set-Cookie parsing and editing
#

# Attributes defined by RFC 6265, plus "comment" from RFC 2965 which WebOb
# has historically supported. Anything else (e.g. "Partitioned", "Priority",
# or site-specific attributes) is treated as an unknown extension.
_KNOWN_SET_COOKIE_ATTRIBUTES = frozenset(
    [
        "comment",
        "domain",
        "expires",
        "httponly",
        "max-age",
        "path",
        "samesite",
        "secure",
    ]
)


class SetCookieParseError(ValueError):
    """Raised when a Set-Cookie header cannot be parsed safely."""


def _check_set_cookie_token(name, what, header):
    if not name:
        raise SetCookieParseError(
            "Invalid Set-Cookie header, %s is empty: %r" % (what, header)
        )

    if any(c not in _valid_token_chars for c in name):
        raise SetCookieParseError(
            "Invalid Set-Cookie header, %s %r contains invalid "
            "characters: %r" % (what, name, header)
        )

    return name


def _reject_ctl_chars(value, what):
    for c in value:
        if ord(c) < 0x20 or ord(c) == 0x7F:
            raise ValueError(
                "%s contains a forbidden control character (%r), refusing "
                "to create a header that could be used for response "
                "splitting" % (what, c)
            )


def _validate_new_attribute_name(name):
    if not isinstance(name, str):
        raise TypeError("attribute name must be a string, not %r" % type(name))

    _reject_ctl_chars(name, "attribute name")

    if not name or any(c not in _valid_token_chars for c in name):
        raise ValueError(
            "Invalid attribute name %r, must be a non-empty RFC 2616 token" % (name,)
        )

    return name


def _validate_new_attribute_value(value):
    if not isinstance(value, str):
        raise TypeError("attribute value must be a string, not %r" % type(value))

    _reject_ctl_chars(value, "attribute value")

    if ";" in value:
        raise ValueError(
            "attribute value %r contains ';', which would break the "
            "structure of the header" % (value,)
        )

    return value


def _quote_set_cookie_value(value):
    if isinstance(value, str):
        _reject_ctl_chars(value, "cookie value")
        value = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray)):
        value = bytes(value)
        if b"\r" in value or b"\n" in value or b"\x00" in value:
            raise ValueError(
                "cookie value contains a forbidden control character, "
                "refusing to create a header that could be used for "
                "response splitting"
            )
    else:
        raise TypeError("cookie value must be a string, not %r" % type(value))

    if not value.translate(None, _allowed_cookie_bytes):
        return value.decode("latin-1")

    return (b'"' + b"".join(map(_escape_char, value)) + b'"').decode("latin-1")


class SetCookieAttribute:
    """
    A single attribute of a ``Set-Cookie`` header.

    ``name`` is the attribute name with its original casing preserved, and
    ``value`` is the attribute value, or ``None`` for flag attributes such
    as ``Secure`` or ``Partitioned``.

    Attributes that are not recognized (see :attr:`known`) keep their
    original text so they round-trip byte-for-byte.
    """

    __slots__ = ("name", "value", "_raw")

    def __init__(self, name, value=None, raw=None):
        self.name = name
        self.value = value
        self._raw = raw

    @property
    def known(self):
        """Whether this attribute is defined by RFC 6265/2965."""

        return self.name.lower() in _KNOWN_SET_COOKIE_ATTRIBUTES

    def serialize(self):
        if self._raw is not None:
            return self._raw

        if self.value is None:
            return "; " + self.name

        return "; {}={}".format(self.name, self.value)

    def __repr__(self):
        if self.value is None:
            return "<{}: {}>".format(self.__class__.__name__, self.name)

        return "<{}: {}={!r}>".format(self.__class__.__name__, self.name, self.value)


class SetCookie:
    """
    A parsed ``Set-Cookie`` header that can be edited losslessly.

    Unlike :class:`Morsel`, this class keeps every attribute of the
    original header, in order, including unknown extension attributes
    (``Partitioned``, ``Priority``, custom attributes, ...) and duplicate
    attributes. Serializing a :class:`SetCookie` reproduces the original
    header byte-for-byte except for the attributes that were explicitly
    modified, which makes it suitable for proxies that need to rewrite a
    single attribute (for example adding ``Secure``) without dropping
    anything else.

    Use :func:`parse_set_cookie` or :func:`parse_set_cookies` to parse
    existing headers, or construct a new cookie directly:

    .. code::

        sc = SetCookie("session", "abc123")
        sc.set("Secure")
        sc.set("Path", "/")
        sc.serialize()  # 'session=abc123; Secure; Path=/'
    """

    def __init__(self, name, value, attributes=()):
        if not isinstance(name, str):
            raise TypeError("cookie name must be a string, not %r" % type(name))

        _reject_ctl_chars(name, "cookie name")

        if not name or any(c not in _valid_token_chars for c in name):
            raise ValueError(
                "Invalid cookie name %r, must be a non-empty RFC 2616 token" % (name,)
            )

        self.name = name
        self._raw_value = ""
        self._raw_pair = None
        self._attributes = list(attributes)
        self.value = value

    @classmethod
    def _from_parsed(cls, name, raw_value, attributes, raw_pair):
        obj = cls.__new__(cls)
        obj.name = name
        obj._raw_value = raw_value
        obj._raw_pair = raw_pair
        obj._attributes = list(attributes)

        return obj

    @property
    def value(self):
        """The cookie value, unquoted and unescaped."""

        raw = self._raw_value.encode("latin-1")

        return _unquote(raw).decode("utf-8", "surrogateescape")

    @value.setter
    def value(self, value):
        raw_value = _quote_set_cookie_value(value)
        self._raw_value = raw_value
        self._raw_pair = None

    @property
    def raw_value(self):
        """The cookie value exactly as it appears on the wire."""

        return self._raw_value

    @property
    def attributes(self):
        """All attributes, in order, including duplicates."""

        return tuple(self._attributes)

    @property
    def known_attributes(self):
        """Attributes defined by RFC 6265/2965, in order."""

        return tuple(a for a in self._attributes if a.known)

    @property
    def extensions(self):
        """Unknown extension attributes, in order."""

        return tuple(a for a in self._attributes if not a.known)

    def get_all(self, name):
        """Return the values of every attribute named ``name``, in order."""

        lname = name.lower()

        return [a.value for a in self._attributes if a.name.lower() == lname]

    def get(self, name, default=None):
        """Return the value of the first attribute named ``name``."""

        values = self.get_all(name)

        return values[0] if values else default

    def has(self, name):
        """Whether an attribute named ``name`` is present."""

        lname = name.lower()

        return any(a.name.lower() == lname for a in self._attributes)

    __contains__ = has

    def set(self, name, value=None):
        """
        Set the attribute ``name`` to ``value``.

        ``value`` may be ``None`` for flag attributes such as ``Secure``.
        If the attribute already exists, only the first occurrence is
        updated, in place; every other attribute keeps its original
        position and text. Otherwise the new attribute is appended.
        """

        name = _validate_new_attribute_name(name)

        if value is not None:
            value = _validate_new_attribute_value(value)

        lname = name.lower()

        for attr in self._attributes:
            if attr.name.lower() == lname:
                attr.value = value
                attr._raw = None

                return

        self._attributes.append(SetCookieAttribute(name, value))

    def remove(self, name):
        """Remove all attributes named ``name``; returns the count removed."""

        lname = name.lower()
        kept = [a for a in self._attributes if a.name.lower() != lname]
        removed = len(self._attributes) - len(kept)
        self._attributes[:] = kept

        return removed

    def __getitem__(self, name):
        values = self.get_all(name)

        if not values:
            raise KeyError(name)

        return values[0]

    def __setitem__(self, name, value):
        self.set(name, value)

    def __delitem__(self, name):
        if not self.remove(name):
            raise KeyError(name)

    def serialize(self):
        if self._raw_pair is not None:
            pair = self._raw_pair
        else:
            pair = "{}={}".format(self.name, self._raw_value)

        result = pair + "".join(a.serialize() for a in self._attributes)

        if "\r" in result or "\n" in result:
            raise ValueError(
                "refusing to serialize a Set-Cookie header containing "
                "CR/LF characters"
            )

        return result

    __str__ = serialize

    def __repr__(self):
        return "<{}: {}={!r}>".format(self.__class__.__name__, self.name, self.value)


def _split_cookie_segments(header):
    # Split a single Set-Cookie header on ';', ignoring semicolons inside
    # double-quoted strings.
    segments = []
    start = 0
    in_quotes = False
    i = 0
    length = len(header)

    while i < length:
        c = header[i]

        if c == "\\" and in_quotes:
            i += 2
            continue

        if c == '"':
            in_quotes = not in_quotes
        elif c == ";" and not in_quotes:
            segments.append(header[start:i])
            start = i + 1

        i += 1

    if in_quotes:
        raise SetCookieParseError(
            "Invalid Set-Cookie header, unterminated quoted string: %r" % (header,)
        )

    segments.append(header[start:])

    return segments


def _split_set_cookie_header(header):
    # Split a combined Set-Cookie header into individual cookies. A comma
    # only starts a new cookie when it is followed by a token and an '='
    # before any ';', so the comma inside an Expires date (e.g.
    # "Expires=Wed, 21 Oct 2015 07:28:00 GMT") is not treated as a cookie
    # separator.
    parts = []
    start = 0
    in_quotes = False
    i = 0
    length = len(header)

    while i < length:
        c = header[i]

        if c == "\\" and in_quotes:
            i += 2
            continue

        if c == '"':
            in_quotes = not in_quotes
        elif c == "," and not in_quotes:
            j = i + 1

            while j < length and header[j] in " \t":
                j += 1

            k = j

            while k < length and header[k] in _valid_token_chars:
                k += 1

            if k > j and k < length and header[k] == "=":
                parts.append(header[start:i])
                start = i + 1

        i += 1

    parts.append(header[start:])

    return [p.strip(" \t") for p in parts if p.strip(" \t")]


def parse_set_cookie(header):
    """
    Parse a single ``Set-Cookie`` header value into a :class:`SetCookie`.

    The result preserves the cookie value, all known attributes, unknown
    extension attributes, and duplicate attributes, in their original
    order, so that ``parse_set_cookie(h).serialize() == h`` for any
    well-formed header ``h``.

    Raises :exc:`SetCookieParseError` with a description of the problem
    when the header is malformed, and refuses headers containing CR/LF
    characters so a parsed header can never be used for response
    splitting.
    """

    if isinstance(header, (bytes, bytearray)):
        header = bytes(header).decode("latin-1")

    if not isinstance(header, str):
        raise TypeError("header must be a string, not %r" % type(header))

    if "\r" in header or "\n" in header:
        raise SetCookieParseError(
            "Invalid Set-Cookie header, contains CR/LF characters, "
            "refusing to parse a potentially injected header: %r" % (header,)
        )

    header = header.strip(" \t")
    segments = _split_cookie_segments(header)
    pair = segments[0]
    name, sep, raw_value = pair.partition("=")

    if not sep:
        raise SetCookieParseError(
            "Invalid Set-Cookie header, expected a name=value pair: %r" % (header,)
        )

    name = _check_set_cookie_token(name.strip(" \t"), "cookie name", header)
    raw_value = raw_value.strip(" \t")
    attributes = []

    for segment in segments[1:]:
        stripped = segment.strip(" \t")

        if not stripped:
            # Tolerate empty segments, e.g. a trailing ';'
            continue

        attr_name, sep, attr_value = stripped.partition("=")
        attr_name = _check_set_cookie_token(
            attr_name.strip(" \t"), "attribute name", header
        )
        attributes.append(
            SetCookieAttribute(
                attr_name,
                attr_value.strip(" \t") if sep else None,
                raw=";" + segment,
            )
        )

    return SetCookie._from_parsed(name, raw_value, attributes, raw_pair=pair)


def parse_set_cookies(header):
    """
    Parse a possibly combined ``Set-Cookie`` header into a list of
    :class:`SetCookie`.

    Commas inside ``Expires`` dates and quoted values are not treated as
    cookie separators. Raises :exc:`SetCookieParseError` for malformed
    input.
    """

    if isinstance(header, (bytes, bytearray)):
        header = bytes(header).decode("latin-1")

    if not isinstance(header, str):
        raise TypeError("header must be a string, not %r" % type(header))

    if "\r" in header or "\n" in header:
        raise SetCookieParseError(
            "Invalid Set-Cookie header, contains CR/LF characters, "
            "refusing to parse a potentially injected header: %r" % (header,)
        )

    return [parse_set_cookie(part) for part in _split_set_cookie_header(header)]


def make_cookie(
    name,
    value,
    max_age=None,
    path="/",
    domain=None,
    secure=False,
    httponly=False,
    comment=None,
    samesite=None,
):
    """
    Generate a cookie value.

    ``name``
      The name of the cookie.

    ``value``
      The ``value`` of the cookie. If it is ``None``, it will generate a cookie
      value with an expiration date in the past.

    ``max_age``
      The maximum age of the cookie used for sessioning (in seconds).
      Default: ``None`` (browser scope).

    ``path``
      The path used for the session cookie. Default: ``/``.

    ``domain``
      The domain used for the session cookie. Default: ``None`` (no domain).

    ``secure``
      The 'secure' flag of the session cookie. Default: ``False``.

    ``httponly``
      Hide the cookie from JavaScript by setting the 'HttpOnly' flag of the
      session cookie. Default: ``False``.

    ``comment``
      Set a comment on the cookie. Default: ``None``

    ``samesite``
      The 'SameSite' attribute of the cookie, can be either ``"strict"``,
      ``"lax"``, ``"none"``, or ``None``. By default, WebOb will validate the
      value to ensure it conforms to the allowable options in the various draft
      RFC's that exist.

      To disable this check and send headers that are experimental or introduced
      in a future RFC, set the module flag ``SAMESITE_VALIDATION`` to a
      false value like:

      .. code::

          import webob.cookies
          webob.cookies.SAMESITE_VALIDATION = False

          ck = webob.cookies.make_cookie(cookie_name, value, samesite='future')

      .. danger::

          This feature has known compatibility issues with various user agents,
          and is not yet an accepted RFC. It is therefore considered
          experimental and subject to change.

          For more information please see :ref:`Experimental: SameSite Cookies
          <samesiteexp>`
    """

    # We are deleting the cookie, override max_age and expires

    if value is None:
        value = b""
        # Note that the max-age value of zero is technically contraspec;
        # RFC6265 says that max-age cannot be zero.  However, all browsers
        # appear to support this to mean "delete immediately".
        # http://www.timwilson.id.au/news-three-critical-problems-with-rfc6265.html
        max_age = 0
        expires = "Wed, 31-Dec-97 23:59:59 GMT"

    # Convert max_age to seconds
    elif isinstance(max_age, timedelta):
        max_age = (max_age.days * 60 * 60 * 24) + max_age.seconds
        expires = max_age
    elif max_age is not None:
        try:
            max_age = int(max_age)
        except ValueError:
            raise ValueError(
                "max_age should be an integer. Amount of seconds until expiration."
            )

        expires = max_age
    else:
        expires = None

    morsel = Morsel(name, value)

    if domain is not None:
        morsel.domain = bytes_(domain)

    if path is not None:
        morsel.path = bytes_(path)

    if httponly:
        morsel.httponly = True

    if secure:
        morsel.secure = True

    if max_age is not None:
        morsel.max_age = max_age

    if expires is not None:
        morsel.expires = expires

    if comment is not None:
        morsel.comment = bytes_(comment)

    if samesite is not None:
        morsel.samesite = samesite

    return morsel.serialize()


class JSONSerializer:
    """A serializer which uses `json.dumps`` and ``json.loads``"""

    def dumps(self, appstruct):
        return bytes_(json.dumps(appstruct), encoding="utf-8")

    def loads(self, bstruct):
        # NB: json.loads raises ValueError if no json object can be decoded
        # so we don't have to do it explicitly here.

        return json.loads(text_(bstruct, encoding="utf-8"))


class Base64Serializer:
    """A serializer which uses base64 to encode/decode data"""

    def __init__(self, serializer=None):
        if serializer is None:
            serializer = JSONSerializer()

        self.serializer = serializer

    def dumps(self, appstruct):
        """
        Given an ``appstruct``, serialize and sign the data.

        Returns a bytestring.
        """
        cstruct = self.serializer.dumps(appstruct)  # will be bytes

        return base64.urlsafe_b64encode(cstruct)

    def loads(self, bstruct):
        """
        Given a ``bstruct`` (a bytestring), verify the signature and then
        deserialize and return the deserialized value.

        A ``ValueError`` will be raised if the signature fails to validate.
        """
        try:
            cstruct = base64.urlsafe_b64decode(bytes_(bstruct))
        except (binascii.Error, TypeError) as e:
            raise ValueError("Badly formed base64 data: %s" % e)

        return self.serializer.loads(cstruct)


class SignedSerializer:
    """
    A helper to cryptographically sign arbitrary content using HMAC.

    The serializer accepts arbitrary functions for performing the actual
    serialization and deserialization.

    ``secret``
      A string which is used to sign the cookie. The secret should be at
      least as long as the block size of the selected hash algorithm. For
      ``sha512`` this would mean a 512 bit (64 character) secret.

    ``salt``
      A namespace to avoid collisions between different uses of a shared
      secret.

    ``hashalg``
      The HMAC digest algorithm to use for signing. The algorithm must be
      supported by the :mod:`hashlib` library. Default: ``'sha512'``.

    ``serializer``
      An object with two methods: `loads`` and ``dumps``.  The ``loads`` method
      should accept bytes and return a Python object.  The ``dumps`` method
      should accept a Python object and return bytes.  A ``ValueError`` should
      be raised for malformed inputs.  Default: ``None`, which will use a
      derivation of :func:`json.dumps` and ``json.loads``.

    """

    def __init__(self, secret, salt, hashalg="sha512", serializer=None):
        self.salt = salt
        self.secret = secret
        self.hashalg = hashalg

        try:
            # bwcompat with webob <= 1.3.1, leave latin-1 as the default
            self.salted_secret = bytes_(salt or "") + bytes_(secret)
        except UnicodeEncodeError:
            self.salted_secret = bytes_(salt or "", "utf-8") + bytes_(secret, "utf-8")

        self.digestmod = lambda string=b"": hashlib.new(self.hashalg, string)
        self.digest_size = self.digestmod().digest_size

        if serializer is None:
            serializer = JSONSerializer()

        self.serializer = serializer

    def dumps(self, appstruct):
        """
        Given an ``appstruct``, serialize and sign the data.

        Returns a bytestring.
        """
        cstruct = self.serializer.dumps(appstruct)  # will be bytes
        sig = hmac.new(self.salted_secret, cstruct, self.digestmod).digest()

        return base64.urlsafe_b64encode(sig + cstruct).rstrip(b"=")

    def loads(self, bstruct):
        """
        Given a ``bstruct`` (a bytestring), verify the signature and then
        deserialize and return the deserialized value.

        A ``ValueError`` will be raised if the signature fails to validate.
        """
        try:
            b64padding = b"=" * (-len(bstruct) % 4)
            fstruct = base64.urlsafe_b64decode(bytes_(bstruct) + b64padding)
        except (binascii.Error, TypeError) as e:
            raise ValueError("Badly formed base64 data: %s" % e)

        cstruct = fstruct[self.digest_size :]
        expected_sig = fstruct[: self.digest_size]

        sig = hmac.new(self.salted_secret, bytes_(cstruct), self.digestmod).digest()

        if not hmac.compare_digest(sig, expected_sig):
            raise ValueError("Invalid signature")

        return self.serializer.loads(cstruct)


_default = object()


class CookieProfile:
    """
    A helper class that helps bring some sanity to the insanity that is cookie
    handling.

    The helper is capable of generating multiple cookies if necessary to
    support subdomains and parent domains.

    ``cookie_name``
      The name of the cookie used for sessioning. Default: ``'session'``.

    ``max_age``
      The maximum age of the cookie used for sessioning (in seconds).
      Default: ``None`` (browser scope).

    ``secure``
      The 'secure' flag of the session cookie. Default: ``False``.

    ``httponly``
      Hide the cookie from Javascript by setting the 'HttpOnly' flag of the
      session cookie. Default: ``False``.

    ``samesite``
      The 'SameSite' attribute of the cookie, can be either ``b"strict"``,
      ``b"lax"``, ``b"none"``, or ``None``.

      For more information please see the ``samesite`` documentation in
      :meth:`webob.cookies.make_cookie`

    ``path``
      The path used for the session cookie. Default: ``'/'``.

    ``domains``
      The domain(s) used for the session cookie. Default: ``None`` (no domain).
      Can be passed an iterable containing multiple domains, this will set
      multiple cookies one for each domain.

    ``serializer``
      An object with two methods: ``loads`` and ``dumps``.  The ``loads`` method
      should accept a bytestring and return a Python object.  The ``dumps``
      method should accept a Python object and return bytes.  A ``ValueError``
      should be raised for malformed inputs.  Default: ``None``, which will use
      a derivation of :func:`json.dumps` and :func:`json.loads`.

    """

    def __init__(
        self,
        cookie_name,
        secure=False,
        max_age=None,
        httponly=None,
        samesite=None,
        path="/",
        domains=None,
        serializer=None,
    ):
        self.cookie_name = cookie_name
        self.secure = secure
        self.max_age = max_age
        self.httponly = httponly
        self.samesite = samesite
        self.path = path
        self.domains = domains

        if serializer is None:
            serializer = Base64Serializer()

        self.serializer = serializer
        self.request = None

    def __call__(self, request):
        """Bind a request to a copy of this instance and return it"""

        return self.bind(request)

    def bind(self, request):
        """Bind a request to a copy of this instance and return it"""

        selfish = CookieProfile(
            self.cookie_name,
            self.secure,
            self.max_age,
            self.httponly,
            self.samesite,
            self.path,
            self.domains,
            self.serializer,
        )
        selfish.request = request

        return selfish

    def get_value(self):
        """Looks for a cookie by name in the currently bound request, and
        returns its value.  If the cookie profile is not bound to a request,
        this method will raise a :exc:`ValueError`.

        Looks for the cookie in the cookies jar, and if it can find it it will
        attempt to deserialize it.  Returns ``None`` if there is no cookie or
        if the value in the cookie cannot be successfully deserialized.
        """

        if not self.request:
            raise ValueError("No request bound to cookie profile")

        cookie = self.request.cookies.get(self.cookie_name)

        if cookie is not None:
            try:
                return self.serializer.loads(bytes_(cookie))
            except ValueError:
                return None

    def set_cookies(
        self,
        response,
        value,
        domains=_default,
        max_age=_default,
        path=_default,
        secure=_default,
        httponly=_default,
        samesite=_default,
    ):
        """Set the cookies on a response."""
        cookies = self.get_headers(
            value,
            domains=domains,
            max_age=max_age,
            path=path,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
        )
        response.headerlist.extend(cookies)

        return response

    def get_headers(
        self,
        value,
        domains=_default,
        max_age=_default,
        path=_default,
        secure=_default,
        httponly=_default,
        samesite=_default,
    ):
        """Retrieve raw headers for setting cookies.

        Returns a list of headers that should be set for the cookies to
        be correctly tracked.
        """

        if value is None:
            max_age = 0
            bstruct = None
        else:
            bstruct = self.serializer.dumps(value)

        return self._get_cookies(
            bstruct,
            domains=domains,
            max_age=max_age,
            path=path,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
        )

    def _get_cookies(self, value, domains, max_age, path, secure, httponly, samesite):
        """Internal function

        This returns a list of cookies that are valid HTTP Headers.

        :environ: The request environment
        :value: The value to store in the cookie
        :domains: The domains, overrides any set in the CookieProfile
        :max_age: The max_age, overrides any set in the CookieProfile
        :path: The path, overrides any set in the CookieProfile
        :secure: Set this cookie to secure, overrides any set in CookieProfile
        :httponly: Set this cookie to HttpOnly, overrides any set in CookieProfile
        :samesite: Set this cookie to be for only the same site, overrides any
                   set in CookieProfile.

        """

        # If the user doesn't provide values, grab the defaults

        if domains is _default:
            domains = self.domains

        if max_age is _default:
            max_age = self.max_age

        if path is _default:
            path = self.path

        if secure is _default:
            secure = self.secure

        if httponly is _default:
            httponly = self.httponly

        if samesite is _default:
            samesite = self.samesite

        # Length selected based upon http://browsercookielimits.x64.me

        if value is not None and len(value) > 4093:
            raise ValueError(
                "Cookie value is too long to store (%s bytes)" % len(value)
            )

        cookies = []

        if not domains:
            cookievalue = make_cookie(
                self.cookie_name,
                value,
                path=path,
                max_age=max_age,
                httponly=httponly,
                samesite=samesite,
                secure=secure,
            )
            cookies.append(("Set-Cookie", cookievalue))

        else:
            for domain in domains:
                cookievalue = make_cookie(
                    self.cookie_name,
                    value,
                    path=path,
                    domain=domain,
                    max_age=max_age,
                    httponly=httponly,
                    samesite=samesite,
                    secure=secure,
                )
                cookies.append(("Set-Cookie", cookievalue))

        return cookies


class SignedCookieProfile(CookieProfile):
    """
    A helper for generating cookies that are signed to prevent tampering.

    By default this will create a single cookie, given a value it will
    serialize it, then use HMAC to cryptographically sign the data. Finally
    the result is base64-encoded for transport. This way a remote user can
    not tamper with the value without uncovering the secret/salt used.

    ``secret``
      A string which is used to sign the cookie. The secret should be at
      least as long as the block size of the selected hash algorithm. For
      ``sha512`` this would mean a 512 bit (64 character) secret.

    ``salt``
      A namespace to avoid collisions between different uses of a shared
      secret.

    ``hashalg``
      The HMAC digest algorithm to use for signing. The algorithm must be
      supported by the :mod:`hashlib` library. Default: ``'sha512'``.

    ``cookie_name``
      The name of the cookie used for sessioning. Default: ``'session'``.

    ``max_age``
      The maximum age of the cookie used for sessioning (in seconds).
      Default: ``None`` (browser scope).

    ``secure``
      The 'secure' flag of the session cookie. Default: ``False``.

    ``httponly``
      Hide the cookie from Javascript by setting the 'HttpOnly' flag of the
      session cookie. Default: ``False``.

    ``samesite``
      The 'SameSite' attribute of the cookie, can be either ``b"strict"``,
      ``b"lax"``, ``b"none"``, or ``None``.

    ``path``
      The path used for the session cookie. Default: ``'/'``.

    ``domains``
      The domain(s) used for the session cookie. Default: ``None`` (no domain).
      Can be passed an iterable containing multiple domains, this will set
      multiple cookies one for each domain.

    ``serializer``
      An object with two methods: `loads`` and ``dumps``.  The ``loads`` method
      should accept bytes and return a Python object.  The ``dumps`` method
      should accept a Python object and return bytes.  A ``ValueError`` should
      be raised for malformed inputs.  Default: ``None`, which will use a
      derivation of :func:`json.dumps` and ``json.loads``.
    """

    def __init__(
        self,
        secret,
        salt,
        cookie_name,
        secure=False,
        max_age=None,
        httponly=False,
        samesite=None,
        path="/",
        domains=None,
        hashalg="sha512",
        serializer=None,
    ):
        self.secret = secret
        self.salt = salt
        self.hashalg = hashalg
        self.original_serializer = serializer

        signed_serializer = SignedSerializer(
            secret, salt, hashalg, serializer=self.original_serializer
        )
        CookieProfile.__init__(
            self,
            cookie_name,
            secure=secure,
            max_age=max_age,
            httponly=httponly,
            samesite=samesite,
            path=path,
            domains=domains,
            serializer=signed_serializer,
        )

    def bind(self, request):
        """Bind a request to a copy of this instance and return it"""

        selfish = SignedCookieProfile(
            self.secret,
            self.salt,
            self.cookie_name,
            self.secure,
            self.max_age,
            self.httponly,
            self.samesite,
            self.path,
            self.domains,
            self.hashalg,
            self.original_serializer,
        )
        selfish.request = request

        return selfish
