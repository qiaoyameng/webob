"""
Parsing and serialization for HTTP Structured Fields (RFC 8941).

This module provides typed access to header field values that use the
Structured Fields syntax.  Three field types are supported:

``item``
    A single bare item (integer, decimal, string, token, byte sequence
    or boolean) optionally followed by parameters.

``list``
    A comma separated list of items or inner lists.

``dictionary``
    A comma separated list of key/value members.

Values are represented as follows:

- integers are ``int``
- decimals are ``decimal.Decimal``
- strings are ``str``
- tokens are ``Token`` (a ``str`` subclass)
- byte sequences are ``bytes``
- booleans are ``bool``
- items with parameters are ``Item`` instances (``value`` + ``params``)
- inner lists are ``InnerList`` instances (a ``list`` with ``params``)
- parameters are ``Parameters`` instances (ordered ``dict``)

Parsing is strict: out of range numbers, invalid escapes, malformed
byte sequences and duplicate dictionary members or parameters all raise
``StructuredFieldError`` instead of being silently discarded.
"""

import base64
import binascii
import re
from decimal import Decimal
from decimal import InvalidOperation

__all__ = [
    "StructuredFieldError",
    "Token",
    "Parameters",
    "Item",
    "InnerList",
    "parse_item",
    "parse_list",
    "parse_dictionary",
    "parse_field",
    "serialize_item",
    "serialize_list",
    "serialize_dictionary",
    "serialize_field",
]

ITEM = "item"
LIST = "list"
DICTIONARY = "dictionary"

_FIELD_TYPES = (ITEM, LIST, DICTIONARY)


class StructuredFieldError(ValueError):
    """Raised when a structured field value cannot be parsed or serialized."""


class Token(str):
    """A bare item that must be serialized as an RFC 8941 token."""


class Parameters(dict):
    """Ordered mapping of parameter names to bare-item values."""


class Item:
    """A bare item together with its parameters."""

    __slots__ = ("value", "params")

    def __init__(self, value, params=None):
        self.value = value
        self.params = Parameters(params or ())

    def __eq__(self, other):
        if isinstance(other, Item):
            return self.value == other.value and self.params == other.params
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((self.value, tuple(self.params.items())))

    def __repr__(self):
        return "Item(%r, %r)" % (self.value, self.params)


class InnerList(list):
    """A list of items together with parameters applying to the list."""

    def __init__(self, items=(), params=None):
        super().__init__(items)
        self.params = Parameters(params or ())

    def __eq__(self, other):
        if isinstance(other, InnerList):
            return list.__eq__(self, other) and self.params == other.params
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    __hash__ = None

    def __repr__(self):
        return "InnerList(%r, %r)" % (list(self), self.params)


_INT_RE = re.compile(r"-?[0-9]+")
_FRAC_RE = re.compile(r"[0-9]+")
_TOKEN_RE = re.compile(r"[A-Za-z*][A-Za-z0-9!#$%&'*+\-./:_^`|~]*")
_KEY_RE = re.compile(r"[a-z*][a-z0-9_.\-*]*")
_TOKEN_FULL_RE = re.compile(r"[A-Za-z*][A-Za-z0-9!#$%&'*+\-./:_^`|~]*\Z")
_KEY_FULL_RE = re.compile(r"[a-z*][a-z0-9_.\-*]*\Z")
_B64_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)

_MAX_INT_DIGITS = 15
_MAX_DEC_INT_DIGITS = 12
_MAX_DEC_FRAC_DIGITS = 3


class _Parser:
    def __init__(self, text):
        if not isinstance(text, str):
            raise StructuredFieldError(
                "structured field value must be str, got %r" % type(text)
            )
        self.text = text
        self.pos = 0

    def error(self, message):
        raise StructuredFieldError(
            "%s at position %d in %r" % (message, self.pos, self.text)
        )

    def eof(self):
        return self.pos >= len(self.text)

    def peek(self):
        if self.eof():
            return ""
        return self.text[self.pos]

    def discard_ows(self):
        while self.peek() in (" ", "\t"):
            self.pos += 1

    def discard_sp(self):
        while self.peek() == " ":
            self.pos += 1


def _parse_bare_item(parser):
    char = parser.peek()
    if char == "":
        parser.error("expected bare item, found end of input")
    if char == "-" or char.isdigit():
        return _parse_number(parser)
    if char == '"':
        return _parse_string(parser)
    if char == ":":
        return _parse_byte_sequence(parser)
    if char == "?":
        return _parse_boolean(parser)
    if char.isalpha() or char == "*":
        return _parse_token(parser)
    parser.error("expected bare item, found %r" % char)


def _parse_number(parser):
    text = parser.text
    match = _INT_RE.match(text, parser.pos)
    int_part = match.group(0)
    digits = len(int_part.lstrip("-"))
    parser.pos = match.end()
    if parser.peek() == ".":
        if digits > _MAX_DEC_INT_DIGITS:
            parser.error(
                "decimal has more than %d integer digits" % _MAX_DEC_INT_DIGITS
            )
        parser.pos += 1
        frac_match = _FRAC_RE.match(text, parser.pos)
        if frac_match is None:
            parser.error("decimal requires at least one fractional digit")
        frac_part = frac_match.group(0)
        if len(frac_part) > _MAX_DEC_FRAC_DIGITS:
            parser.error(
                "decimal has more than %d fractional digits" % _MAX_DEC_FRAC_DIGITS
            )
        parser.pos = frac_match.end()
        return Decimal(int_part + "." + frac_part)
    if digits > _MAX_INT_DIGITS:
        parser.error("integer has more than %d digits" % _MAX_INT_DIGITS)
    return int(int_part)


def _parse_string(parser):
    parser.pos += 1  # consume opening DQUOTE
    chars = []
    while True:
        if parser.eof():
            parser.error("unterminated string")
        char = parser.text[parser.pos]
        parser.pos += 1
        if char == '"':
            return "".join(chars)
        if char == "\\":
            if parser.eof():
                parser.error("unterminated escape sequence in string")
            escaped = parser.text[parser.pos]
            parser.pos += 1
            if escaped not in ('"', "\\"):
                parser.error("invalid escape sequence \\%s in string" % escaped)
            chars.append(escaped)
        else:
            code = ord(char)
            if code < 0x20 or code > 0x7E:
                parser.error("invalid character %#04x in string" % code)
            chars.append(char)


def _parse_byte_sequence(parser):
    parser.pos += 1  # consume opening colon
    end = parser.text.find(":", parser.pos)
    if end == -1:
        parser.error("unterminated byte sequence")
    content = parser.text[parser.pos:end]
    if any(char not in _B64_CHARS for char in content):
        parser.error("invalid character in byte sequence")
    try:
        value = base64.b64decode(content.encode("ascii"), validate=True)
    except (binascii.Error, ValueError):
        parser.error("invalid base64 padding in byte sequence")
    parser.pos = end + 1
    return value


def _parse_boolean(parser):
    parser.pos += 1  # consume "?"
    char = parser.peek()
    if char == "1":
        parser.pos += 1
        return True
    if char == "0":
        parser.pos += 1
        return False
    parser.error("invalid boolean")


def _parse_token(parser):
    match = _TOKEN_RE.match(parser.text, parser.pos)
    parser.pos = match.end()
    return Token(match.group(0))


def _parse_key(parser):
    match = _KEY_RE.match(parser.text, parser.pos)
    if match is None:
        parser.error("expected dictionary or parameter key")
    parser.pos = match.end()
    return match.group(0)


def _parse_parameters(parser):
    params = Parameters()
    while parser.peek() == ";":
        parser.pos += 1
        parser.discard_sp()
        key = _parse_key(parser)
        if parser.peek() == "=":
            parser.pos += 1
            value = _parse_bare_item(parser)
        else:
            value = True
        if key in params:
            parser.error("duplicate parameter %r" % key)
        params[key] = value
    return params


def _parse_item(parser):
    value = _parse_bare_item(parser)
    params = _parse_parameters(parser)
    return Item(value, params)


def _parse_inner_list(parser):
    parser.pos += 1  # consume "("
    items = []
    while True:
        parser.discard_sp()
        if parser.eof():
            parser.error("unterminated inner list")
        if parser.peek() == ")":
            parser.pos += 1
            return InnerList(items, _parse_parameters(parser))
        items.append(_parse_item(parser))
        if parser.peek() not in (" ", ")"):
            parser.error("expected space or ')' in inner list")


def _parse_item_or_inner_list(parser):
    if parser.peek() == "(":
        return _parse_inner_list(parser)
    return _parse_item(parser)


def _finish(parser):
    parser.discard_ows()
    if not parser.eof():
        parser.error("trailing characters after structured field value")


def parse_item(text):
    """Parse an Item structured field value, returning an ``Item``."""
    parser = _Parser(text)
    parser.discard_ows()
    item = _parse_item(parser)
    _finish(parser)
    return item


def parse_list(text):
    """Parse a List structured field value, returning a list of members."""
    parser = _Parser(text)
    parser.discard_ows()
    members = []
    if parser.eof():
        return members
    while True:
        members.append(_parse_item_or_inner_list(parser))
        parser.discard_ows()
        if parser.eof():
            return members
        if parser.text[parser.pos] != ",":
            parser.error("expected ',' between list members")
        parser.pos += 1
        parser.discard_ows()
        if parser.eof():
            parser.error("trailing comma in list")


def parse_dictionary(text):
    """Parse a Dictionary structured field value, returning a dict."""
    parser = _Parser(text)
    parser.discard_ows()
    result = {}
    if parser.eof():
        return result
    while True:
        key = _parse_key(parser)
        if key in result:
            parser.error("duplicate dictionary member %r" % key)
        if parser.peek() == "=":
            parser.pos += 1
            result[key] = _parse_item_or_inner_list(parser)
        else:
            result[key] = Item(True, _parse_parameters(parser))
        parser.discard_ows()
        if parser.eof():
            return result
        if parser.text[parser.pos] != ",":
            parser.error("expected ',' between dictionary members")
        parser.pos += 1
        parser.discard_ows()
        if parser.eof():
            parser.error("trailing comma in dictionary")


def parse_field(lines, field_type):
    """Parse (possibly repeated) header field lines as ``field_type``.

    ``lines`` is an iterable of field line values.  Merging of repeated
    lines follows RFC 8941: lists and dictionaries are combined, while an
    item field must appear at most once.  Duplicate dictionary members
    across lines are an error.
    """
    if field_type not in _FIELD_TYPES:
        raise ValueError("unknown structured field type %r" % (field_type,))
    lines = list(lines)
    if field_type == ITEM:
        if len(lines) > 1:
            raise StructuredFieldError(
                "item structured field must not span multiple field lines"
            )
        if not lines:
            raise KeyError("no such structured header")
        return parse_item(lines[0])
    if not lines:
        raise KeyError("no such structured header")
    if field_type == LIST:
        members = []
        for line in lines:
            members.extend(parse_list(line))
        return members
    result = {}
    for line in lines:
        for key, value in parse_dictionary(line).items():
            if key in result:
                raise StructuredFieldError(
                    "duplicate dictionary member %r across field lines" % key
                )
            result[key] = value
    return result


def _serialize_bare_item(value):
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, int):
        if len(str(abs(value))) > _MAX_INT_DIGITS:
            raise StructuredFieldError(
                "integer %r has more than %d digits" % (value, _MAX_INT_DIGITS)
            )
        return str(value)
    if isinstance(value, Decimal):
        return _serialize_decimal(value)
    if isinstance(value, Token):
        if not _TOKEN_FULL_RE.match(value):
            raise StructuredFieldError("invalid token %r" % value)
        return str(value)
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, (bytes, bytearray)):
        return ":" + base64.b64encode(bytes(value)).decode("ascii") + ":"
    raise StructuredFieldError(
        "cannot serialize %r as a structured field bare item" % (value,)
    )


def _serialize_decimal(value):
    try:
        rounded = value.quantize(Decimal("0.001"))
    except InvalidOperation:
        raise StructuredFieldError(
            "decimal %r cannot be represented with 3 fractional digits" % (value,)
        )
    int_digits = len(rounded.copy_abs().quantize(Decimal("1")).as_tuple().digits)
    if int_digits > _MAX_DEC_INT_DIGITS:
        raise StructuredFieldError(
            "decimal %r has more than %d integer digits" % (value, _MAX_DEC_INT_DIGITS)
        )
    text = format(rounded, "f")
    if "." not in text:
        text += ".000"
    return text


def _serialize_string(value):
    chars = []
    for char in value:
        code = ord(char)
        if char in ('"', "\\"):
            chars.append("\\" + char)
        elif code < 0x20 or code > 0x7E:
            raise StructuredFieldError(
                "invalid character %#04x in string" % code
            )
        else:
            chars.append(char)
    return '"' + "".join(chars) + '"'


def _serialize_key(key):
    if not isinstance(key, str) or not _KEY_FULL_RE.match(key):
        raise StructuredFieldError("invalid key %r" % (key,))
    return key


def _serialize_parameters(params):
    parts = []
    for key, value in params.items():
        part = ";" + _serialize_key(key)
        if value is not True:
            part += "=" + _serialize_bare_item(value)
        parts.append(part)
    return "".join(parts)


def _as_item(value):
    if isinstance(value, Item):
        return value
    return Item(value)


def _serialize_item(item):
    item = _as_item(item)
    return _serialize_bare_item(item.value) + _serialize_parameters(item.params)


def _serialize_item_or_inner_list(member):
    if isinstance(member, InnerList):
        inner = " ".join(_serialize_item(item) for item in member)
        return "(" + inner + ")" + _serialize_parameters(member.params)
    return _serialize_item(member)


def serialize_item(item):
    """Serialize an ``Item`` (or bare value) as an Item field value."""
    return _serialize_item(item)


def serialize_list(members):
    """Serialize a list of items/inner lists as a List field value."""
    return ", ".join(_serialize_item_or_inner_list(member) for member in members)


def serialize_dictionary(mapping):
    """Serialize a mapping as a Dictionary field value."""
    parts = []
    for key, value in mapping.items():
        key = _serialize_key(key)
        if isinstance(value, InnerList):
            parts.append(key + "=" + _serialize_item_or_inner_list(value))
            continue
        item = _as_item(value)
        if item.value is True:
            parts.append(key + _serialize_parameters(item.params))
        else:
            parts.append(
                key
                + "="
                + _serialize_bare_item(item.value)
                + _serialize_parameters(item.params)
            )
    return ", ".join(parts)


def serialize_field(value, field_type):
    """Serialize ``value`` according to ``field_type``."""
    if field_type == ITEM:
        return serialize_item(value)
    if field_type == LIST:
        return serialize_list(value)
    if field_type == DICTIONARY:
        return serialize_dictionary(value)
    raise ValueError("unknown structured field type %r" % (field_type,))
