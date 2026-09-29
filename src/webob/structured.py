"""
Typed access to HTTP Structured Fields (RFC 8941).

This module parses and serializes the three structured field types --
``item``, ``list`` and ``dictionary`` -- including parameters, inner
lists, byte sequences, booleans and fixed-point decimals.  Parsing is
strict: out-of-range numbers, bad escapes, malformed byte sequences and
duplicate dictionary members or parameter names raise
:exc:`StructuredFieldError` instead of being silently discarded.
"""

import base64
import binascii
import re
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation

__all__ = [
    "StructuredFieldError",
    "Token",
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

# RFC 8941 range limits: integers have at most 15 digits, decimals at
# most 12 digits before and 3 digits after the decimal point.
_MAX_INTEGER = 999999999999999
_MAX_DECIMAL = Decimal("999999999999.999")
_DECIMAL_PLACES = Decimal("0.001")

_KEY_RE = re.compile(r"[a-z*][a-z0-9_.*-]*")
_KEY_FULL_RE = re.compile(r"[a-z*][a-z0-9_.*-]*\Z")
_TOKEN_RE = re.compile(r"[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*")
_TOKEN_FULL_RE = re.compile(r"[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*\Z")
_INTEGER_RE = re.compile(r"-?[0-9]+")
_B64_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)


class StructuredFieldError(ValueError):
    """Raised when a structured field value cannot be parsed or serialized."""


class Token(str):
    """A bare token, kept distinct from a quoted string on serialization."""


class Item:
    """A bare item together with its parameters."""

    __slots__ = ("value", "params")

    def __init__(self, value, params=None):
        self.value = value
        self.params = dict(params) if params else {}

    def __eq__(self, other):
        if isinstance(other, Item):
            return self.value == other.value and self.params == other.params
        return NotImplemented

    def __ne__(self, other):
        eq = self.__eq__(other)
        return eq if eq is NotImplemented else not eq

    def __repr__(self):
        return "Item(%r, %r)" % (self.value, self.params)


class InnerList(list):
    """A parenthesized list of items, together with its parameters."""

    def __init__(self, items=(), params=None):
        super().__init__(items)
        self.params = dict(params) if params else {}

    def __eq__(self, other):
        if isinstance(other, InnerList):
            return list.__eq__(self, other) and self.params == other.params
        return list.__eq__(self, other)

    def __ne__(self, other):
        eq = self.__eq__(other)
        return eq if eq is NotImplemented else not eq

    __hash__ = None

    def __repr__(self):
        return "InnerList(%s, %r)" % (list.__repr__(self), self.params)


class _Parser:
    def __init__(self, text):
        self.text = text
        self.pos = 0

    def fail(self, message):
        raise StructuredFieldError(
            "%s (at position %d in %r)" % (message, self.pos, self.text)
        )

    def peek(self):
        if self.pos < len(self.text):
            return self.text[self.pos]
        return ""

    def discard_ows(self):
        while self.peek() in (" ", "\t"):
            self.pos += 1

    def discard_sp(self):
        while self.peek() == " ":
            self.pos += 1

    def parse_key(self):
        match = _KEY_RE.match(self.text, self.pos)
        if match is None:
            self.fail("expected a dictionary or parameter key")
        self.pos = match.end()
        return match.group()

    def parse_parameters(self):
        params = {}
        while self.peek() == ";":
            self.pos += 1
            self.discard_sp()
            key = self.parse_key()
            if key in params:
                self.fail("duplicate parameter name %r" % key)
            if self.peek() == "=":
                self.pos += 1
                params[key] = self.parse_bare_item()
            else:
                params[key] = True
        return params

    def parse_item(self):
        return Item(self.parse_bare_item(), self.parse_parameters())

    def parse_item_or_inner_list(self):
        if self.peek() == "(":
            return self.parse_inner_list()
        return self.parse_item()

    def parse_inner_list(self):
        self.pos += 1  # consume "("
        items = []
        while True:
            if self.pos >= len(self.text):
                self.fail("unterminated inner list")
            self.discard_sp()
            if self.peek() == ")":
                self.pos += 1
                break
            items.append(self.parse_item())
            if self.peek() not in (" ", ")"):
                self.fail("inner list items must be separated by spaces")
        return InnerList(items, self.parse_parameters())

    def parse_bare_item(self):
        char = self.peek()
        if char == '"':
            return self.parse_string()
        if char == "-" or char.isdigit():
            return self.parse_number()
        if char == ":":
            return self.parse_byte_sequence()
        if char == "?":
            return self.parse_boolean()
        if char.isalpha() or char == "*":
            return self.parse_token()
        self.fail("expected a bare item")

    def parse_number(self):
        match = _INTEGER_RE.match(self.text, self.pos)
        int_part = match.group()
        digits = int_part.lstrip("-")
        self.pos = match.end()
        if self.peek() == ".":
            if len(digits) > 12:
                self.fail("decimal has more than 12 integer digits")
            self.pos += 1
            start = self.pos
            while self.peek().isdigit():
                self.pos += 1
            frac_part = self.text[start : self.pos]
            if not frac_part:
                self.fail("decimal has no fractional digits")
            if len(frac_part) > 3:
                self.fail("decimal has more than 3 fractional digits")
            return Decimal("%s.%s" % (int_part, frac_part))
        if len(digits) > 15:
            self.fail("integer has more than 15 digits")
        return int(int_part)

    def parse_string(self):
        self.pos += 1  # consume opening quote
        chars = []
        while True:
            if self.pos >= len(self.text):
                self.fail("unterminated string")
            char = self.text[self.pos]
            if char == '"':
                self.pos += 1
                return "".join(chars)
            if char == "\\":
                self.pos += 1
                if self.pos >= len(self.text):
                    self.fail("unterminated escape in string")
                escaped = self.text[self.pos]
                if escaped not in ('"', "\\"):
                    self.fail("invalid escape sequence \\%s" % escaped)
                chars.append(escaped)
                self.pos += 1
            else:
                if not 0x20 <= ord(char) <= 0x7E:
                    self.fail("invalid character in string")
                chars.append(char)
                self.pos += 1

    def parse_token(self):
        match = _TOKEN_RE.match(self.text, self.pos)
        if match is None:
            self.fail("expected a token")
        self.pos = match.end()
        return Token(match.group())

    def parse_byte_sequence(self):
        self.pos += 1  # consume ":"
        start = self.pos
        while self.peek() in _B64_CHARS:
            self.pos += 1
        if self.peek() != ":":
            self.fail("unterminated byte sequence")
        encoded = self.text[start : self.pos]
        self.pos += 1
        try:
            return base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            self.fail("invalid base64 in byte sequence")

    def parse_boolean(self):
        self.pos += 1  # consume "?"
        char = self.peek()
        if char == "1":
            self.pos += 1
            return True
        if char == "0":
            self.pos += 1
            return False
        self.fail("invalid boolean")

    def parse_list(self):
        members = []
        while True:
            self.discard_ows()
            if self.pos >= len(self.text):
                return members
            members.append(self.parse_item_or_inner_list())
            self.discard_ows()
            if self.pos >= len(self.text):
                return members
            if self.text[self.pos] != ",":
                self.fail("expected ',' between list members")
            self.pos += 1
            self.discard_ows()
            if self.pos >= len(self.text):
                self.fail("trailing comma in list")

    def parse_dictionary(self):
        members = {}
        while True:
            self.discard_ows()
            if self.pos >= len(self.text):
                return members
            key = self.parse_key()
            if key in members:
                self.fail("duplicate dictionary member %r" % key)
            if self.peek() == "=":
                self.pos += 1
                members[key] = self.parse_item_or_inner_list()
            else:
                members[key] = Item(True, self.parse_parameters())
            self.discard_ows()
            if self.pos >= len(self.text):
                return members
            if self.text[self.pos] != ",":
                self.fail("expected ',' between dictionary members")
            self.pos += 1
            self.discard_ows()
            if self.pos >= len(self.text):
                self.fail("trailing comma in dictionary")


def _parse(text, field_type):
    if not isinstance(text, str):
        raise StructuredFieldError(
            "structured field value must be str, got %s" % type(text).__name__
        )
    parser = _Parser(text)
    if field_type == ITEM:
        parser.discard_ows()
        result = parser.parse_item()
        parser.discard_ows()
        if parser.pos != len(text):
            parser.fail("trailing characters after item")
        return result
    if field_type == LIST:
        return parser.parse_list()
    if field_type == DICTIONARY:
        return parser.parse_dictionary()
    raise ValueError(
        "field_type must be one of %r, got %r" % (_FIELD_TYPES, field_type)
    )


def parse_item(value):
    """Parse a single header line as an Item field."""
    return _parse(value, ITEM)


def parse_list(value):
    """Parse a single header line as a List field."""
    return _parse(value, LIST)


def parse_dictionary(value):
    """Parse a single header line as a Dictionary field."""
    return _parse(value, DICTIONARY)


def parse_field(values, field_type):
    """Parse one or more header lines according to ``field_type``.

    ``values`` is a string or an iterable of strings (one per header
    line).  List and Dictionary lines are combined with ``", "`` before
    parsing, as required by RFC 8941; an Item field must appear on
    exactly one line.
    """
    if field_type not in _FIELD_TYPES:
        raise ValueError(
            "field_type must be one of %r, got %r" % (_FIELD_TYPES, field_type)
        )
    if isinstance(values, str):
        values = [values]
    values = list(values)
    if not values:
        raise StructuredFieldError("no header value to parse")
    if field_type == ITEM:
        if len(values) != 1:
            raise StructuredFieldError(
                "an Item field must not span %d header lines" % len(values)
            )
        text = values[0]
    else:
        text = ", ".join(values)
    return _parse(text, field_type)


def _validate_key(key):
    if not isinstance(key, str) or _KEY_FULL_RE.match(key) is None:
        raise StructuredFieldError(
            "invalid dictionary or parameter key %r" % (key,)
        )


def _serialize_decimal(value):
    try:
        quantized = value.quantize(_DECIMAL_PLACES, rounding=ROUND_HALF_EVEN)
    except (InvalidOperation, ValueError):
        raise StructuredFieldError(
            "cannot serialize decimal %r" % (value,)
        ) from None
    if abs(quantized) > _MAX_DECIMAL:
        raise StructuredFieldError("decimal %r is out of range" % (value,))
    text = format(quantized, "f")
    if "." in text:
        text = text.rstrip("0")
        if text.endswith("."):
            text += "0"
    return text


def serialize_bare_item(value):
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, int):
        if not -_MAX_INTEGER <= value <= _MAX_INTEGER:
            raise StructuredFieldError("integer %r is out of range" % (value,))
        return str(value)
    if isinstance(value, Decimal):
        return _serialize_decimal(value)
    if isinstance(value, float):
        raise StructuredFieldError(
            "floats are not supported; use decimal.Decimal for fixed-point values"
        )
    if isinstance(value, Token):
        if _TOKEN_FULL_RE.match(value) is None:
            raise StructuredFieldError("invalid token %r" % (value,))
        return str(value)
    if isinstance(value, str):
        for char in value:
            if not 0x20 <= ord(char) <= 0x7E:
                raise StructuredFieldError("invalid character %r in string" % char)
        return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')
    if isinstance(value, (bytes, bytearray)):
        return ":" + base64.b64encode(bytes(value)).decode("ascii") + ":"
    raise StructuredFieldError(
        "cannot serialize value of type %s" % type(value).__name__
    )


def _serialize_params(params):
    parts = []
    for key, value in params.items():
        _validate_key(key)
        if value is True:
            parts.append(";" + key)
        else:
            parts.append(";" + key + "=" + serialize_bare_item(value))
    return "".join(parts)


def serialize_item(value):
    """Serialize a bare value or an :class:`Item` (with parameters)."""
    if isinstance(value, Item):
        return serialize_bare_item(value.value) + _serialize_params(value.params)
    return serialize_bare_item(value)


def serialize_inner_list(value):
    """Serialize an :class:`InnerList` or a plain list/tuple of items."""
    if isinstance(value, InnerList):
        items, params = value, value.params
    else:
        items, params = value, {}
    return (
        "(" + " ".join(serialize_item(item) for item in items) + ")"
    ) + _serialize_params(params)


def serialize_list(value):
    """Serialize a sequence of items and inner lists as a List field."""
    parts = []
    for member in value:
        if isinstance(member, (InnerList, list, tuple)):
            parts.append(serialize_inner_list(member))
        else:
            parts.append(serialize_item(member))
    return ", ".join(parts)


def serialize_dictionary(value):
    """Serialize a mapping as a Dictionary field."""
    parts = []
    for key, member in value.items():
        _validate_key(key)
        if isinstance(member, InnerList) or (
            isinstance(member, (list, tuple)) and not isinstance(member, Item)
        ):
            parts.append(key + "=" + serialize_inner_list(member))
        elif isinstance(member, Item):
            if member.value is True:
                parts.append(key + _serialize_params(member.params))
            else:
                parts.append(key + "=" + serialize_item(member))
        elif member is True:
            parts.append(key)
        else:
            parts.append(key + "=" + serialize_item(member))
    return ", ".join(parts)


def serialize_field(value, field_type=None):
    """Serialize ``value`` to its canonical structured field form.

    When ``field_type`` is omitted it is inferred: mappings become
    dictionaries, other sequences become lists, anything else an item.
    """
    if field_type is None:
        if isinstance(value, dict):
            field_type = DICTIONARY
        elif isinstance(value, (list, tuple)):
            field_type = LIST
        else:
            field_type = ITEM
    if field_type == ITEM:
        return serialize_item(value)
    if field_type == LIST:
        return serialize_list(value)
    if field_type == DICTIONARY:
        return serialize_dictionary(value)
    raise ValueError(
        "field_type must be one of %r, got %r" % (_FIELD_TYPES, field_type)
    )
