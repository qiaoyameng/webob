from decimal import Decimal

import pytest

from webob.headers import EnvironHeaders, ResponseHeaders
from webob.structured import (
    InnerList,
    Item,
    Parameters,
    StructuredFieldError,
    Token,
    parse_dictionary,
    parse_field,
    parse_item,
    parse_list,
    serialize_dictionary,
    serialize_field,
    serialize_item,
    serialize_list,
)


class TestParseItem:
    def test_integer(self):
        assert parse_item("42") == Item(42)
        assert parse_item("-42") == Item(-42)
        assert parse_item("0") == Item(0)

    def test_integer_max_digits(self):
        assert parse_item("999999999999999") == Item(999999999999999)
        assert parse_item("-999999999999999") == Item(-999999999999999)

    def test_integer_too_many_digits(self):
        with pytest.raises(StructuredFieldError):
            parse_item("1000000000000000")

    def test_decimal(self):
        assert parse_item("1.5") == Item(Decimal("1.5"))
        assert parse_item("1.500") == Item(Decimal("1.500"))
        assert parse_item("-0.001") == Item(Decimal("-0.001"))

    def test_decimal_precision_preserved(self):
        item = parse_item("3.140")
        assert item.value == Decimal("3.140")
        assert item.value.as_tuple().exponent == -3

    def test_decimal_too_many_fraction_digits(self):
        with pytest.raises(StructuredFieldError):
            parse_item("1.0001")

    def test_decimal_too_many_integer_digits(self):
        with pytest.raises(StructuredFieldError):
            parse_item("1234567890123.0")

    def test_decimal_missing_fraction(self):
        with pytest.raises(StructuredFieldError):
            parse_item("1.")

    def test_string(self):
        assert parse_item('"hello world"') == Item("hello world")
        assert parse_item('""') == Item("")

    def test_string_escapes(self):
        assert parse_item('"a \\"quoted\\" string"') == Item('a "quoted" string')
        assert parse_item('"back\\\\slash"') == Item("back\\slash")

    def test_string_invalid_escape(self):
        with pytest.raises(StructuredFieldError):
            parse_item('"bad \\n escape"')
        with pytest.raises(StructuredFieldError):
            parse_item('"bad \\x41"')

    def test_string_unterminated(self):
        with pytest.raises(StructuredFieldError):
            parse_item('"oops')
        with pytest.raises(StructuredFieldError):
            parse_item('"oops\\')

    def test_string_non_ascii(self):
        with pytest.raises(StructuredFieldError):
            parse_item('"caf\u00e9"')

    def test_token(self):
        assert parse_item("text/html") == Item(Token("text/html"))
        assert parse_item("*") == Item(Token("*"))
        assert parse_item("a_b-c.d:*!") == Item(Token("a_b-c.d:*!"))

    def test_byte_sequence(self):
        assert parse_item(":aGVsbG8=:") == Item(b"hello")
        assert parse_item("::") == Item(b"")

    def test_byte_sequence_invalid_char(self):
        with pytest.raises(StructuredFieldError):
            parse_item(":aGVsbG8!:")

    def test_byte_sequence_bad_padding(self):
        with pytest.raises(StructuredFieldError):
            parse_item(":aGVsbG8:")

    def test_byte_sequence_unterminated(self):
        with pytest.raises(StructuredFieldError):
            parse_item(":aGVsbG8=")

    def test_boolean(self):
        assert parse_item("?1") == Item(True)
        assert parse_item("?0") == Item(False)

    def test_boolean_invalid(self):
        with pytest.raises(StructuredFieldError):
            parse_item("?2")

    def test_parameters(self):
        item = parse_item("text/html;level=1;charset=utf-8;q=0.5")
        assert item.value == Token("text/html")
        assert item.params == {
            "level": 1,
            "charset": Token("utf-8"),
            "q": Decimal("0.5"),
        }

    def test_parameter_bare_true(self):
        item = parse_item("a;b")
        assert item.params == {"b": True}

    def test_parameter_duplicate(self):
        with pytest.raises(StructuredFieldError):
            parse_item("a;b=1;b=2")

    def test_surrounding_whitespace(self):
        assert parse_item("   42 \t") == Item(42)

    def test_trailing_garbage(self):
        with pytest.raises(StructuredFieldError):
            parse_item("42 43")
        with pytest.raises(StructuredFieldError):
            parse_item("a, b")

    def test_empty(self):
        with pytest.raises(StructuredFieldError):
            parse_item("")


class TestParseList:
    def test_simple(self):
        assert parse_list("a, b, c") == [
            Item(Token("a")),
            Item(Token("b")),
            Item(Token("c")),
        ]

    def test_empty(self):
        assert parse_list("") == []
        assert parse_list("   ") == []

    def test_mixed_members(self):
        members = parse_list('1, "two", ?1, :aGk=:, tok')
        assert [m.value for m in members] == [1, "two", True, b"hi", Token("tok")]

    def test_inner_list(self):
        members = parse_list('("a" "b");p=1, c')
        inner, other = members
        assert isinstance(inner, InnerList)
        assert inner == InnerList([Item(Token("a")), Item(Token("b"))], {"p": 1})
        assert other == Item(Token("c"))

    def test_inner_list_space_separated(self):
        members = parse_list("(1 2.500 ?0)")
        assert [item.value for item in members[0]] == [1, Decimal("2.500"), False]

    def test_inner_list_empty(self):
        members = parse_list("()")
        assert members == [InnerList()]

    def test_inner_list_item_params(self):
        members = parse_list('(a;x=1 b);y="z"')
        inner = members[0]
        assert inner[0] == Item(Token("a"), {"x": 1})
        assert inner[1] == Item(Token("b"))
        assert inner.params == {"y": "z"}

    def test_inner_list_comma_is_not_separator(self):
        with pytest.raises(StructuredFieldError):
            parse_list("(a, b)")

    def test_inner_list_missing_space(self):
        with pytest.raises(StructuredFieldError):
            parse_list("(a;b=1c)")

    def test_inner_list_unterminated(self):
        with pytest.raises(StructuredFieldError):
            parse_list("(a b")

    def test_trailing_comma(self):
        with pytest.raises(StructuredFieldError):
            parse_list("a, b,")

    def test_double_comma(self):
        with pytest.raises(StructuredFieldError):
            parse_list("a,, b")


class TestParseDictionary:
    def test_simple(self):
        result = parse_dictionary("a=1, b=?0, c")
        assert result == {"a": Item(1), "b": Item(False), "c": Item(True)}

    def test_empty(self):
        assert parse_dictionary("") == {}

    def test_params_without_value(self):
        result = parse_dictionary("a;b=1")
        assert result == {"a": Item(True, {"b": 1})}

    def test_inner_list_member(self):
        result = parse_dictionary('a=(1 2);p="x", b')
        assert result["a"] == InnerList([Item(1), Item(2)], {"p": "x"})
        assert result["b"] == Item(True)

    def test_duplicate_member(self):
        with pytest.raises(StructuredFieldError):
            parse_dictionary("a=1, a=2")

    def test_duplicate_member_same_value(self):
        with pytest.raises(StructuredFieldError):
            parse_dictionary("a=1, a=1")

    def test_trailing_comma(self):
        with pytest.raises(StructuredFieldError):
            parse_dictionary("a=1,")

    def test_bad_key(self):
        with pytest.raises(StructuredFieldError):
            parse_dictionary("A=1")
        with pytest.raises(StructuredFieldError):
            parse_dictionary("1a=1")


class TestParseFieldMerging:
    def test_item_single_line(self):
        assert parse_field(["1; a=2"], "item") == Item(1, {"a": 2})

    def test_item_repeated_is_error(self):
        with pytest.raises(StructuredFieldError):
            parse_field(["1", "2"], "item")

    def test_list_merges_lines(self):
        assert parse_field(["a, b", "c"], "list") == [
            Item(Token("a")),
            Item(Token("b")),
            Item(Token("c")),
        ]

    def test_list_merges_empty_line(self):
        assert parse_field(["a", ""], "list") == [Item(Token("a"))]

    def test_dictionary_merges_lines(self):
        assert parse_field(["a=1", "b=?0"], "dictionary") == {
            "a": Item(1),
            "b": Item(False),
        }

    def test_dictionary_duplicate_across_lines(self):
        with pytest.raises(StructuredFieldError):
            parse_field(["a=1", "a=2"], "dictionary")

    def test_missing_header(self):
        with pytest.raises(KeyError):
            parse_field([], "item")
        with pytest.raises(KeyError):
            parse_field([], "list")
        with pytest.raises(KeyError):
            parse_field([], "dictionary")

    def test_unknown_field_type(self):
        with pytest.raises(ValueError):
            parse_field(["a"], "nope")


class TestSerialize:
    def test_integer(self):
        assert serialize_item(42) == "42"
        assert serialize_item(-999999999999999) == "-999999999999999"

    def test_integer_out_of_range(self):
        with pytest.raises(StructuredFieldError):
            serialize_item(10**15)

    def test_decimal_canonical_three_places(self):
        assert serialize_item(Decimal("1.5")) == "1.500"
        assert serialize_item(Decimal("2")) == "2.000"
        assert serialize_item(Decimal("-0.001")) == "-0.001"

    def test_decimal_rounds_to_three_places(self):
        assert serialize_item(Decimal("1.0004")) == "1.000"
        assert serialize_item(Decimal("0.0009")) == "0.001"

    def test_decimal_integer_part_too_large(self):
        with pytest.raises(StructuredFieldError):
            serialize_item(Decimal("9999999999999.9"))

    def test_string_escaping(self):
        assert serialize_item('a "b" \\c') == '"a \\"b\\" \\\\c"'

    def test_string_non_ascii(self):
        with pytest.raises(StructuredFieldError):
            serialize_item("caf\u00e9")

    def test_token(self):
        assert serialize_item(Token("text/html")) == "text/html"

    def test_token_invalid(self):
        with pytest.raises(StructuredFieldError):
            serialize_item(Token("not a token"))

    def test_bytes(self):
        assert serialize_item(b"hello") == ":aGVsbG8=:"

    def test_boolean(self):
        assert serialize_item(True) == "?1"
        assert serialize_item(False) == "?0"

    def test_params(self):
        item = Item(
            Token("text/html"), Parameters([("level", 1), ("q", Decimal("0.5"))])
        )
        assert serialize_item(item) == "text/html;level=1;q=0.500"

    def test_param_true_omits_value(self):
        assert serialize_item(Item(Token("a"), {"b": True})) == "a;b"

    def test_param_false_kept(self):
        assert serialize_item(Item(Token("a"), {"b": False})) == "a;b=?0"

    def test_param_bad_key(self):
        with pytest.raises(StructuredFieldError):
            serialize_item(Item(1, {"Bad Key": 1}))

    def test_list(self):
        members = [
            Item(Token("a")),
            InnerList([Item(1), Item(Decimal("2.5"))], {"p": "x"}),
            Item(Token("b"), {"q": True}),
        ]
        assert serialize_list(members) == 'a, (1 2.500);p="x", b;q'

    def test_list_bare_values(self):
        assert serialize_list([1, "two", False]) == '1, "two", ?0'

    def test_dictionary(self):
        assert serialize_dictionary(
            {
                "a": Item(1),
                "b": Item(False),
                "c": Item(True),
                "d": InnerList([Item(1), Item(2)], {"p": True}),
                "e": Item(True, {"x": Token("y")}),
            }
        ) == "a=1, b=?0, c, d=(1 2);p, e;x=y"

    def test_dictionary_bad_key(self):
        with pytest.raises(StructuredFieldError):
            serialize_dictionary({"Bad": Item(1)})

    def test_roundtrip(self):
        wire = 'a=1;b="x", c=(t:ok: ?1);p=0.250, d'
        assert serialize_dictionary(parse_dictionary(wire)) == wire

    def test_roundtrip_list(self):
        wire = '(1 "two");x=:aGk=:, 3.140'
        assert serialize_list(parse_list(wire)) == wire

    def test_serialize_field_dispatch(self):
        assert serialize_field(Item(1), "item") == "1"
        assert serialize_field([Item(1)], "list") == "1"
        assert serialize_field({"a": Item(1)}, "dictionary") == "a=1"
        with pytest.raises(ValueError):
            serialize_field(1, "nope")


class TestResponseHeadersAccess:
    def make_headers(self, pairs):
        return ResponseHeaders(pairs)

    def test_get_item(self):
        headers = self.make_headers([("X-Rate", "1.5;unit=eur")])
        item = headers.get_structured("X-Rate", "item")
        assert item == Item(Decimal("1.5"), {"unit": Token("eur")})

    def test_get_item_repeated_rejected(self):
        headers = self.make_headers([("X-Rate", "1"), ("X-Rate", "2")])
        with pytest.raises(StructuredFieldError):
            headers.get_structured("X-Rate", "item")

    def test_get_list_merges_repeated(self):
        headers = self.make_headers(
            [("X-Tokens", "a, (b c);p=1"), ("X-Tokens", "d")]
        )
        members = headers.get_structured("X-Tokens", "list")
        assert members == [
            Item(Token("a")),
            InnerList([Item(Token("b")), Item(Token("c"))], {"p": 1}),
            Item(Token("d")),
        ]

    def test_get_dictionary_merges_repeated(self):
        headers = self.make_headers([("X-Prefs", "a=1"), ("X-Prefs", "b=?0")])
        assert headers.get_structured("X-Prefs", "dictionary") == {
            "a": Item(1),
            "b": Item(False),
        }

    def test_get_dictionary_duplicate_across_repeated(self):
        headers = self.make_headers([("X-Prefs", "a=1"), ("X-Prefs", "a=2")])
        with pytest.raises(StructuredFieldError):
            headers.get_structured("X-Prefs", "dictionary")

    def test_get_missing(self):
        headers = self.make_headers([])
        with pytest.raises(KeyError):
            headers.get_structured("X-Missing", "list")

    def test_get_invalid_raises(self):
        headers = self.make_headers([("X-Bad", "1.0001")])
        with pytest.raises(StructuredFieldError):
            headers.get_structured("X-Bad", "item")

    def test_set_item(self):
        headers = self.make_headers([])
        headers.set_structured(
            "X-Rate", Item(Decimal("1.5"), {"unit": Token("eur")}), "item"
        )
        assert headers["X-Rate"] == "1.500;unit=eur"

    def test_set_replaces_existing(self):
        headers = self.make_headers([("X-Tokens", "old"), ("X-Tokens", "older")])
        headers.set_structured("X-Tokens", [Item(Token("a"))], "list")
        assert headers.getall("X-Tokens") == ["a"]

    def test_set_dictionary(self):
        headers = self.make_headers([])
        headers.set_structured(
            "X-Prefs",
            {"a": Item(1), "b": Item(True), "c": InnerList([Item("x"), Item(2)])},
            "dictionary",
        )
        assert headers["X-Prefs"] == 'a=1, b, c=("x" 2)'

    def test_plain_api_untouched(self):
        headers = self.make_headers([("X-Raw", "a, b"), ("X-Raw", "c")])
        assert headers["X-Raw"] == "c"
        assert headers.getall("X-Raw") == ["a, b", "c"]
        headers["X-Raw"] = "x, y"
        assert headers["X-Raw"] == "x, y"


class TestEnvironHeadersAccess:
    def make_headers(self, pairs):
        environ = {}
        headers = EnvironHeaders(environ)
        for key, value in pairs:
            headers[key] = value
        return headers

    def test_get_list(self):
        headers = self.make_headers([("X-Tokens", "a, (1 2);p")])
        assert headers.get_structured("X-Tokens", "list") == [
            Item(Token("a")),
            InnerList([Item(1), Item(2)], {"p": True}),
        ]

    def test_get_missing(self):
        headers = self.make_headers([])
        with pytest.raises(KeyError):
            headers.get_structured("X-Missing", "item")

    def test_set_item(self):
        headers = self.make_headers([])
        headers.set_structured("X-Flag", Item(True, {"strict": True}), "item")
        assert headers["X-Flag"] == "?1;strict"
