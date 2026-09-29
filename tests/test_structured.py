from decimal import Decimal

import pytest

from webob.headers import EnvironHeaders, ResponseHeaders
from webob.request import Request
from webob.structured import (
    InnerList,
    Item,
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

    def test_negative_integer(self):
        assert parse_item("-42") == Item(-42)

    def test_integer_max_15_digits(self):
        assert parse_item("999999999999999") == Item(999999999999999)
        assert parse_item("-999999999999999") == Item(-999999999999999)

    def test_integer_16_digits_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_item("9999999999999999")

    def test_decimal(self):
        assert parse_item("1.5") == Item(Decimal("1.5"))

    def test_decimal_three_places(self):
        assert parse_item("1.234") == Item(Decimal("1.234"))

    def test_decimal_four_places_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_item("1.2345")

    def test_decimal_max_12_integer_digits(self):
        assert parse_item("999999999999.999") == Item(Decimal("999999999999.999"))

    def test_decimal_13_integer_digits_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_item("9999999999999.9")

    def test_decimal_negative(self):
        assert parse_item("-999999999999.999") == Item(Decimal("-999999999999.999"))

    def test_decimal_no_fractional_digits_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_item("1.")

    def test_number_followed_by_garbage_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_item("1a")

    def test_string(self):
        assert parse_item('"hello world"') == Item("hello world")

    def test_string_escapes(self):
        assert parse_item(r'"a \"quoted\" \\ path"') == Item('a "quoted" \\ path')

    def test_string_bad_escape_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_item(r'"bad \n escape"')

    def test_string_unterminated_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_item('"unterminated')

    def test_string_control_character_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_item('"bad\x1fchar"')

    def test_string_non_ascii_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_item('"café"')

    def test_token(self):
        assert parse_item("text/html") == Item(Token("text/html"))

    def test_token_star(self):
        assert parse_item("*") == Item(Token("*"))

    def test_token_not_confused_with_string(self):
        item = parse_item("gzip")
        assert isinstance(item.value, Token)
        assert item.value == "gzip"

    def test_byte_sequence(self):
        assert parse_item(":aGVsbG8=:") == Item(b"hello")

    def test_byte_sequence_empty(self):
        assert parse_item("::") == Item(b"")

    def test_byte_sequence_bad_alphabet_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_item(":aGVsbG8=!:")

    def test_byte_sequence_bad_padding_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_item(":aGVsbG:")

    def test_byte_sequence_unterminated_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_item(":aGVsbG8=")

    def test_boolean_true(self):
        assert parse_item("?1") == Item(True)

    def test_boolean_false(self):
        assert parse_item("?0") == Item(False)

    def test_boolean_invalid_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_item("?2")

    def test_parameters(self):
        assert parse_item('text/html; charset="utf-8";q=0.5') == Item(
            Token("text/html"), {"charset": "utf-8", "q": Decimal("0.5")}
        )

    def test_parameter_bare_boolean(self):
        assert parse_item("a;b") == Item(Token("a"), {"b": True})

    def test_parameter_duplicate_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_item("a;x=1;x=2")

    def test_parameter_uppercase_key_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_item("a;B=1")

    def test_trailing_garbage_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_item("1 2")

    def test_surrounding_ows_stripped(self):
        assert parse_item("  42 \t") == Item(42)


class TestParseList:
    def test_simple_list(self):
        assert parse_list("sugar, tea, rum") == [
            Item(Token("sugar")),
            Item(Token("tea")),
            Item(Token("rum")),
        ]

    def test_empty_list(self):
        assert parse_list("") == []
        assert parse_list("   ") == []

    def test_mixed_members(self):
        assert parse_list('1, "two", ?0, :aGk=:') == [
            Item(1),
            Item("two"),
            Item(False),
            Item(b"hi"),
        ]

    def test_inner_list(self):
        assert parse_list("(a b);p=1, c") == [
            InnerList([Item(Token("a")), Item(Token("b"))], {"p": 1}),
            Item(Token("c")),
        ]

    def test_inner_list_item_params(self):
        assert parse_list("(a;x=1 b)") == [
            InnerList([Item(Token("a"), {"x": 1}), Item(Token("b"))])
        ]

    def test_inner_list_empty(self):
        assert parse_list("()") == [InnerList()]

    def test_inner_list_comma_separator_fails(self):
        # inner list members are separated by SP, not commas
        with pytest.raises(StructuredFieldError):
            parse_list("(a, b)")

    def test_inner_list_unterminated_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_list("(a b")

    def test_trailing_comma_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_list("a, b,")

    def test_double_comma_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_list("a,, b")


class TestParseDictionary:
    def test_simple_dictionary(self):
        assert parse_dictionary("a=1, b=?0, c") == {
            "a": Item(1),
            "b": Item(False),
            "c": Item(True),
        }

    def test_empty_dictionary(self):
        assert parse_dictionary("") == {}

    def test_member_with_params(self):
        assert parse_dictionary("a=1;p=q, b;x") == {
            "a": Item(1, {"p": Token("q")}),
            "b": Item(True, {"x": True}),
        }

    def test_inner_list_member(self):
        assert parse_dictionary("a=(x y);p=1") == {
            "a": InnerList([Item(Token("x")), Item(Token("y"))], {"p": 1})
        }

    def test_duplicate_member_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_dictionary("a=1, a=2")

    def test_duplicate_member_across_lines_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_field(["a=1", "b=2, a=3"], "dictionary")

    def test_trailing_comma_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_dictionary("a=1,")

    def test_uppercase_key_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_dictionary("A=1")


class TestParseFieldMerging:
    def test_list_lines_merged(self):
        assert parse_field(["a, b", "c"], "list") == [
            Item(Token("a")),
            Item(Token("b")),
            Item(Token("c")),
        ]

    def test_dictionary_lines_merged(self):
        assert parse_field(["a=1", "b=2"], "dictionary") == {
            "a": Item(1),
            "b": Item(2),
        }

    def test_item_multiple_lines_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_field(["1", "2"], "item")

    def test_item_single_line(self):
        assert parse_field(["1"], "item") == Item(1)

    def test_no_values_fails(self):
        with pytest.raises(StructuredFieldError):
            parse_field([], "list")

    def test_unknown_field_type_fails(self):
        with pytest.raises(ValueError):
            parse_field(["a"], "set")


class TestSerialize:
    def test_integer(self):
        assert serialize_item(42) == "42"
        assert serialize_item(-999999999999999) == "-999999999999999"

    def test_integer_out_of_range_fails(self):
        with pytest.raises(StructuredFieldError):
            serialize_item(9999999999999999)

    def test_decimal_trailing_zeros_stripped(self):
        assert serialize_item(Decimal("1.500")) == "1.5"
        assert serialize_item(Decimal("2.000")) == "2.0"
        assert serialize_item(Decimal("1.234")) == "1.234"

    def test_decimal_rounded_to_three_places(self):
        assert serialize_item(Decimal("1.23456")) == "1.235"
        assert serialize_item(Decimal("2.0004")) == "2.0"

    def test_decimal_out_of_range_fails(self):
        with pytest.raises(StructuredFieldError):
            serialize_item(Decimal("1000000000000.0"))

    def test_float_rejected(self):
        with pytest.raises(StructuredFieldError):
            serialize_item(1.5)

    def test_string_escaped(self):
        assert serialize_item('a "b" \\ c') == r'"a \"b\" \\ c"'

    def test_string_non_ascii_fails(self):
        with pytest.raises(StructuredFieldError):
            serialize_item("café")

    def test_token(self):
        assert serialize_item(Token("text/html")) == "text/html"

    def test_token_invalid_fails(self):
        with pytest.raises(StructuredFieldError):
            serialize_item(Token("not a token"))

    def test_bytes(self):
        assert serialize_item(b"hello") == ":aGVsbG8=:"

    def test_boolean(self):
        assert serialize_item(True) == "?1"
        assert serialize_item(False) == "?0"

    def test_item_with_params(self):
        assert (
            serialize_item(Item(Token("text/html"), {"q": Decimal("0.5"), "x": True}))
            == "text/html;q=0.5;x"
        )

    def test_param_invalid_key_fails(self):
        with pytest.raises(StructuredFieldError):
            serialize_item(Item(1, {"Bad Key": 1}))

    def test_list(self):
        assert serialize_list([Token("a"), Item(1, {"p": 2}), [Token("x"), "y"]]) == (
            'a, 1;p=2, (x "y")'
        )

    def test_inner_list_params(self):
        assert serialize_list([InnerList([Token("a")], {"p": 1})]) == "(a);p=1"

    def test_dictionary(self):
        assert serialize_dictionary(
            {
                "a": 1,
                "b": True,
                "c": Item(False),
                "d": InnerList([Token("x")], {"p": 1}),
                "e": Item(Token("tok"), {"q": Decimal("0.5")}),
            }
        ) == "a=1, b, c=?0, d=(x);p=1, e=tok;q=0.5"

    def test_dictionary_true_with_params(self):
        assert serialize_dictionary({"a": Item(True, {"p": 1})}) == "a;p=1"

    def test_dictionary_invalid_key_fails(self):
        with pytest.raises(StructuredFieldError):
            serialize_dictionary({"Bad": 1})

    def test_serialize_field_infers_type(self):
        assert serialize_field({"a": 1}) == "a=1"
        assert serialize_field([Token("a")]) == "a"
        assert serialize_field(1) == "1"

    def test_roundtrip_decimal_precision(self):
        wire = "1.005, 999999999999.999, -0.001"
        parsed = parse_list(wire)
        assert [item.value for item in parsed] == [
            Decimal("1.005"),
            Decimal("999999999999.999"),
            Decimal("-0.001"),
        ]
        assert serialize_list(parsed) == wire

    def test_roundtrip_inner_list_separators(self):
        wire = '("a b" :eHl6:);lvl=2, (x;y=?0 z);p="q v"'
        parsed = parse_list(wire)
        assert serialize_list(parsed) == wire


class TestResponseHeadersStructuredAccess:
    def make_headers(self, pairs):
        headers = ResponseHeaders()
        for name, value in pairs:
            headers.add(name, value)
        return headers

    def test_get_structured_item(self):
        headers = self.make_headers([("X-Rate", "1.5;p=2")])
        assert headers.get_structured("X-Rate", "item") == Item(
            Decimal("1.5"), {"p": 2}
        )

    def test_get_structured_list_merges_repeated_headers(self):
        headers = self.make_headers([("X-Tags", "a, b"), ("X-Tags", "c")])
        assert headers.get_structured("X-Tags", "list") == [
            Item(Token("a")),
            Item(Token("b")),
            Item(Token("c")),
        ]

    def test_get_structured_dictionary_merges_repeated_headers(self):
        headers = self.make_headers([("X-Opts", "a=1"), ("X-Opts", "b=?0")])
        assert headers.get_structured("X-Opts", "dictionary") == {
            "a": Item(1),
            "b": Item(False),
        }

    def test_get_structured_item_repeated_fails(self):
        headers = self.make_headers([("X-Rate", "1"), ("X-Rate", "2")])
        with pytest.raises(StructuredFieldError):
            headers.get_structured("X-Rate", "item")

    def test_get_structured_missing_raises_keyerror(self):
        headers = self.make_headers([])
        with pytest.raises(KeyError):
            headers.get_structured("X-Missing", "list")

    def test_get_structured_invalid_raises(self):
        headers = self.make_headers([("X-Rate", "1.2345")])
        with pytest.raises(StructuredFieldError):
            headers.get_structured("X-Rate", "item")

    def test_set_structured_writes_canonical_form(self):
        headers = self.make_headers([])
        headers.set_structured("X-Rate", Item(Decimal("1.500"), {"p": True}))
        assert headers["X-Rate"] == "1.5;p"

    def test_set_structured_replaces_existing_lines(self):
        headers = self.make_headers([("X-Tags", "old"), ("X-Tags", "older")])
        headers.set_structured("X-Tags", [Token("a"), Token("b")])
        assert headers.getall("X-Tags") == ["a, b"]

    def test_plain_header_api_unchanged(self):
        headers = self.make_headers([("X-Tags", "a, b"), ("X-Tags", "c")])
        assert headers["X-Tags"] == "c"
        assert headers.getall("X-Tags") == ["a, b", "c"]
        headers["X-Tags"] = "x, y, z"
        assert headers["X-Tags"] == "x, y, z"


class TestEnvironHeadersStructuredAccess:
    def test_get_structured(self):
        request = Request.blank("/", headers={"X-Opts": "a=1, b"})
        assert request.headers.get_structured("X-Opts", "dictionary") == {
            "a": Item(1),
            "b": Item(True),
        }

    def test_get_structured_missing_raises_keyerror(self):
        request = Request.blank("/")
        with pytest.raises(KeyError):
            request.headers.get_structured("X-Missing", "item")

    def test_get_structured_invalid_raises(self):
        request = Request.blank("/", headers={"X-Opts": "a=1, a=2"})
        with pytest.raises(StructuredFieldError):
            request.headers.get_structured("X-Opts", "dictionary")

    def test_set_structured(self):
        headers = EnvironHeaders({})
        headers.set_structured("X-Tags", [Token("a"), Token("b")])
        assert headers["X-Tags"] == "a, b"
