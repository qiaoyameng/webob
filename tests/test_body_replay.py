from io import BytesIO
from urllib.parse import parse_qsl, urlencode

import pytest

from webob.request import BodyReplayView, Request


class CountingInput:
    """A wsgi.input stand-in that tracks how much the source was consumed."""

    def __init__(self, data):
        self._fp = BytesIO(data)
        self.bytes_read = 0

    def read(self, size=-1):
        data = self._fp.read(size)
        self.bytes_read += len(data)

        return data


def _make_form_request(fields, body_cls=BytesIO):
    body = urlencode(fields).encode("ascii")
    req = Request.blank(
        "/",
        method="POST",
        content_type="application/x-www-form-urlencoded",
        body=body,
    )
    req.environ["wsgi.input"] = body_cls(body)

    return req, body


class TestBodyReplayView:
    def test_interleaved_views_then_form_parse(self):
        fields = [("name", "value"), ("foo", "bar"), ("multi", "1"), ("multi", "2")]
        req, body = _make_form_request(fields)

        # the audit middleware and the form parser each get their own view
        audit = req.body_replay_view()
        parser = req.body_replay_view()

        # interleave reads between the two views; each keeps its own cursor
        assert audit.read(5) == body[:5]
        assert parser.read(10) == body[:10]
        assert audit.read(5) == body[5:10]
        assert parser.read(4) == body[10:14]

        # rewinding one view must not disturb the other
        assert audit.seek(0) == 0
        assert audit.read(8) == body[:8]
        assert parser.read(2) == body[14:16]

        # a third view parses the form from the very beginning
        form = req.body_replay_view()
        assert parse_qsl(form.read().decode("ascii")) == fields

        # the siblings are still valid and positioned where they left off
        assert parser.read() == body[16:]
        assert audit.read() == body[8:]

        for view in (audit, parser, form):
            view.close()

    def test_source_is_consumed_only_once(self):
        req, body = _make_form_request([("a", "1"), ("b", "2")], CountingInput)
        source = req.environ["wsgi.input"]

        views = [req.body_replay_view() for _ in range(3)]

        for view in views:
            assert view.read() == body
            view.seek(0)
            assert view.read() == body
            view.close()

        assert source.bytes_read == len(body)

    def test_shallow_copy_shares_replay_storage(self):
        req, body = _make_form_request([("a", "1")], CountingInput)
        source = req.environ["wsgi.input"]

        first = req.body_replay_view()
        copied = Request(req.environ.copy())
        second = copied.body_replay_view()

        assert first.read() == body
        assert second.read() == body
        assert source.bytes_read == len(body)

        first.close()
        second.close()

    def test_spills_to_tempfile_over_limit(self):
        fields = [("field%d" % i, "value%d" % i) for i in range(20)]
        req, body = _make_form_request(fields)
        req.request_body_tempfile_limit = 16

        view = req.body_replay_view()
        assert view.read() == body

        store = req.environ["webob._body_replay_store"]
        assert store._in_tempfile

        view.seek(0)
        assert parse_qsl(view.read().decode("ascii")) == fields
        view.close()

    def test_unknown_length_requires_termination_semantics(self):
        req, body = _make_form_request([("a", "1")])
        del req.environ["CONTENT_LENGTH"]

        with pytest.raises(ValueError):
            req.body_replay_view()

    def test_unknown_length_reads_to_eof_when_terminated(self):
        req, body = _make_form_request([("a", "1"), ("b", "2")])
        del req.environ["CONTENT_LENGTH"]
        req.environ["wsgi.input_terminated"] = True

        view = req.body_replay_view()
        assert view.read() == body
        assert view.read() == b""
        view.close()

    def test_closing_one_view_keeps_siblings_alive(self):
        req, body = _make_form_request([("a", "1"), ("b", "2")])
        first = req.body_replay_view()
        second = req.body_replay_view()

        first.read(3)
        first.close()

        # the surviving view is unaffected and can still pull new data
        assert second.read() == body

        store = req.environ["webob._body_replay_store"]
        assert not store.closed

        second.close()
        assert store.closed

        with pytest.raises(ValueError):
            store.open_view()

    def test_closed_view_rejects_operations(self):
        req, body = _make_form_request([("a", "1")])
        view = req.body_replay_view()
        view.close()
        view.close()  # closing twice is harmless

        with pytest.raises(ValueError):
            view.read()
        with pytest.raises(ValueError):
            view.readline()
        with pytest.raises(ValueError):
            view.seek(0)
        with pytest.raises(ValueError):
            view.tell()

    def test_read_readline_seek_boundaries(self):
        body = b"first line\nsecond line\n\nlast line"
        req = Request.blank("/", method="POST", body=body)
        view = req.body_replay_view()

        # read boundaries
        assert view.read(0) == b""
        assert view.tell() == 0
        assert view.read(6) == b"first "
        assert view.read(-1) == body[6:]
        assert view.read() == b""
        assert view.read(10) == b""

        # readline boundaries
        assert view.seek(0) == 0
        assert view.readline(0) == b""
        assert view.tell() == 0
        assert view.readline(5) == b"first"
        assert view.readline() == b" line\n"
        assert view.readline() == b"second line\n"
        assert view.readline() == b"\n"
        assert view.readline(100) == b"last line"
        assert view.readline() == b""

        # seek boundaries
        assert view.seek(-10, 2) == len(body) - 10
        assert view.read() == body[-10:]
        assert view.seek(0, 1) == len(body)
        assert view.seek(len(body) + 5) == len(body) + 5
        assert view.read() == b""
        assert view.readline() == b""

        with pytest.raises(ValueError):
            view.seek(-1)
        with pytest.raises(ValueError):
            view.seek(0, 3)

        view.close()

    def test_readinto_and_iteration(self):
        body = b"line one\nline two\n"
        req = Request.blank("/", method="POST", body=body)
        view = req.body_replay_view()

        buff = bytearray(9)
        assert view.readinto(buff) == 9
        assert bytes(buff) == b"line one\n"

        assert list(view) == [b"line two\n"]
        view.close()

    def test_view_is_a_binary_io_base(self):
        req, _ = _make_form_request([("a", "1")])
        view = req.body_replay_view()

        assert isinstance(view, BodyReplayView)
        assert view.readable()
        assert view.seekable()
        assert not view.writable()

        with req.body_replay_view() as ctx_view:
            assert ctx_view.read(1) == b"a"
        assert ctx_view.closed

        view.close()

    def test_short_body_raises_disconnection_error(self):
        from webob.request import DisconnectionError

        req = Request.blank("/", method="POST", body=b"abc")
        req.environ["CONTENT_LENGTH"] = "10"

        view = req.body_replay_view()

        with pytest.raises(DisconnectionError):
            view.read()

        view.close()
