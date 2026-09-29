import io
from urllib.parse import parse_qsl, urlencode

import pytest

from webob.request import (
    BaseRequest,
    BodyReplayStore,
    DisconnectionError,
)


class CountingStream:
    """A wsgi.input stand-in that tracks how much was actually read."""

    def __init__(self, data):
        self._fp = io.BytesIO(data)
        self.bytes_read = 0
        self.read_calls = 0

    def read(self, size=-1):
        self.read_calls += 1
        data = self._fp.read(size)
        self.bytes_read += len(data)

        return data


def make_request(body, stream=None, content_length=None, terminated=None):
    if stream is None:
        stream = io.BytesIO(body)
    if content_length is None:
        content_length = len(body)
    environ = {
        "REQUEST_METHOD": "POST",
        "SCRIPT_NAME": "",
        "PATH_INFO": "/",
        "QUERY_STRING": "",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "HTTP_HOST": "localhost:80",
        "SERVER_PROTOCOL": "HTTP/1.0",
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "http",
        "wsgi.input": stream,
        "wsgi.errors": io.BytesIO(),
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
        "CONTENT_TYPE": "application/x-www-form-urlencoded",
    }
    if content_length is not None:
        environ["CONTENT_LENGTH"] = str(content_length)
    if terminated is not None:
        environ["wsgi.input_terminated"] = terminated

    return BaseRequest(environ)


def get_store(req):
    return req.environ["webob.body_replay_store"][0]


class TestInterleavedReplay:
    def test_interleaved_views_and_form_parse(self):
        fields = [
            ("name", "alice"),
            ("comment", "line1 line2"),
            ("tag", "a"),
            ("tag", "b"),
            ("empty", ""),
        ]
        body = urlencode(fields).encode("ascii")
        stream = CountingStream(body)
        req = make_request(body, stream=stream)

        view1 = req.body_replay_view()
        view2 = req.body_replay_view()

        pieces1 = []
        pieces2 = []

        # Interleave reads between the two independent cursors.
        pieces1.append(view1.read(5))
        pieces2.append(view2.read(9))
        pieces1.append(view1.read(3))
        assert view1.tell() == 8
        assert view2.tell() == 9

        # Rewinding one view must not disturb the other.
        assert view2.seek(0) == 0
        pieces2 = [view2.read(7)]
        pieces1.append(view1.read(6))
        pieces2.append(view2.read())
        pieces1.append(view1.read())

        assert b"".join(pieces1) == body
        assert b"".join(pieces2) == body

        # A third view parses the form from the same shared storage.
        with req.body_replay_view() as view3:
            parsed = parse_qsl(
                view3.read().decode("ascii"), keep_blank_values=True
            )
        assert parsed == fields

        # The original stream was consumed exactly once, in full.
        assert stream.bytes_read == len(body)

        view1.close()
        view2.close()

    def test_views_share_one_store(self):
        req = make_request(b"a=1&b=2")
        view1 = req.body_replay_view()
        view2 = req.body_replay_view()
        assert view1._store is view2._store
        view1.close()
        view2.close()

    def test_store_invalidated_when_body_file_changes(self):
        req = make_request(b"a=1")
        view1 = req.body_replay_view()
        req.body_file = io.BytesIO(b"z=9")
        view2 = req.body_replay_view()
        assert view2._store is not view1._store
        assert view2.read() == b"z=9"
        view1.close()
        view2.close()


class TestBoundaries:
    def test_seek_read_readline_agree_on_bounds(self):
        body = b"alpha\nbeta\ngamma"
        req = make_request(body)
        view = req.body_replay_view()

        # seek clamps to [0, len(body)]
        assert view.seek(-5) == 0
        assert view.seek(1000) == len(body)
        assert view.read() == b""
        assert view.readline() == b""

        assert view.seek(0) == 0
        assert view.readline() == b"alpha\n"
        assert view.readline(3) == b"bet"
        assert view.readline() == b"a\n"
        assert view.read(4) == b"gamm"
        assert view.tell() == len(body) - 1
        assert view.read(10) == b"a"
        assert view.readline(10) == b""

        # SEEK_CUR and SEEK_END are clamped the same way.
        assert view.seek(2, io.SEEK_END) == len(body)
        assert view.seek(-5, io.SEEK_END) == len(body) - 5
        assert view.read() == b"gamma"[-5:]
        assert view.seek(-100, io.SEEK_CUR) == 0
        view.close()

    def test_readline_size_zero(self):
        req = make_request(b"a\nb")
        view = req.body_replay_view()
        assert view.readline(0) == b""
        assert view.readline() == b"a\n"
        view.close()

    def test_read_beyond_content_length_is_clamped(self):
        stream = CountingStream(b"abcdef")
        req = make_request(b"abcdef", stream=stream, content_length=3)
        view = req.body_replay_view()
        assert view.read() == b"abc"
        assert stream.bytes_read == 3
        view.close()

    def test_short_stream_raises_disconnection(self):
        stream = CountingStream(b"abc")
        req = make_request(b"abc", stream=stream, content_length=10)
        view = req.body_replay_view()
        with pytest.raises(DisconnectionError):
            view.read()
        view.close()

    def test_empty_body(self):
        req = make_request(b"", content_length=0)
        view = req.body_replay_view()
        assert view.read() == b""
        assert view.readline() == b""
        assert view.seek(0, io.SEEK_END) == 0
        view.close()


class TestUnknownLength:
    def test_unknown_length_without_termination_raises(self):
        req = make_request(b"a=1", content_length=None)
        del req.environ["CONTENT_LENGTH"]
        with pytest.raises(ValueError, match="wsgi.input_terminated"):
            req.body_replay_view()

    def test_unknown_length_terminated_reads_to_eof(self):
        body = b"name=bob&city=paris"
        stream = CountingStream(body)
        req = make_request(body, stream=stream, terminated=True)
        del req.environ["CONTENT_LENGTH"]

        view = req.body_replay_view()
        assert view.read(4) == b"name"
        assert view.read() == b"=bob&city=paris"
        assert view.read() == b""
        assert stream.bytes_read == len(body)

        # The end is only known once EOF was reached; seek agrees.
        assert view.seek(0, io.SEEK_END) == len(body)
        assert view.seek(0) == 0
        assert view.readline() == body  # no newline: reads to EOF
        view.close()

    def test_store_rejects_unknown_length_without_termination(self):
        with pytest.raises(ValueError):
            BodyReplayStore(io.BytesIO(b"abc"), content_length=None)

    def test_store_unknown_length_terminated(self):
        store = BodyReplayStore(
            io.BytesIO(b"abc"), content_length=None, terminated=True
        )
        view = store.open_view()
        assert view.read() == b"abc"
        view.close()


class TestTempfileSpill:
    def test_spills_to_tempfile_beyond_limit(self):
        body = urlencode([("k", "v" * 4096)]).encode("ascii")
        stream = CountingStream(body)
        req = make_request(body, stream=stream)
        req.request_body_tempfile_limit = 1024

        view1 = req.body_replay_view()
        view2 = req.body_replay_view()
        assert view1.read() == body
        assert view2.read() == body
        assert get_store(req)._spilled
        assert stream.bytes_read == len(body)
        view1.close()
        view2.close()

    def test_small_body_stays_in_memory(self):
        req = make_request(b"a=1")
        view = req.body_replay_view()
        assert view.read() == b"a=1"
        assert not get_store(req)._spilled
        view.close()


class TestCloseSemantics:
    def test_closing_one_view_keeps_others_usable(self):
        body = b"a=1&b=2&c=3"
        req = make_request(body)
        view1 = req.body_replay_view()
        view2 = req.body_replay_view()

        view1.read(2)
        view1.close()

        with pytest.raises(ValueError):
            view1.read(1)
        with pytest.raises(ValueError):
            view1.seek(0)

        # The surviving view is unaffected and can read everything.
        assert view2.read() == body
        assert not get_store(req).released

        view2.close()
        assert get_store(req).released

    def test_last_close_releases_storage(self):
        body = urlencode([("k", "v" * 4096)]).encode("ascii")
        req = make_request(body)
        req.request_body_tempfile_limit = 1024
        view1 = req.body_replay_view()
        view2 = req.body_replay_view()
        view1.read()
        store = get_store(req)
        storage = store._file

        view1.close()
        assert not storage.closed
        view2.close()
        assert storage.closed

    def test_no_new_views_after_release(self):
        req = make_request(b"a=1")
        view = req.body_replay_view()
        view.close()
        with pytest.raises(ValueError, match="released"):
            req.body_replay_view()

    def test_view_is_context_manager(self):
        req = make_request(b"a=1")
        with req.body_replay_view() as view:
            assert view.read() == b"a=1"
        assert view.closed
        assert get_store(req).released

    def test_iteration_yields_lines(self):
        req = make_request(b"one\ntwo\nthree")
        with req.body_replay_view() as view:
            assert list(view) == [b"one\n", b"two\n", b"three"]
