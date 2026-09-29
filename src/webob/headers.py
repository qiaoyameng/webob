from collections.abc import MutableMapping

from webob import structured
from webob.multidict import MultiDict

__all__ = ["ResponseHeaders", "EnvironHeaders"]


class ResponseHeaders(MultiDict):
    """
    Dictionary view on the response headerlist.
    Keys are normalized for case and whitespace.
    """

    def __getitem__(self, key):
        key = key.lower()

        for k, v in reversed(self._items):
            if k.lower() == key:
                return v
        raise KeyError(key)

    def getall(self, key):
        key = key.lower()

        return [v for (k, v) in self._items if k.lower() == key]

    def mixed(self):
        r = self.dict_of_lists()

        for key, val in r.items():
            if len(val) == 1:
                r[key] = val[0]

        return r

    def dict_of_lists(self):
        r = {}

        for key, val in self.items():
            r.setdefault(key.lower(), []).append(val)

        return r

    def __setitem__(self, key, value):
        norm_key = key.lower()
        self._items[:] = [(k, v) for (k, v) in self._items if k.lower() != norm_key]
        self._items.append((key, value))

    def __delitem__(self, key):
        key = key.lower()
        items = self._items
        found = False

        for i in range(len(items) - 1, -1, -1):
            if items[i][0].lower() == key:
                del items[i]
                found = True

        if not found:
            raise KeyError(key)

    def __contains__(self, key):
        key = key.lower()

        for k, _ in self._items:
            if k.lower() == key:
                return True

        return False

    has_key = __contains__

    def setdefault(self, key, default=None):
        c_key = key.lower()

        for k, v in self._items:
            if k.lower() == c_key:
                return v
        self._items.append((key, default))

        return default

    def get_structured(self, key, field_type):
        """Return this header parsed as an HTTP Structured Field.

        ``field_type`` is one of ``"item"``, ``"list"`` or
        ``"dictionary"`` (see :mod:`webob.structured`).  Repeated
        header lines are combined according to the field type: lists
        and dictionaries are merged, while an item field must appear
        exactly once.  Raises :exc:`KeyError` if the header is absent
        and :exc:`~webob.structured.StructuredFieldError` if the value
        is not valid for the declared type.
        """
        values = self.getall(key)

        if not values:
            raise KeyError(key)

        return structured.parse_field(values, field_type)

    def set_structured(self, key, value, field_type=None):
        """Serialize ``value`` as an HTTP Structured Field header.

        This replaces any existing lines for the header with a single
        line in canonical form.  ``field_type`` defaults to being
        inferred from ``value`` (see
        :func:`webob.structured.serialize_field`).
        """
        self[key] = structured.serialize_field(value, field_type)

    def pop(self, key, *args):
        if len(args) > 1:
            raise TypeError(
                "pop expected at most 2 arguments, got %s" % repr(1 + len(args))
            )
        key = key.lower()

        for i in range(len(self._items)):
            if self._items[i][0].lower() == key:
                v = self._items[i][1]
                del self._items[i]

                return v

        if args:
            return args[0]
        else:
            raise KeyError(key)


key2header = {
    "CONTENT_TYPE": "Content-Type",
    "CONTENT_LENGTH": "Content-Length",
    "HTTP_CONTENT_TYPE": "Content_Type",
    "HTTP_CONTENT_LENGTH": "Content_Length",
}

header2key = {v.upper(): k for (k, v) in key2header.items()}


def _trans_key(key):
    if not isinstance(key, str):
        return None
    elif key in key2header:
        return key2header[key]
    elif key.startswith("HTTP_"):
        return key[5:].replace("_", "-").title()
    else:
        return None


def _trans_name(name):
    name = name.upper()

    if name in header2key:
        return header2key[name]

    return "HTTP_" + name.replace("-", "_")


class EnvironHeaders(MutableMapping):
    """An object that represents the headers as present in a
    WSGI environment.

    This object is a wrapper (with no internal state) for a WSGI
    request object, representing the CGI-style HTTP_* keys as a
    dictionary.  Because a CGI environment can only hold one value for
    each key, this dictionary is single-valued (unlike outgoing
    headers).
    """

    def __init__(self, environ):
        self.environ = environ

    def __getitem__(self, hname):
        return self.environ[_trans_name(hname)]

    def __setitem__(self, hname, value):
        self.environ[_trans_name(hname)] = value

    def __delitem__(self, hname):
        del self.environ[_trans_name(hname)]

    def get_structured(self, hname, field_type):
        """Return this header parsed as an HTTP Structured Field.

        ``field_type`` is one of ``"item"``, ``"list"`` or
        ``"dictionary"`` (see :mod:`webob.structured`).  Raises
        :exc:`KeyError` if the header is absent and
        :exc:`~webob.structured.StructuredFieldError` if the value is
        not valid for the declared type.
        """
        return structured.parse_field(self[hname], field_type)

    def set_structured(self, hname, value, field_type=None):
        """Serialize ``value`` as an HTTP Structured Field header.

        ``field_type`` defaults to being inferred from ``value`` (see
        :func:`webob.structured.serialize_field`).
        """
        self[hname] = structured.serialize_field(value, field_type)

    def keys(self):
        return filter(None, map(_trans_key, self.environ))

    def __contains__(self, hname):
        return _trans_name(hname) in self.environ

    def __len__(self):
        return len(list(self.keys()))

    def __iter__(self):
        yield from self.keys()
