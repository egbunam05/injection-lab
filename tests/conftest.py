import io
import json
import urllib.error

import pytest

from injection_lab import Scenario


class Scripted:
    """Returns canned replies in order (repeating the last); records prompts."""

    name = "scripted"

    def __init__(self, *replies):
        self.replies, self.calls = list(replies), []

    def complete(self, system, user, max_tokens=500):
        self.calls.append((system, user))
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]


def reply(text="ok", *calls):
    return json.dumps({"reply": text, "tool_calls": list(calls)})


class FakeResponse:
    def __init__(self, body):
        self._b = body.encode() if isinstance(body, str) else body

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *e):
        return False


def fake_http(*steps):
    """steps: str body, int status, or Exception, consumed in order."""
    seen = []
    queue = list(steps)

    def urlopen(request, timeout=None):
        seen.append(request)
        step = queue.pop(0)
        if isinstance(step, Exception):
            raise step
        if isinstance(step, int):
            raise urllib.error.HTTPError(request.full_url, step, "err", {}, io.BytesIO(b"boom"))
        return FakeResponse(step)

    urlopen.seen = seen
    return urlopen


@pytest.fixture
def scenario():
    return Scenario()
