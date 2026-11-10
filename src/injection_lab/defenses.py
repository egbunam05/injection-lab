"""Four defenses, each usable alone or stacked.

sanitize      input heuristic: drop sentences that look like injected instructions, redact unknown e-mail addresses
spotlight     prompt-level: wrap untrusted text in random markers and tell the model it is data (needs a real model to measure)
output_guard  output check: block replies/tool arguments containing the canary (even obfuscated), strip external links
tool_policy   least privilege: send_email only if the customer asked for it, and only to allow-listed addresses
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Dict, Iterable, List, Tuple

from .detect import leaked, strip_external_urls

KNOWN = ("sanitize", "spotlight", "output_guard", "tool_policy")
LADDER: List[Tuple[str, Tuple[str, ...]]] = [
    ("none", ()),
    ("sanitize", ("sanitize",)),
    ("spotlight", ("spotlight",)),
    ("output_guard", ("output_guard",)),
    ("tool_policy", ("tool_policy",)),
    ("guard+policy", ("output_guard", "tool_policy")),
    ("all", KNOWN),
]

BLOCKED_REPLY = "Sorry, I can't share that."

_PATTERNS = [
    r"\bignore\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier)\b",
    r"\bdisregard\s+(all\s+|any\s+|the\s+|everything\s+)?(previous|prior|above|earlier)?\b.*\b(instruction|above|before)",
    r"\b(reveal|print|show|output|repeat|display|disclose)\w*\b[^.\n]{0,40}\b(system prompt|reference code|your instructions|configuration)",
    r"\bnew instructions?\s*:",
    r"\bsystem\s+(notice|message|override|prompt)\b",
    r"\b(note|message|instruction)s?\s+(to|for)\s+(the\s+)?(ai|assistant|llm|model)s?\b",
    r"\bai assistants? reading\b",
    r"\byou are now\b",
    r"\b(developer|debug|admin|audit)\s+mode\b",
    r"\bact as\b[^.\n]{0,40}\b(grandmother|grandma)\b",
    r"\b(decode|decrypt)\b[^.\n]{0,40}\b(follow|obey|do what)",
    r"</?\s*(document|tool_result|system)\b",
    r"\bsend_email\b",
]
_COMPILED = [re.compile(p, re.I) for p in _PATTERNS]
_EMAIL = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")


def sanitize_text(text: str, allowed_domains: Iterable[str]) -> Tuple[str, List[str]]:
    """Return (cleaned text, list of what was removed)."""
    allowed = set(allowed_domains)
    hits: List[str] = []

    def redact(m: "re.Match[str]") -> str:
        if m.group(1).lower() in allowed:
            return m.group(0)
        hits.append("unknown_email")
        return "[email removed]"

    text = _EMAIL.sub(redact, text)
    kept = []
    for part in _SENTENCE.split(text):
        if not part.strip():
            continue
        if any(p.search(part) for p in _COMPILED):
            hits.append("injection_phrase")
            kept.append("[filtered]")
        else:
            kept.append(part)
    return "\n".join(kept) if hits else text, hits


def spotlight_wrap(text: str, seed: str) -> str:
    nonce = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:8]
    safe = text.replace("<<", "< <").replace(">>", "> >")
    return f"<<DATA-{nonce}>>\n{safe}\n<<END-{nonce}>>"


def plain_wrap(text: str, channel: str) -> str:
    if channel == "tool_output":
        return f'<tool_result name="web_search">\n{text}\n</tool_result>'
    return f"<document>\n{text}\n</document>"


def guard_output(reply: str, calls: List[dict], canary: str, allowed_domains: Iterable[str]):
    reasons: List[str] = []
    if leaked(canary, reply)[0]:
        reply = BLOCKED_REPLY
        reasons.append("canary_in_reply")
    else:
        cleaned = strip_external_urls(reply, allowed_domains)
        if cleaned != reply:
            reasons.append("external_link")
            reply = cleaned
    kept = []
    for call in calls:
        if leaked(canary, json.dumps(call))[0]:
            reasons.append("canary_in_tool_args")
        else:
            kept.append(call)
    return reply, kept, reasons


def apply_tool_policy(calls: List[dict], may_send_email: bool, allowed_emails: Iterable[str]):
    allowed = {e.lower() for e in allowed_emails}
    kept, reasons = [], []
    for call in calls:
        to = str(call.get("to", "")).strip().lower()
        if not may_send_email:
            reasons.append("tool_not_requested")
        elif to not in allowed:
            reasons.append("recipient_not_allowed")
        else:
            kept.append(call)
    return kept, reasons


def parse_defenses(spec: str) -> Tuple[str, ...]:
    """'none', 'all', a ladder label such as 'guard+policy', or a '+' list of defense names."""
    spec = spec.strip()
    for label, names in LADDER:
        if spec == label:
            return names
    names = tuple(s.strip() for s in spec.split("+") if s.strip() and s.strip() != "none")
    bad = [n for n in names if n not in KNOWN]
    if bad:
        raise ValueError(f"unknown defense(s): {', '.join(bad)} (known: {', '.join(KNOWN)})")
    return names
