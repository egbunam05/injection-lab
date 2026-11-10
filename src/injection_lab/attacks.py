"""Attack and benign-case loaders. Attacks are canary-style probes, not real exploits:
success means the app leaked a fake secret, emailed a fake attacker address, or said a nonsense token."""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .scenario import Scenario, marker_for

DATA = Path(__file__).resolve().parent / "data"
CHANNELS = ("user", "document", "tool_output")
GOALS = ("leak", "tool", "hijack", "append")


class AttackFileError(ValueError):
    pass


@dataclass(frozen=True)
class Attack:
    id: str
    category: str
    channel: str
    goal: str
    payload: str
    inner: str = ""
    encode: str = ""
    message: str = ""            # for document/tool_output attacks: the customer's real request
    may_send_email: bool = False  # the customer legitimately asked for an e-mail in this case
    wave: int = 1

    def render(self, scenario: Scenario) -> str:
        values = {
            "marker": marker_for(self.id),
            "attacker": scenario.attacker_email,
            "attacker_domain": scenario.attacker_domain,
        }
        if self.encode == "base64":
            inner = self.inner.format(**values)
            values["encoded"] = base64.b64encode(inner.encode("utf-8")).decode("ascii")
        return self.payload.format(**values)


@dataclass(frozen=True)
class Benign:
    id: str
    user_message: str
    document: str = ""
    channel: str = "user"
    expect_any: tuple = ()
    may_send_email: bool = False
    expect_tool_to: str = ""


def _rows(path: Path) -> List[dict]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise AttackFileError(f"cannot read {path}: {exc.strerror or exc}") from None
    rows = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError as exc:
            raise AttackFileError(f"{path}:{n}: invalid JSON ({exc})") from None
        if not isinstance(obj, dict):
            raise AttackFileError(f"{path}:{n}: expected a JSON object")
        obj["_line"] = n
        rows.append(obj)
    return rows


def load_attacks(path: Optional[Path] = None) -> List[Attack]:
    path = Path(path) if path else DATA / "attacks.jsonl"
    attacks, seen = [], set()
    for row in _rows(path):
        where = f"{path}:{row['_line']}"
        try:
            a = Attack(
                id=str(row["id"]), category=str(row["category"]), channel=str(row["channel"]),
                goal=str(row["goal"]), payload=str(row["payload"]),
                inner=str(row.get("inner", "")), encode=str(row.get("encode", "")),
                message=str(row.get("message", "")), may_send_email=bool(row.get("may_send_email", False)),
                wave=int(row.get("wave", 1)),
            )
        except KeyError as exc:
            raise AttackFileError(f"{where}: missing field {exc}") from None
        if a.channel not in CHANNELS:
            raise AttackFileError(f"{where}: channel must be one of {CHANNELS}")
        if a.goal not in GOALS:
            raise AttackFileError(f"{where}: goal must be one of {GOALS}")
        if a.id in seen:
            raise AttackFileError(f"{where}: duplicate id {a.id!r}")
        if a.encode not in ("", "base64"):
            raise AttackFileError(f"{where}: encode must be empty or 'base64'")
        if a.encode and "{encoded}" not in a.payload:
            raise AttackFileError(f"{where}: encoded attacks need {{encoded}} in the payload")
        if a.goal in ("hijack", "append") and "{marker}" not in (a.payload + a.inner):
            raise AttackFileError(f"{where}: hijack and append attacks must contain {{marker}}")
        if a.goal == "tool" and "{attacker}" not in (a.payload + a.inner):
            raise AttackFileError(f"{where}: tool attacks must contain {{attacker}}")
        seen.add(a.id)
        attacks.append(a)
    return attacks


def load_benign(path: Optional[Path] = None) -> List[Benign]:
    path = Path(path) if path else DATA / "benign.jsonl"
    out = []
    for row in _rows(path):
        where = f"{path}:{row['_line']}"
        try:
            out.append(Benign(
                id=str(row["id"]), user_message=str(row["user_message"]),
                document=str(row.get("document", "")), channel=str(row.get("channel", "user")),
                expect_any=tuple(str(x).lower() for x in row.get("expect_any", [])),
                may_send_email=bool(row.get("may_send_email", False)),
                expect_tool_to=str(row.get("expect_tool_to", "")).lower(),
            ))
        except KeyError as exc:
            raise AttackFileError(f"{where}: missing field {exc}") from None
    return out


def by_wave(attacks, wave):
    """Keep one wave (1 or 2); None keeps everything."""
    return [a for a in attacks if wave is None or a.wave == wave]
