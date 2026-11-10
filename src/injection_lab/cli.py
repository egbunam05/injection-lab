"""injection-lab command line."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .app import case_from_attack, build_prompt, run_case
from .attacks import AttackFileError, by_wave, load_attacks, load_benign
from .defenses import KNOWN, LADDER, parse_defenses
from .eval import render_markdown, run_matrix, summarize
from .llm import make_llm
from .scenario import Scenario


def _add_llm(p: argparse.ArgumentParser) -> None:
    p.add_argument("--llm", default="mock", choices=["mock", "anthropic", "groq", "openai"],
                   help="mock is a simulated worst-case model; the others call a real API")
    p.add_argument("--model", help="model name (or set INJECTION_LAB_MODEL)")
    p.add_argument("--base-url", help="for --llm openai: any OpenAI-compatible endpoint")
    p.add_argument("--api-key-env", help="name of the environment variable holding the API key")
    p.add_argument("--attacks", type=Path, help="your own attacks.jsonl")
    p.add_argument("--wave", type=int, choices=[1, 2], help="only wave 1 (basic) or wave 2 (harder) attacks")


def cmd_attacks(args) -> int:
    attacks = by_wave(load_attacks(args.attacks), getattr(args, "wave", None))
    if args.category:
        attacks = [a for a in attacks if a.category == args.category]
    scenario = Scenario()
    for a in attacks:
        print(f"{a.id:28} w{a.wave} {a.category:16} {a.channel:12} {a.goal}")
        if args.show:
            print("    " + a.render(scenario).replace("\n", "\n    "))
    print(f"\n{len(attacks)} attack(s)")
    return 0


def cmd_run(args) -> int:
    attacks = {a.id: a for a in load_attacks(args.attacks)}
    if args.attack not in attacks:
        print(f"error: unknown attack {args.attack!r}. Run `injection-lab attacks` to list them.", file=sys.stderr)
        return 2
    scenario, defenses = Scenario(), parse_defenses(args.defense)
    case = case_from_attack(attacks[args.attack], scenario)
    system, user, _ = build_prompt(case, defenses, scenario)
    llm = make_llm(args.llm, args.model, args.base_url, args.api_key_env)
    result = run_case(case, llm, defenses, scenario)
    if args.show_prompt:
        print("--- system ---\n" + system + "\n--- user ---\n" + user + "\n")
    print(f"attack   : {case.id} ({case.category}, via {case.channel}, goal {case.goal})")
    print(f"defenses : {'+'.join(defenses) or 'none'}   model: {llm.name}")
    print(f"reply    : {result.reply}")
    for c in result.executed_calls:
        print(f"tool call: send_email to {c['to']}")
    print(f"raw model harms  : {', '.join(result.raw_harms) or 'none'}")
    print(f"final harms      : {', '.join(result.harms) or 'none'}   blocked by: {', '.join(result.blocked_by) or '-'}")
    print("verdict  : " + ("ATTACK SUCCEEDED" if result.attack_success else "attack stopped"))
    return 1 if result.attack_success else 0


def cmd_eval(args) -> int:
    attacks, benign = by_wave(load_attacks(args.attacks), args.wave), load_benign()
    if args.defenses:
        configs = [(spec, parse_defenses(spec)) for spec in args.defenses.split(",")]
    else:
        configs = list(LADDER)
    llm = make_llm(args.llm, args.model, args.base_url, args.api_key_env)
    matrix = run_matrix(attacks, benign, llm, configs, trials=args.trials, delay=args.delay,
                        progress=args.llm != "mock")
    md = render_markdown(matrix, llm.name, args.trials)
    print(md)
    if args.details:
        for label, results in matrix.items():
            for r in results:
                if r.attack_success:
                    print(f"  [{label}] {r.case_id}: {', '.join(r.harms)} -> {r.reply[:80]!r}")
    if args.markdown:
        Path(args.markdown).write_text(md, encoding="utf-8")
        print(f"wrote {args.markdown}")
    if args.json:
        payload = {"model": llm.name, "trials": args.trials,
                   "configs": {l: {"summary": summarize(rs), "results": [r.to_dict() for r in rs]} for l, rs in matrix.items()}}
        Path(args.json).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"wrote {args.json}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="injection-lab", description="Measure prompt-injection attacks and defenses on a small LLM app.")
    p.add_argument("--version", action="version", version=f"injection-lab {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("attacks", help="list the attack corpus")
    a.add_argument("--category")
    a.add_argument("--show", action="store_true", help="print each rendered payload")
    a.add_argument("--attacks", type=Path)
    a.add_argument("--wave", type=int, choices=[1, 2])
    a.set_defaults(func=cmd_attacks)

    r = sub.add_parser("run", help="run one attack and show what happened")
    r.add_argument("attack")
    r.add_argument("--defense", default="none", help=f"none or a '+' list of: {', '.join(KNOWN)}")
    r.add_argument("--show-prompt", action="store_true")
    _add_llm(r)
    r.set_defaults(func=cmd_run)

    e = sub.add_parser("eval", help="run every attack against every defense setting")
    e.add_argument("--defenses", help="comma list of settings, e.g. none,output_guard,output_guard+tool_policy (default: the full ladder)")
    e.add_argument("--trials", type=int, default=1, help="repeat each case (use >1 for real models)")
    e.add_argument("--delay", type=float, default=0.0, help="seconds to wait between API calls (free tiers rate-limit)")
    e.add_argument("--details", action="store_true", help="list every attack that still succeeds")
    e.add_argument("--markdown", help="write the report here")
    e.add_argument("--json", help="write full results here")
    _add_llm(e)
    e.set_defaults(func=cmd_eval)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (AttackFileError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
