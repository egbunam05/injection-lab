"""injection-lab: measure prompt-injection attacks and defenses on a small LLM app."""
__version__ = "0.1.0"

from .app import Case, Result, case_from_attack, case_from_benign, run_case
from .attacks import Attack, Benign, load_attacks, load_benign
from .detect import hijack_succeeded, leaked
from .eval import run_matrix, summarize, wilson
from .scenario import Scenario
