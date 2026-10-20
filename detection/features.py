"""
Layer 1 feature extraction.

One code path for training and for live scoring. `SessionState` is an online
accumulator: feed it a session's records in order and it returns one vector per
call, using only that call and the calls before it. The offline extractor
(`Featurizer.transform`) is a loop over the same accumulator, so a model can never
be trained on a feature the gate could not compute at call time. A test checks
that the two paths agree.

WHAT IS DELIBERATELY NOT A FEATURE
  policy_status, rule_ids, owasp_tags   Layer 3's verdict. Using it would make
                                        Layer 1 partly a copy of Layer 3 and any
                                        "Layer 1 catches X" claim circular.
  result_status == BLOCKED              Same thing, one step removed.
  latency_ms                            Wall-clock noise of the Python process.
  timestamp                             When the corpus was generated, not when
                                        the simulated call happened.
  args_hash, session_id, attack_id,
  is_attack, l1_score                   Identifiers and labels.
A test perturbs every one of these and asserts the vector does not move.

FEATURE SET (18) — the knowledge base listed 8; what happened to each:
  calls_per_minute      -> win_calls, win_same_tool (sim-time window, 60 s)
  unique_tool_ratio     -> unique_tool_ratio (last 10 calls)
  tool_sequence_entropy -> seq_entropy (last 10 calls)
  data_volume_bytes     -> bytes_dev, rows_dev (per role AND tool), log_cum_bytes
  time_of_day_zscore    -> hour_surprise (-log P(hour | role)); a z-score assumes
                           a unimodal hour distribution and DevOps is not one
  cross_agent_hops      -> delegation_depth (now real: agents delegate)
  failed_auth_rate      -> denied_frac. There is no authentication in the sim;
                           this is the share of calls refused by the tool sandbox
                           (DENIED/ERROR from mock_tools), which is independent
                           of Layer 3.
  privilege_delta       -> dropped. Privilege is fixed per role, so it is always 0.
Added: tool_surprise, schema_surprise, target_surprise (UEBA-style "is this
normal for this role"), payee_surprise, amount_dev, args_len_dev, log_turn.

WHY VOLUME IS CONDITIONED ON ROLE AND TOOL
The first version used raw log bytes. A 72 KB email then looked unremarkable,
because 72 KB is an ordinary size for a database query, and an Isolation Forest
with axis-aligned splits cannot easily learn the interaction "big AND email".
Each volume-like feature is now a robust z-score against the training median and
IQR for the same (role, tool), i.e. a per-entity baseline in the UEBA sense.

AGGREGATED RARITY
An Isolation Forest only splits on features that vary inside a node, and sklearn
skips features that are constant in the sample. A novelty indicator that is never
set in benign training data (finance has never paid a new payee, HR has never read
the finance schema) is therefore invisible to the forest however extreme it gets
at test time. Measured: B-102 salami payments carried payee_surprise ~4.6 against
a benign value of 0.01 and scored 0/40. total_surprise sums the per-event rarity
terms, which does vary in benign traffic (hour and target rarity have real
spread), so a novel event pushes a varying feature into its tail. The sum is then
z-scored against the same role's own distribution: summed globally, a finance
payment to a new payee (+4.6) still looked ordinary next to DevOps at 03:00 on a
rare target, which is routine for DevOps.
A related limit that remains: a value beyond the training range is isolated no
faster than the most extreme training value on that axis. The forest cannot tell
a 75k payment from the benign 49.5k cluster at the clip. Policy limits are a rule
problem, which is why Layer 3 exists.

CROSS-FITTING
The surprise features depend on frequency tables fitted on benign training data.
Computing training vectors with tables fitted on those same records is optimistic
in a way that matters: every training payee is "already seen", so a feature that
is routinely 1 at test time (a refund to a new customer) is always 0 in training
and the forest learns to fear it. cross_fit_transform() fits the tables on K-1
session folds and transforms the held-out fold, so training vectors carry the same
out-of-sample surprise the live scorer will see.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field

import numpy as np

FEATURE_NAMES = [
    "tool_surprise",      # -log P(tool | role)
    "schema_surprise",    # -log P(schema | role), db_query only
    "hour_surprise",      # -log P(sim_hour | role)
    "target_surprise",    # -log P(target | role, tool): email domain, file dir, shell verb
    "payee_surprise",     # -log P(payee is new | role); a new vendor is rare for finance,
                          # a new customer is the norm for a CS refund
    "rarity_dev",         # sum of the five above, robust z vs this role (AGGREGATED RARITY)
    "bytes_dev",          # log bytes, robust z vs this role's baseline for this tool
    "rows_dev",           # log rows,  same
    "amount_dev",         # log payment amount, robust z vs this role's payments
    "args_len_dev",       # log free-text length, robust z vs role+tool
    "win_calls",          # calls in this session in the last 60 sim-seconds
    "win_same_tool",      # same-tool calls in the last 60 sim-seconds
    "unique_tool_ratio",  # distinct tools / calls, last 10 calls
    "seq_entropy",        # Shannon entropy of tool names, last 10 calls
    "denied_frac",        # share of session calls refused by the sandbox so far
    "delegation_depth",
    "log_cum_bytes",      # bytes returned so far this session
    "log_turn",
]

WINDOW_SECONDS = 60.0
HISTORY = 10
_FREE_TEXT = {"db_query": "query", "execute_shell": "command", "send_email": "body",
              "write_file": "content", "create_ticket": "details",
              "escalate_to_human": "reason", "read_file": "path", "call_payment_api": "recipient"}


def _target(tool: str, args: dict) -> str | None:
    """The 'who/what' of a call, coarse enough that benign variety collapses."""
    args = args or {}
    if "__target__" in args:            # external-dataset adapters (detection/cert) set
        return args["__target__"]       # the target directly; the simulator never does
    if tool == "send_email":
        to = str(args.get("to", ""))
        return to.split("@", 1)[-1].lower() if "@" in to else to.lower()
    if tool in ("read_file", "write_file"):
        path = str(args.get("path", "")).replace("\\", "/").lstrip("/")
        return path.split("/", 1)[0] if "/" in path else "(root)"
    if tool == "execute_shell":
        parts = str(args.get("command", "")).split()
        return " ".join(parts[:2])
    if tool == "create_ticket":
        return str(args.get("ticket_type", ""))
    return None


def _payee(tool: str, args: dict) -> str | None:
    return str((args or {}).get("recipient")) if tool == "call_payment_api" else None


class _Robust:
    """Per-key median / IQR of a scalar, for robust z-scores. IQR is floored so a
    tool whose output size never varies (payments are always 320 bytes) does not
    turn a one-byte difference into an infinite deviation."""

    FLOOR = 0.25

    def __init__(self):
        self.vals: dict = defaultdict(list)
        self.stats: dict = {}

    def add(self, key, x: float):
        self.vals[key].append(x)

    def finalize(self):
        for k, v in self.vals.items():
            q1, med, q3 = np.percentile(v, [25, 50, 75])
            self.stats[k] = (float(med), max(float(q3 - q1), self.FLOOR))
        self.vals = defaultdict(list)

    def z(self, key, x: float) -> float:
        if key not in self.stats:
            return 0.0
        med, scale = self.stats[key]
        return (x - med) / scale


def _amount(tool: str, args: dict) -> float | None:
    if tool != "call_payment_api":
        return None
    try:
        return float((args or {}).get("amount"))
    except (TypeError, ValueError):
        return None


def _text_len(tool: str, args: dict) -> float:
    if args and "__text_len__" in args:  # adapter-supplied length (see _target)
        return math.log1p(max(float(args["__text_len__"]), 0.0))
    return math.log1p(len(str((args or {}).get(_FREE_TEXT.get(tool, ""), "") or "")))


class _Freq:
    """Laplace-smoothed conditional frequency, -log P(value | key)."""

    def __init__(self, alpha: float = 1.0):
        self.alpha = alpha
        self.counts: dict = defaultdict(Counter)

    def add(self, key, value):
        self.counts[key][value] += 1

    def surprise(self, key, value) -> float:
        c = self.counts.get(key)
        if not c:
            return 0.0      # key never seen in training: no basis to call it unusual
        total = sum(c.values())
        vocab = len(c) + 1  # +1 for "anything unseen"
        return -math.log((c.get(value, 0) + self.alpha) / (total + self.alpha * vocab))


@dataclass
class SessionState:
    """Everything the extractor remembers about one session, call to call."""
    times: deque = field(default_factory=deque)   # (sim_time, tool)
    tools: deque = field(default_factory=lambda: deque(maxlen=HISTORY))
    calls: int = 0
    denied: int = 0
    cum_bytes: int = 0


class Featurizer:
    """Fitted on benign training records only (the frequency tables are part of
    the model), then turns records into vectors."""

    def __init__(self):
        self.tool = _Freq()
        self.schema = _Freq()
        self.hour = _Freq()
        self.target = _Freq()
        self.payees: dict[str, set] = defaultdict(set)
        self.p_new_payee: dict[str, float] = {}
        self.bytes = _Robust()
        self.rows = _Robust()
        self.amount = _Robust()
        self.textlen = _Robust()
        self.fitted = False

    # -- fitting --------------------------------------------------------------
    def fit(self, records) -> "Featurizer":
        payee_counts: dict = defaultdict(Counter)
        for r in records:
            role = r.agent_role
            self.tool.add(role, r.tool_name)
            if r.tool_name == "db_query":
                self.schema.add(role, r.schema_accessed)
            self.hour.add(role, r.sim_hour)
            t = _target(r.tool_name, r.args_raw)
            if t is not None:
                self.target.add((role, r.tool_name), t)
            p = _payee(r.tool_name, r.args_raw)
            if p is not None:
                self.payees[role].add(p)
                payee_counts[role][p] += 1
            key = (role, r.tool_name)
            self.bytes.add(key, math.log1p(max(int(r.bytes_returned or 0), 0)))
            self.rows.add(key, math.log1p(max(int(r.rows_returned or 0), 0)))
            self.textlen.add(key, _text_len(r.tool_name, r.args_raw))
            amt = _amount(r.tool_name, r.args_raw)
            if amt is not None:
                self.amount.add(role, math.log1p(max(amt, 0.0)))
        for stat in (self.bytes, self.rows, self.amount, self.textlen):
            stat.finalize()
        # Second pass: the per-role baseline for summed rarity needs the tables above.
        self.fitted = True
        self.rarity = _Robust()
        for r in records:
            self.rarity.add(r.agent_role, sum(self._surprises(r)))
        self.rarity.finalize()
        # Good-Turing: the chance the next payment goes to a new payee is roughly the
        # share of payments whose payee was seen exactly once.
        for role, c in payee_counts.items():
            total = sum(c.values())
            singletons = sum(1 for v in c.values() if v == 1)
            self.p_new_payee[role] = min(max(singletons / total, 0.01), 0.99)
        self.fitted = True
        return self

    # -- online ---------------------------------------------------------------
    def vector(self, state: SessionState, r) -> np.ndarray:
        """Update *state* with record *r* and return r's feature vector."""
        role, tool, args = r.agent_role, r.tool_name, (r.args_raw or {})
        t_now = float(r.sim_time_seconds if r.sim_time_seconds is not None else state.calls * 2.0)

        state.calls += 1
        state.tools.append(tool)
        state.times.append((t_now, tool))
        while state.times and state.times[0][0] <= t_now - WINDOW_SECONDS:
            state.times.popleft()
        if r.result_status in ("DENIED", "ERROR"):     # sandbox refusals, not Layer 3 blocks
            state.denied += 1
        state.cum_bytes += int(r.bytes_returned or 0)

        tool_counts = Counter(state.tools)
        n_hist = len(state.tools)
        entropy = -sum((c / n_hist) * math.log2(c / n_hist) for c in tool_counts.values())

        target = _target(tool, args)
        payee = _payee(tool, args)
        amount = _amount(tool, args)
        key = (role, tool)

        surprises = self._surprises(r)
        return np.array([
            *surprises,
            self.rarity.z(role, sum(surprises)),
            self.bytes.z(key, math.log1p(max(int(r.bytes_returned or 0), 0))),
            self.rows.z(key, math.log1p(max(int(r.rows_returned or 0), 0))),
            self.amount.z(role, math.log1p(max(amount, 0.0))) if amount is not None else 0.0,
            self.textlen.z(key, _text_len(tool, args)),
            float(len(state.times)),
            float(sum(1 for _, tl in state.times if tl == tool)),
            len(tool_counts) / n_hist,
            entropy,
            state.denied / state.calls,
            float(r.delegation_depth or 0),
            math.log1p(state.cum_bytes),
            math.log1p(r.turn_index or state.calls),
        ], dtype=float)

    def _surprises(self, r) -> list[float]:
        role, tool, args = r.agent_role, r.tool_name, (r.args_raw or {})
        target = _target(tool, args)
        return [
            self.tool.surprise(role, tool),
            self.schema.surprise(role, r.schema_accessed) if tool == "db_query" else 0.0,
            self.hour.surprise(role, r.sim_hour),
            self.target.surprise((role, tool), target) if target is not None else 0.0,
            self._payee_surprise(role, _payee(tool, args)),
        ]

    def _payee_surprise(self, role: str, payee: str | None) -> float:
        if payee is None or role not in self.p_new_payee:
            return 0.0
        p_new = self.p_new_payee[role]
        return -math.log(p_new if payee not in self.payees[role] else 1.0 - p_new)

    # -- offline --------------------------------------------------------------
    def transform(self, records) -> np.ndarray:
        """Vectors for *records*, in the order given. Sessions are replayed in
        turn order through SessionState, so each vector sees only its past."""
        order = sorted(range(len(records)),
                       key=lambda i: (records[i].session_id, records[i].turn_index))
        out = np.zeros((len(records), len(FEATURE_NAMES)))
        states: dict[str, SessionState] = {}
        for i in order:
            r = records[i]
            out[i] = self.vector(states.setdefault(r.session_id, SessionState()), r)
        return out

    @staticmethod
    def cross_fit_transform(records, k: int = 5, seed: int = 0) -> np.ndarray:
        """Out-of-fold vectors for training records (see AGGREGATED RARITY
An Isolation Forest only splits on features that vary inside a node, and sklearn
skips features that are constant in the sample. A novelty indicator that is never
set in benign training data (finance has never paid a new payee, HR has never read
the finance schema) is therefore invisible to the forest however extreme it gets
at test time. Measured: B-102 salami payments carried payee_surprise ~4.6 against
a benign value of 0.01 and scored 0/40. total_surprise sums the per-event rarity
terms, which does vary in benign traffic (hour and target rarity have real
spread), so a novel event pushes a varying feature into its tail. The sum is then
z-scored against the same role's own distribution: summed globally, a finance
payment to a new payee (+4.6) still looked ordinary next to DevOps at 03:00 on a
rare target, which is routine for DevOps.
A related limit that remains: a value beyond the training range is isolated no
faster than the most extreme training value on that axis. The forest cannot tell
a 75k payment from the benign 49.5k cluster at the clip. Policy limits are a rule
problem, which is why Layer 3 exists.

CROSS-FITTING above).
        Folds are by session, so no session is split across fit and transform."""
        rng = np.random.default_rng(seed)
        sessions = sorted({r.session_id for r in records})
        fold_of = {s: int(f) for s, f in zip(sessions, rng.integers(0, k, len(sessions)))}
        out = np.zeros((len(records), len(FEATURE_NAMES)))
        for f in range(k):
            fit_recs = [r for r in records if fold_of[r.session_id] != f]
            idx = [i for i, r in enumerate(records) if fold_of[r.session_id] == f]
            if not idx:
                continue
            fz = Featurizer().fit(fit_recs)
            out[idx] = fz.transform([records[i] for i in idx])
        return out
