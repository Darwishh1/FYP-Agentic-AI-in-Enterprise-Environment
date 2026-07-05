"""
Red-team suite runner.

Runs every scenario in scenarios.SCENARIOS through the detection engine and
prints a per-scenario table plus the headline evaluation metrics:

  Detection Rate (DR)   - % of attacks correctly flagged            (target > 85%)
  False Positive Rate   - % of benign controls wrongly flagged      (target < 5%)
  OWASP tag accuracy    - % of detected attacks tagged correctly
  Per-OWASP coverage    - which ASI categories the suite exercises + catches

Run from the project root:
    python -m red_team.runner
"""
import sys

# Allow `python red_team/runner.py` too, not just `-m`.
sys.path.insert(0, ".")

# Console-safe UTF-8 output on Windows (✓/✗ and emoji in output).
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

from security_monitor import SecurityMonitor
from red_team.scenarios import SCENARIOS


def run_suite():
    monitor = SecurityMonitor()
    results = [s.run(monitor) for s in SCENARIOS]

    print("=" * 100)
    print(f"{'ID':6} {'exp':4} {'det':4} {'status':8} {'rule':7} {'owasp':6} {'ok':3} {'name'}")
    print("-" * 100)
    for r in results:
        exp = "ATK" if r.expect_detected else "ben"
        det = "yes" if r.detected else "no"
        ok = "✓" if r.correct else "✗"
        print(f"{r.attack_id:6} {exp:4} {det:4} {r.status:8} "
              f"{(r.rule_id or '-'):7} {(r.actual_owasp or '-'):6} {ok:3} {r.name}")
    print("=" * 100)

    attacks = [r for r in results if r.expect_detected]
    benign = [r for r in results if not r.expect_detected]

    dr = sum(r.detected for r in attacks) / len(attacks) if attacks else 0.0
    fpr = sum(r.detected for r in benign) / len(benign) if benign else 0.0
    owasp_acc = (
        sum(r.owasp_correct for r in attacks if r.detected)
        / sum(r.detected for r in attacks)
        if any(r.detected for r in attacks) else 0.0
    )

    print("\nMETRICS")
    print(f"  Detection Rate (DR)     : {dr:6.1%}  ({sum(r.detected for r in attacks)}/{len(attacks)} attacks flagged)   target > 85%")
    print(f"  False Positive Rate     : {fpr:6.1%}  ({sum(r.detected for r in benign)}/{len(benign)} benign flagged)     target < 5%")
    print(f"  OWASP tag accuracy      : {owasp_acc:6.1%}  (correct ASI tag among detected attacks)")

    # Per-OWASP coverage across the attack scenarios.
    print("\nPER-OWASP COVERAGE (attacks)")
    by_owasp = {}
    for r in attacks:
        by_owasp.setdefault(r.expected_owasp, [0, 0])
        by_owasp[r.expected_owasp][0] += 1
        by_owasp[r.expected_owasp][1] += int(r.detected)
    for tag in sorted(by_owasp):
        total, caught = by_owasp[tag]
        print(f"  {tag}: {caught}/{total} caught")

    misses = [r for r in results if not r.correct]
    if misses:
        print("\nINCORRECT (investigate):")
        for r in misses:
            print(f"  {r.attack_id} {r.name}: expected detected={r.expect_detected}, got status={r.status}")
    else:
        print("\nAll scenarios classified correctly.")

    return results


if __name__ == "__main__":
    run_suite()
