"""Shared fixtures.

The rule tests run against a FIXTURE policy, not against the live policy.yaml.
That is deliberate: policy.yaml is a tuning surface. Payment limits and rate caps
are meant to be changed while calibrating the false-positive rate, and tests that
read it would either break on every tune or, worse, be quietly weakened by one.
The fixture pins the numbers the assertions depend on.

There is a separate test (test_policy_shape) that does look at the live file, to
check its structure rather than its values.
"""
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from security_monitor import SecurityMonitor  # noqa: E402


# Two roles are enough to cover every rule: one HIGH-privilege role with a payment
# limit and per-tool rate caps, one LOW-privilege role for the contrast cases.
FIXTURE_POLICY = {
    "version": "test",
    "agents": {
        "finance_agent": {
            "allowed_tools": ["db_query", "call_payment_api", "send_email"],
            "db_schemas": ["finance", "accounts"],
            "privilege_level": "HIGH",
            "payment_limit": 50000,
            "max_calls_per_minute": 15,
            "allowed_hours": [8, 18],
            "tool_rate_limits": {"call_payment_api": 5, "db_query": 20},
        },
        "customer_service_agent": {
            "allowed_tools": ["db_query", "create_ticket"],
            "db_schemas": ["crm"],
            "privilege_level": "LOW",
            "payment_limit": 500,
            "max_calls_per_minute": 50,
            "allowed_hours": [8, 22],
        },
    },
    "global_rules": {"window_seconds": 60},
}


@pytest.fixture
def policy_path(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump(FIXTURE_POLICY), encoding="utf-8")
    return str(p)


@pytest.fixture
def monitor(policy_path):
    return SecurityMonitor(policy_path=policy_path)
