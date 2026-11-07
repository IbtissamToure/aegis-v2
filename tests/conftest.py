import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aegis.detection.validators import saudi_id_check_digit  # noqa: E402
from aegis.gateway import Aegis  # noqa: E402
from aegis.llm.providers import NullProvider  # noqa: E402


def make_id(prefix9: str) -> str:
    return prefix9 + saudi_id_check_digit(prefix9)


@pytest.fixture
def aegis(tmp_path):
    return Aegis(audit_path=str(tmp_path / "audit.db"), data_dir=tmp_path, llm=NullProvider())
