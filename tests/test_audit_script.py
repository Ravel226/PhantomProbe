"""
Tests for scripts/audit_cpe_mapping.py.

The script's job is to call NVD, so the network calls are stubbed and what is
checked here is the part that decides things: how a result count becomes a
verdict, which pairs get checked, and whether a dead mapping fails the run.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "audit_cpe_mapping.py"


def _load():
    spec = importlib.util.spec_from_file_location("audit_cpe_mapping", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["audit_cpe_mapping"] = module
    spec.loader.exec_module(module)
    return module


audit_script = _load()


@pytest.fixture
def no_waiting(monkeypatch):
    monkeypatch.setattr(audit_script.time, "sleep", lambda *_: None)


class TestClassify:
    """Zero is the case that matters: it is what a wrong vendor looks like."""

    @pytest.mark.parametrize("total,expected", [
        (0, "dead"),
        (1, "thin"),
        (4, "thin"),
        (5, "ok"),
        (1442, "ok"),
        (None, "unchecked"),
    ])
    def test_counts_become_verdicts(self, total, expected):
        assert audit_script.classify(total) == expected

    def test_every_verdict_has_a_note_entry(self):
        for total in (0, 1, 99, None):
            assert audit_script.classify(total) in audit_script.VERDICT_NOTE


class TestRun:
    def test_a_dead_mapping_fails_the_run(self, monkeypatch, no_waiting, capsys):
        monkeypatch.setattr(audit_script, "count_cves",
                            lambda vendor, product, key, timeout=45: (0, ""))
        code = audit_script.main(["--tech", "nginx"])

        assert code == 1
        assert "dead" in capsys.readouterr().out

    def test_a_healthy_table_passes(self, monkeypatch, no_waiting):
        monkeypatch.setattr(audit_script, "count_cves",
                            lambda vendor, product, key, timeout=45: (41, ""))
        assert audit_script.main(["--tech", "nginx", "php"]) == 0

    def test_thin_coverage_is_reported_but_not_a_failure(
            self, monkeypatch, no_waiting, capsys):
        monkeypatch.setattr(audit_script, "count_cves",
                            lambda vendor, product, key, timeout=45: (1, ""))
        code = audit_script.main(["--tech", "gunicorn"])

        assert code == 0
        assert "thin" in capsys.readouterr().out

    def test_a_failed_lookup_is_not_mistaken_for_a_dead_mapping(
            self, monkeypatch, no_waiting, capsys):
        """A timeout means unknown, not broken; it must not fail the run."""
        monkeypatch.setattr(audit_script, "count_cves",
                            lambda vendor, product, key, timeout=45: (None, "timeout"))
        code = audit_script.main(["--tech", "nginx"])

        assert code == 0
        assert "unchecked" in capsys.readouterr().out

    def test_checks_the_whole_table_by_default(self, monkeypatch, no_waiting):
        from phantomprobe.cve import CVEMatcher

        seen = []

        def record(vendor, product, key, timeout=45):
            seen.append((vendor, product))
            return 10, ""

        monkeypatch.setattr(audit_script, "count_cves", record)
        audit_script.main([])
        assert len(seen) == len(CVEMatcher.CPE_MAPPING)

    def test_candidate_pairs_need_not_be_in_the_table(self, monkeypatch, no_waiting):
        seen = []
        monkeypatch.setattr(
            audit_script, "count_cves",
            lambda vendor, product, key, timeout=45: (seen.append((vendor, product)), (7, ""))[1])
        assert audit_script.main(["--check", "brand:new"]) == 0
        assert seen == [("brand", "new")]

    def test_unknown_tech_is_rejected(self, no_waiting):
        with pytest.raises(SystemExit):
            audit_script.main(["--tech", "definitely-not-a-tech"])

    def test_malformed_candidate_is_rejected(self, no_waiting):
        with pytest.raises(SystemExit):
            audit_script.main(["--check", "missing-the-colon"])

    def test_json_output_records_each_verdict(self, monkeypatch, no_waiting, tmp_path):
        import json

        monkeypatch.setattr(audit_script, "count_cves",
                            lambda vendor, product, key, timeout=45: (41, ""))
        out = tmp_path / "audit.json"
        audit_script.main(["--tech", "nginx", "--json", str(out)])

        saved = json.loads(out.read_text(encoding="utf-8"))
        assert saved["nginx"]["verdict"] == "ok"
        assert saved["nginx"]["vendor"] == "f5"
