"""Tests for scanner.payloads.loader -- loading, validating, and filtering payloads."""
from __future__ import annotations

import json

import pytest

from scanner.core.models import AttackCategory
from scanner.payloads.loader import PayloadValidationError, filter_payloads, load_payloads


class TestLoadRealLibrary:
    """Sanity checks against the actual shipped data/payloads.json."""

    def test_loads_exactly_25_payloads(self, all_payloads):
        assert len(all_payloads) == 25

    def test_category_distribution_matches_spec(self, all_payloads):
        counts = {}
        for p in all_payloads:
            counts[p.category] = counts.get(p.category, 0) + 1
        assert counts[AttackCategory.PROMPT_EXTRACTION] == 9
        assert counts[AttackCategory.PROMPT_INJECTION] == 8
        assert counts[AttackCategory.GUARDRAIL_BYPASS] == 8

    def test_all_ids_unique(self, all_payloads):
        ids = [p.id for p in all_payloads]
        assert len(ids) == len(set(ids))

    def test_all_canary_tokens_unique(self, all_payloads):
        canaries = [p.canary_token for p in all_payloads if p.canary_token]
        assert len(canaries) == len(set(canaries))

    def test_every_injection_payload_has_a_canary_token(self, all_payloads):
        injection_payloads = [p for p in all_payloads if p.category == AttackCategory.PROMPT_INJECTION]
        assert len(injection_payloads) == 8
        for p in injection_payloads:
            assert p.canary_token, f"{p.id} should have a canary token to make detection unambiguous"

    def test_no_empty_prompt_templates(self, all_payloads):
        for p in all_payloads:
            assert p.prompt_template.strip(), f"{p.id} has an empty prompt template"

    def test_every_payload_has_an_owasp_reference(self, all_payloads):
        for p in all_payloads:
            assert p.owasp_ref, f"{p.id} is missing an OWASP reference"


class TestValidationErrors:
    """Confirm the loader actually rejects malformed data rather than silently accepting it."""

    def _write(self, tmp_path, payloads):
        path = tmp_path / "bad_payloads.json"
        path.write_text(json.dumps({"payloads": payloads}), encoding="utf-8")
        return path

    def test_missing_required_field_raises(self, tmp_path):
        path = self._write(tmp_path, [{"id": "x", "name": "X", "category": "prompt_injection"}])
        with pytest.raises(PayloadValidationError, match="missing required field"):
            load_payloads(path)

    def test_duplicate_id_raises(self, tmp_path):
        entry = {
            "id": "dup", "name": "A", "category": "guardrail_bypass",
            "technique": "t", "description": "d", "prompt_template": "hi",
        }
        path = self._write(tmp_path, [entry, dict(entry, name="B")])
        with pytest.raises(PayloadValidationError, match="Duplicate payload id"):
            load_payloads(path)

    def test_unknown_category_raises(self, tmp_path):
        path = self._write(tmp_path, [{
            "id": "x", "name": "X", "category": "not_a_real_category",
            "technique": "t", "description": "d", "prompt_template": "hi",
        }])
        with pytest.raises(PayloadValidationError, match="unrecognized category"):
            load_payloads(path)

    def test_duplicate_canary_token_raises(self, tmp_path):
        base = {"category": "prompt_injection", "technique": "t", "description": "d",
                "prompt_template": "hi", "canary_token": "SAME_TOKEN"}
        path = self._write(tmp_path, [dict(base, id="a", name="A"), dict(base, id="b", name="B")])
        with pytest.raises(PayloadValidationError, match="reuses canary token"):
            load_payloads(path)

    def test_empty_payload_list_raises(self, tmp_path):
        path = tmp_path / "empty.json"
        path.write_text(json.dumps({"payloads": []}), encoding="utf-8")
        with pytest.raises(PayloadValidationError, match="no payloads"):
            load_payloads(path)

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(PayloadValidationError, match="not found"):
            load_payloads(tmp_path / "does_not_exist.json")

    def test_malformed_json_raises(self, tmp_path):
        path = tmp_path / "broken.json"
        path.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(PayloadValidationError, match="not valid JSON"):
            load_payloads(path)


class TestFilterPayloads:
    def test_category_filter(self, all_payloads):
        result = filter_payloads(all_payloads, categories_enabled={
            "prompt_extraction": True, "prompt_injection": False, "guardrail_bypass": False,
        })
        assert len(result) == 9
        assert all(p.category == AttackCategory.PROMPT_EXTRACTION for p in result)

    def test_explicit_id_list_overrides_category_filter(self, all_payloads):
        result = filter_payloads(
            all_payloads,
            categories_enabled={"prompt_extraction": False, "prompt_injection": False, "guardrail_bypass": False},
            payload_ids_enabled=["sp_direct_ask", "gb_dan_roleplay"],
        )
        assert {p.id for p in result} == {"sp_direct_ask", "gb_dan_roleplay"}

    def test_no_filters_returns_everything(self, all_payloads):
        result = filter_payloads(all_payloads)
        assert len(result) == len(all_payloads)
