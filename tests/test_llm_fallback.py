"""Tests for Layer 6 LLM fallback — graceful skip, provider selection, prompt building."""

import json
import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from llm_fallback import classify_with_llm, _build_prompt, _parse_response


def _make_finding(file_path="a/b/c.java", severity="high", cwe="CWE-321",
                  description="Hardcoded key", vuln_name="test_rule",
                  cvss=7.5, owasp_mobile="", masvs=""):
    return {
        "file_path": file_path,
        "vuln_name": vuln_name,
        "severity": severity,
        "cwe": cwe,
        "cvss": cvss,
        "owasp_mobile": owasp_mobile,
        "masvs": masvs,
        "description": description,
        "category": "unknown",
        "confidence": "low",
        "classified_by": "pending_llm",
        "llm_reason": "",
    }


# --- Skipped / no API key ---

class TestLLMFallbackSkipped:
    def test_skip_when_no_api_key(self):
        findings = [_make_finding()]
        result = classify_with_llm(findings, None)
        assert result[0]["classified_by"] == "skipped_no_api_key"

    def test_skip_when_empty_api_key(self):
        findings = [_make_finding()]
        result = classify_with_llm(findings, "")
        assert result[0]["classified_by"] == "skipped_no_api_key"

    def test_skip_when_no_api_key_gemini(self):
        findings = [_make_finding()]
        result = classify_with_llm(findings, None, provider="gemini")
        assert result[0]["classified_by"] == "skipped_no_api_key"

    def test_multiple_findings_all_skipped(self):
        findings = [_make_finding(f"path/{i}.java") for i in range(5)]
        result = classify_with_llm(findings, None)
        assert all(f["classified_by"] == "skipped_no_api_key" for f in result)


# --- Prompt building ---

class TestBuildPrompt:
    def test_includes_file_path(self):
        prompt = _build_prompt("com/example/Foo.java")
        assert "com/example/Foo.java" in prompt

    def test_includes_vulnerability_context(self):
        prompt = _build_prompt(
            "a/b/c.java",
            severity="high",
            cwe="CWE-321",
            description="Hardcoded encryption key",
            is_obfuscated=True,
            vuln_name="android_hardcoded_key",
            cvss=7.5,
            owasp_mobile="M2: Insecure Data Storage",
            masvs="MSTG-STORAGE-1",
        )
        assert "high" in prompt
        assert "CWE-321" in prompt
        assert "Hardcoded encryption key" in prompt
        assert "True" in prompt
        assert "android_hardcoded_key" in prompt
        assert "7.5" in prompt
        assert "M2: Insecure Data Storage" in prompt
        assert "MSTG-STORAGE-1" in prompt

    def test_obfuscation_flag_false(self):
        prompt = _build_prompt("com/example/Foo.java", is_obfuscated=False)
        assert "False" in prompt

    def test_sibling_paths_included(self):
        siblings = ["d/e/f.java", "g/h/i.java", "com/google/Firebase.java"]
        prompt = _build_prompt(
            "a/b/c.java",
            sibling_paths=siblings,
        )
        assert "d/e/f.java" in prompt
        assert "g/h/i.java" in prompt
        assert "com/google/Firebase.java" in prompt
        assert "3 total" in prompt

    def test_sibling_paths_truncated_at_10(self):
        siblings = [f"path/{i}.java" for i in range(15)]
        prompt = _build_prompt("a/b/c.java", sibling_paths=siblings)
        # Should show first 10 and a "... and 5 more" note
        assert "path/9.java" in prompt
        assert "path/10.java" not in prompt
        assert "5 more" in prompt

    def test_no_siblings_no_context(self):
        prompt = _build_prompt("a/b/c.java", sibling_paths=None)
        assert "Other files flagged" not in prompt


# --- Response parsing ---

class TestParseResponse:
    def test_valid_json(self):
        text = '{"category": "app_code", "confidence": "high", "reason": "test"}'
        result = _parse_response(text)
        assert result["category"] == "app_code"
        assert result["confidence"] == "high"

    def test_markdown_wrapped(self):
        text = '```json\n{"category": "third_party", "confidence": "medium", "reason": "lib"}\n```'
        result = _parse_response(text)
        assert result["category"] == "third_party"

    def test_invalid_category_falls_back(self):
        text = '{"category": "something_else", "confidence": "high", "reason": ""}'
        result = _parse_response(text)
        assert result["category"] == "unknown"

    def test_invalid_confidence_falls_back(self):
        text = '{"category": "app_code", "confidence": "very_high", "reason": ""}'
        result = _parse_response(text)
        assert result["confidence"] == "low"

    def test_obfuscated_unknown_is_valid(self):
        text = '{"category": "obfuscated_unknown", "confidence": "medium", "reason": "obfuscated"}'
        result = _parse_response(text)
        assert result["category"] == "obfuscated_unknown"


# --- Provider integration (mocked) ---

class TestAnthropicProvider:
    @patch("llm_fallback._init_client")
    def test_anthropic_classified_by_tag(self, mock_init):
        mock_client = MagicMock()
        mock_init.return_value = mock_client

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='{"category": "app_code", "confidence": "high", "reason": "test"}')]
        mock_client.messages.create.return_value = mock_response

        findings = [_make_finding()]
        result = classify_with_llm(findings, "fake-key", provider="anthropic")
        assert result[0]["classified_by"] == "llm_fallback_anthropic"
        assert result[0]["category"] == "app_code"


class TestGeminiProvider:
    @patch("llm_fallback._init_client")
    def test_gemini_classified_by_tag(self, mock_init):
        mock_client = MagicMock()
        mock_init.return_value = mock_client

        mock_response = MagicMock()
        mock_response.text = '{"category": "third_party", "confidence": "medium", "reason": "library"}'
        mock_client.models.generate_content.return_value = mock_response

        findings = [_make_finding()]
        result = classify_with_llm(findings, "fake-key", provider="gemini")
        assert result[0]["classified_by"] == "llm_fallback_gemini"
        assert result[0]["category"] == "third_party"

    @patch("llm_fallback._init_client")
    def test_gemini_error_handled_gracefully(self, mock_init):
        mock_init.side_effect = Exception("Gemini init failed")

        findings = [_make_finding()]
        result = classify_with_llm(findings, "fake-key", provider="gemini")
        assert result[0]["classified_by"] == "llm_error"
        assert result[0]["category"] == "unknown"
