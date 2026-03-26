"""Tests for Layer 6 LLM fallback — graceful skip when no API key."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from llm_fallback import classify_with_llm


class TestLLMFallbackSkipped:
    def test_skip_when_no_api_key(self):
        findings = [
            {
                "file_path": "a/b/c/Obfuscated.java",
                "vuln_name": "test_rule",
                "severity": "high",
                "cwe": "CWE-321",
                "description": "Hardcoded key",
                "category": "unknown",
                "confidence": "low",
                "classified_by": "pending_llm",
                "llm_reason": "",
            }
        ]
        result = classify_with_llm(findings, None)
        assert len(result) == 1
        assert result[0]["category"] == "unknown"
        assert result[0]["confidence"] == "low"
        assert result[0]["classified_by"] == "skipped_no_api_key"

    def test_skip_when_empty_api_key(self):
        findings = [
            {
                "file_path": "x/y/Z.java",
                "vuln_name": "rule",
                "severity": "medium",
                "cwe": "",
                "description": "",
                "category": "unknown",
                "confidence": "low",
                "classified_by": "pending_llm",
                "llm_reason": "",
            }
        ]
        result = classify_with_llm(findings, "")
        assert result[0]["classified_by"] == "skipped_no_api_key"

    def test_multiple_findings_all_skipped(self):
        findings = [
            {"file_path": f"path/{i}.java", "vuln_name": "r", "severity": "low",
             "cwe": "", "description": "",
             "category": "unknown", "confidence": "low", "classified_by": "pending_llm", "llm_reason": ""}
            for i in range(5)
        ]
        result = classify_with_llm(findings, None)
        assert all(f["classified_by"] == "skipped_no_api_key" for f in result)
