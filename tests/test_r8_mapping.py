"""Tests for R8/ProGuard mapping file parser."""

import os
import tempfile
import pytest

from r8_mapping import parse_mapping_file, deobfuscate_path, _split_extension


# --- parse_mapping_file ---

SAMPLE_MAPPING = """\
# compiler: R8
# compiler_version: 3.3.75
com.example.myapp.CryptoHelper -> a.b.c:
    java.lang.String key -> a
    void encrypt(byte[]) -> b
com.example.myapp.MainActivity -> a.b.d:
    void onCreate(android.os.Bundle) -> a
com.google.firebase.FirebaseAuth -> d.e.f:
    int field1 -> a
com.squareup.okhttp3.OkHttpClient -> g.h:
"""


class TestParseMappingFile:
    def _write_mapping(self, content):
        """Write mapping content to a temp file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        return path

    def test_basic_class_mappings(self):
        path = self._write_mapping(SAMPLE_MAPPING)
        try:
            mapping = parse_mapping_file(path)
            assert mapping["a/b/c"] == "com/example/myapp/CryptoHelper"
            assert mapping["a/b/d"] == "com/example/myapp/MainActivity"
            assert mapping["d/e/f"] == "com/google/firebase/FirebaseAuth"
            assert mapping["g/h"] == "com/squareup/okhttp3/OkHttpClient"
        finally:
            os.unlink(path)

    def test_skips_member_mappings(self):
        path = self._write_mapping(SAMPLE_MAPPING)
        try:
            mapping = parse_mapping_file(path)
            # Member mappings (indented lines) should not appear
            assert len(mapping) == 4
        finally:
            os.unlink(path)

    def test_skips_comments_and_blanks(self):
        content = "# comment\n\ncom.Foo -> a.b:\n"
        path = self._write_mapping(content)
        try:
            mapping = parse_mapping_file(path)
            assert mapping == {"a/b": "com/Foo"}
        finally:
            os.unlink(path)

    def test_empty_file(self):
        path = self._write_mapping("")
        try:
            mapping = parse_mapping_file(path)
            assert mapping == {}
        finally:
            os.unlink(path)


# --- deobfuscate_path ---

class TestDeobfuscatePath:
    def setup_method(self):
        self.mapping = {
            "a/b/c": "com/example/myapp/CryptoHelper",
            "d/e/f": "com/google/firebase/FirebaseAuth",
        }

    def test_java_file(self):
        result = deobfuscate_path("a/b/c.java", self.mapping)
        assert result == "com/example/myapp/CryptoHelper.java"

    def test_kotlin_file(self):
        result = deobfuscate_path("a/b/c.kt", self.mapping)
        assert result == "com/example/myapp/CryptoHelper.kt"

    def test_smali_file(self):
        result = deobfuscate_path("a/b/c.smali", self.mapping)
        assert result == "com/example/myapp/CryptoHelper.smali"

    def test_no_mapping_found(self):
        result = deobfuscate_path("x/y/z.java", self.mapping)
        assert result is None

    def test_already_deobfuscated_path(self):
        result = deobfuscate_path("com/example/myapp/Foo.java", self.mapping)
        assert result is None


# --- _split_extension ---

class TestSplitExtension:
    def test_java(self):
        assert _split_extension("a/b/c.java") == ("a/b/c", ".java")

    def test_kotlin(self):
        assert _split_extension("a/b/c.kt") == ("a/b/c", ".kt")

    def test_smali(self):
        assert _split_extension("a/b/c.smali") == ("a/b/c", ".smali")

    def test_no_extension(self):
        assert _split_extension("a/b/c") == ("a/b/c", "")

    def test_unknown_extension(self):
        assert _split_extension("a/b/c.xml") == ("a/b/c", ".xml")


# --- Integration: classify_findings with r8_mapping ---

class TestClassifyFindingsWithMapping:
    def test_deobfuscated_path_classified_as_app_code(self):
        """When mapping is provided, obfuscated paths should be de-obfuscated
        and classified normally by Layers 1-4."""
        from classifier import classify_findings

        mapping = {
            "a/b/c": "com/example/myapp/CryptoHelper",
        }
        report = {
            "package_name": "com.example.myapp",
            "code_analysis": {
                "findings": {
                    "hardcoded_key": {
                        "files": {
                            "a/b/c.java": "10",
                        },
                        "metadata": {
                            "severity": "high",
                            "cwe": "CWE-321",
                            "cvss": 7.5,
                            "description": "Hardcoded key",
                            "masvs": "",
                            "owasp-mobile": "",
                            "ref": "",
                        }
                    }
                }
            }
        }
        classified, unclassified = classify_findings(report, (), r8_mapping=mapping)
        assert len(classified) == 1
        assert len(unclassified) == 0
        f = classified[0]
        assert f["category"] == "app_code"
        assert f["original_path"] == "com/example/myapp/CryptoHelper.java"
        assert f["file_path"] == "a/b/c.java"  # original obfuscated path preserved

    def test_deobfuscated_third_party_classified(self):
        """Mapping that reveals a third-party path should be classified by Layer 2."""
        from classifier import classify_findings

        mapping = {
            "d/e/f": "com/google/firebase/FirebaseAuth",
        }
        report = {
            "code_analysis": {
                "findings": {
                    "some_vuln": {
                        "files": {
                            "d/e/f.java": "5",
                        },
                        "metadata": {
                            "severity": "info",
                            "cwe": "",
                            "cvss": 0,
                            "description": "Test",
                            "masvs": "",
                            "owasp-mobile": "",
                            "ref": "",
                        }
                    }
                }
            }
        }
        classified, unclassified = classify_findings(
            report, ("com/google/",), r8_mapping=mapping
        )
        assert len(classified) == 1
        assert classified[0]["category"] == "third_party"
        assert classified[0]["original_path"] == "com/google/firebase/FirebaseAuth.java"

    def test_no_mapping_falls_through(self):
        """Paths not in the mapping should proceed through normal classification."""
        from classifier import classify_findings

        mapping = {"a/b/c": "com/example/myapp/CryptoHelper"}
        report = {
            "code_analysis": {
                "findings": {
                    "vuln": {
                        "files": {
                            "x/y/z.java": "1",
                        },
                        "metadata": {
                            "severity": "warning",
                            "cwe": "",
                            "cvss": 0,
                            "description": "Test",
                            "masvs": "",
                            "owasp-mobile": "",
                            "ref": "",
                        }
                    }
                }
            }
        }
        classified, unclassified = classify_findings(report, (), r8_mapping=mapping)
        # x/y/z.java has no mapping match and no layer 1-4 match → unclassified
        assert len(unclassified) == 1
        assert unclassified[0]["original_path"] == ""
