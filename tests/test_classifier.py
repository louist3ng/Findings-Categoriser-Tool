"""Tests for the classification engine (Layers 1-5)."""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from classifier import (
    classify_layer1,
    classify_layer2,
    classify_layer3,
    infer_app_package,
    classify_findings,
    load_third_party_prefixes,
    is_obfuscated_path,
    classify_obfuscated,
    extract_manifest_components,
    classify_manifest_component,
)


# --- Layer 1: Android prefix matching ---

class TestLayer1:
    def test_android_prefix(self):
        result = classify_layer1("android/content/Context.java")
        assert result is not None
        assert result["category"] == "android_code"
        assert result["confidence"] == "high"
        assert result["classified_by"] == "android_prefix"

    def test_java_prefix(self):
        result = classify_layer1("java/util/ArrayList.java")
        assert result["category"] == "android_code"

    def test_javax_prefix(self):
        result = classify_layer1("javax/crypto/Cipher.java")
        assert result["category"] == "android_code"

    def test_kotlin_prefix(self):
        result = classify_layer1("kotlin/collections/MapsKt.java")
        assert result["category"] == "android_code"

    def test_kotlinx_prefix(self):
        result = classify_layer1("kotlinx/coroutines/CoroutineScope.java")
        assert result["category"] == "android_code"

    def test_dalvik_prefix(self):
        result = classify_layer1("dalvik/system/DexClassLoader.java")
        assert result["category"] == "android_code"

    def test_org_xml_prefix(self):
        result = classify_layer1("org/xml/sax/Parser.java")
        assert result["category"] == "android_code"

    def test_org_json_prefix(self):
        result = classify_layer1("org/json/JSONObject.java")
        assert result["category"] == "android_code"

    def test_no_match(self):
        result = classify_layer1("com/example/myapp/MainActivity.java")
        assert result is None

    def test_partial_match_not_triggered(self):
        result = classify_layer1("com/android/billing/Helper.java")
        assert result is None  # "com/android" != "android/"


# --- Layer 2: Third-party whitelist matching ---

class TestLayer2:
    @pytest.fixture
    def prefixes(self):
        return (
            "com/google/", "com/facebook/", "com/squareup/",
            "okhttp3/", "retrofit2/", "io/reactivex/",
            "com/amazonaws/", "org/apache/",
        )

    def test_google_match(self, prefixes):
        result = classify_layer2("com/google/firebase/FirebaseApp.java", prefixes)
        assert result is not None
        assert result["category"] == "third_party"
        assert result["confidence"] == "high"
        assert result["classified_by"] == "third_party_whitelist"

    def test_okhttp_match(self, prefixes):
        result = classify_layer2("okhttp3/OkHttpClient.java", prefixes)
        assert result["category"] == "third_party"

    def test_apache_match(self, prefixes):
        result = classify_layer2("org/apache/http/HttpEntity.java", prefixes)
        assert result["category"] == "third_party"

    def test_no_match(self, prefixes):
        result = classify_layer2("com/example/myapp/Utils.java", prefixes)
        assert result is None

    def test_facebook_match(self, prefixes):
        result = classify_layer2("com/facebook/login/LoginManager.java", prefixes)
        assert result["category"] == "third_party"


# --- Layer 3: Manifest component matching ---

class TestManifestComponents:
    def test_extract_activities(self):
        report = {
            "activities": [
                "com.example.myapp.MainActivity",
                "com.example.myapp.SettingsActivity",
            ],
            "services": ["com.example.myapp.SyncService"],
            "receivers": [],
            "providers": [],
        }
        paths, prefixes = extract_manifest_components(report)
        assert "com/example/myapp/MainActivity" in paths
        assert "com/example/myapp/SettingsActivity" in paths
        assert "com/example/myapp/SyncService" in paths
        assert "com/example/myapp/" in prefixes

    def test_filters_android_components(self):
        report = {
            "activities": ["android.app.Activity"],
            "services": [],
            "receivers": [],
            "providers": [],
        }
        paths, prefixes = extract_manifest_components(report)
        assert len(paths) == 0

    def test_filters_third_party_components(self):
        report = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": ["com.google.firebase.provider.FirebaseInitProvider"],
        }
        paths, prefixes = extract_manifest_components(report, ("com/google/",))
        assert len(paths) == 0

    def test_classify_exact_component_match(self):
        manifest_paths = {"com/example/myapp/MainActivity"}
        manifest_prefixes = {"com/example/myapp/"}
        result = classify_manifest_component(
            "com/example/myapp/MainActivity.java",
            manifest_paths, manifest_prefixes
        )
        assert result is not None
        assert result["category"] == "app_code"
        assert result["confidence"] == "high"
        assert result["classified_by"] == "manifest_component"

    def test_classify_package_match(self):
        manifest_paths = {"com/example/myapp/MainActivity"}
        manifest_prefixes = {"com/example/myapp/"}
        result = classify_manifest_component(
            "com/example/myapp/utils/Helper.java",
            manifest_paths, manifest_prefixes
        )
        assert result is not None
        assert result["category"] == "app_code"
        assert result["confidence"] == "medium"
        assert result["classified_by"] == "manifest_package"

    def test_no_match(self):
        manifest_paths = {"com/example/myapp/MainActivity"}
        manifest_prefixes = {"com/example/myapp/"}
        result = classify_manifest_component(
            "com/other/lib/Foo.java",
            manifest_paths, manifest_prefixes
        )
        assert result is None

    def test_empty_manifest(self):
        paths, prefixes = extract_manifest_components({})
        assert len(paths) == 0
        assert len(prefixes) == 0


# --- Layer 4: Package inference ---

class TestLayer3:
    def test_classify_with_inferred_package(self):
        result = classify_layer3(
            "com/example/myapp/MainActivity.java",
            "com/example/myapp/",
            "high",
        )
        assert result is not None
        assert result["category"] == "app_code"
        assert result["confidence"] == "high"
        assert result["classified_by"] == "inferred_app_package"

    def test_no_match_different_package(self):
        result = classify_layer3(
            "com/other/lib/Helper.java",
            "com/example/myapp/",
            "high",
        )
        assert result is None

    def test_medium_confidence(self):
        result = classify_layer3(
            "com/example/myapp/utils/Crypto.java",
            "com/example/myapp/",
            "medium",
        )
        assert result["confidence"] == "medium"

    def test_no_package_inferred(self):
        result = classify_layer3("com/example/myapp/Main.java", None, None)
        assert result is None


class TestInferAppPackage:
    def test_infer_from_manifest(self):
        report = {"package_name": "com.example.myapp"}
        pkg, conf = infer_app_package(report, ())
        assert pkg == "com/example/myapp/"
        assert conf == "high"

    def test_infer_from_frequency(self):
        report = {
            "code_analysis": {
                "findings": {
                    "rule1": {
                        "files": {
                            "com/mycompany/app/A.java": "1",
                            "com/mycompany/app/B.java": "2",
                            "com/mycompany/app/C.java": "3",
                            "com/mycompany/app/sub/D.java": "4",
                        },
                        "metadata": {}
                    }
                }
            }
        }
        pkg, conf = infer_app_package(report, ("com/google/",))
        assert pkg == "com/mycompany/app/"
        assert conf == "high"

    def test_infer_excludes_android(self):
        report = {
            "code_analysis": {
                "findings": {
                    "rule1": {
                        "files": {
                            "android/os/Build.java": "1",
                            "android/os/Handler.java": "2",
                            "com/myapp/test/Main.java": "3",
                        },
                        "metadata": {}
                    }
                }
            }
        }
        pkg, conf = infer_app_package(report, ())
        assert pkg is not None
        assert not pkg.startswith("android/")

    def test_empty_report(self):
        pkg, conf = infer_app_package({}, ())
        assert pkg is None

    def test_infer_skips_obfuscated_paths(self):
        """Obfuscated paths (a/b/c.java) should not influence package inference.

        This ensures -keep survivors (real-named classes) dominate the frequency
        count even when obfuscated classes outnumber them.
        """
        report = {
            "code_analysis": {
                "findings": {
                    "rule1": {
                        "files": {
                            # Obfuscated paths (should be skipped)
                            "a/b/c.java": "1",
                            "a/b/d.java": "2",
                            "a/b/e.java": "3",
                            "a/c/f.java": "4",
                            "b/c/g.java": "5",
                            "b/c/h.java": "6",
                            # Real-named -keep survivors
                            "com/myapp/real/Keep1.java": "7",
                            "com/myapp/real/Keep2.java": "8",
                        },
                        "metadata": {}
                    }
                }
            }
        }
        pkg, conf = infer_app_package(report, ())
        assert pkg == "com/myapp/real/"


# --- Layer 5: Obfuscation heuristic ---

class TestIsObfuscatedPath:
    def test_classic_obfuscated(self):
        assert is_obfuscated_path("a/b/c.java") is True

    def test_deeper_obfuscated(self):
        assert is_obfuscated_path("x/y/z/Foo.java") is True

    def test_mixed_case_obfuscated(self):
        assert is_obfuscated_path("a/b/C.java") is True

    def test_shallow_obfuscated(self):
        """R8 often flattens to single dir + filename (e.g. A/n.java)."""
        assert is_obfuscated_path("A/n.java") is True

    def test_two_char_dir_obfuscated(self):
        """R8 sometimes uses 2-char directory segments (e.g. a0/a.java)."""
        assert is_obfuscated_path("a0/a.java") is True

    def test_mangled_class_name_obfuscated(self):
        """R8 mangles class names like AbstractC0079l0 under short dirs."""
        assert is_obfuscated_path("k/AbstractC0079l0.java") is True

    def test_real_package_not_obfuscated(self):
        assert is_obfuscated_path("com/example/myapp/Main.java") is False

    def test_io_reactivex_not_obfuscated(self):
        """Packages like io/reactivex/ have multi-char segments."""
        assert is_obfuscated_path("io/reactivex/Observable.java") is False

    def test_single_file_no_dirs(self):
        assert is_obfuscated_path("Main.java") is False

    def test_one_real_dir_segment(self):
        """If any directory segment is >2 chars, it's not obfuscated."""
        assert is_obfuscated_path("com/a/B.java") is False

    def test_single_letter_with_long_filename(self):
        assert is_obfuscated_path("a/b/SomeClass.java") is True


class TestClassifyObfuscated:
    def test_obfuscated_path_classified(self):
        result = classify_obfuscated("a/b/c.java")
        assert result is not None
        assert result["category"] == "obfuscated_unknown"
        assert result["confidence"] == "medium"
        assert result["classified_by"] == "obfuscation_heuristic"

    def test_real_path_not_classified(self):
        result = classify_obfuscated("com/example/Main.java")
        assert result is None


# --- Integration: classify_findings ---

class TestClassifyFindings:
    def test_mixed_findings(self):
        report = {
            "package_name": "com.example.myapp",
            "code_analysis": {
                "findings": {
                    "hardcoded_key": {
                        "files": {
                            "com/example/myapp/CryptoHelper.java": "10,20",
                            "com/google/firebase/FirebaseAuth.java": "5",
                            "android/util/Base64.java": "3",
                        },
                        "metadata": {
                            "severity": "high",
                            "cwe": "CWE-321",
                            "cvss": 7.5,
                            "description": "Hardcoded encryption key",
                            "masvs": "",
                            "owasp-mobile": "",
                            "ref": "",
                        }
                    }
                },
                "summary": {"high": 1}
            }
        }
        tp_prefixes = ("com/google/",)
        classified, unclassified = classify_findings(report, tp_prefixes)

        categories = {f["file_path"]: f["category"] for f in classified}
        assert categories["com/example/myapp/CryptoHelper.java"] == "app_code"
        assert categories["com/google/firebase/FirebaseAuth.java"] == "third_party"
        assert categories["android/util/Base64.java"] == "android_code"
        assert len(unclassified) == 0

    def test_obfuscated_path_left_unclassified_for_llm(self):
        """Obfuscated paths should be unclassified (pending LLM first, then
        obfuscation heuristic as final fallback in cli.py)."""
        report = {
            "code_analysis": {
                "findings": {
                    "some_vuln": {
                        "files": {
                            "a/b/c.java": "1",
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
        classified, unclassified = classify_findings(report, ())
        assert len(unclassified) == 1
        assert unclassified[0]["file_path"] == "a/b/c.java"
        assert unclassified[0]["classified_by"] == "pending_llm"

    def test_manifest_component_classification(self):
        """Manifest-declared components should be classified as app_code even
        if they don't match the inferred package prefix."""
        report = {
            "activities": ["com.example.myapp.MainActivity"],
            "services": [],
            "receivers": [],
            "providers": [],
            "code_analysis": {
                "findings": {
                    "vuln": {
                        "files": {
                            "com/example/myapp/MainActivity.java": "5",
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
        classified, unclassified = classify_findings(report, ())
        assert len(classified) == 1
        assert classified[0]["category"] == "app_code"
        assert classified[0]["classified_by"] in ("manifest_component", "manifest_package")
