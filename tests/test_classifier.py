"""Tests for the classification engine (Layers 1-3)."""

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


# --- Layer 3: Package inference ---

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
