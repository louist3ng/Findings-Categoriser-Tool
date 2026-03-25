"""Tests for MobSF client — upload and polling with mocked HTTP."""

import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import responses
from mobsf_client import MobSFClient


BASE_URL = "http://localhost:8000"
API_KEY = "test_api_key_123"


@pytest.fixture
def client():
    return MobSFClient(BASE_URL, API_KEY)


@pytest.fixture
def temp_apk():
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
        f.write(b"fake apk content")
        path = f.name
    yield path
    os.unlink(path)


class TestUpload:
    @responses.activate
    def test_upload_success(self, client, temp_apk):
        # Mock the connection check
        responses.add(responses.GET, f"{BASE_URL}/api/v1/scans", json={}, status=200)
        # Mock the upload
        responses.add(
            responses.POST,
            f"{BASE_URL}/api/v1/upload",
            json={"hash": "abc123def456", "file_name": "test.apk"},
            status=200,
        )
        file_hash = client.upload(temp_apk)
        assert file_hash == "abc123def456"

    @responses.activate
    def test_upload_failure(self, client, temp_apk):
        responses.add(responses.GET, f"{BASE_URL}/api/v1/scans", json={}, status=200)
        responses.add(responses.POST, f"{BASE_URL}/api/v1/upload", body="Error", status=500)
        with pytest.raises(SystemExit):
            client.upload(temp_apk)

    @responses.activate
    def test_connection_failure(self, client, temp_apk):
        responses.add(
            responses.GET,
            f"{BASE_URL}/api/v1/scans",
            body=ConnectionError("Connection refused"),
        )
        with pytest.raises(SystemExit):
            client.upload(temp_apk)


class TestScan:
    @responses.activate
    def test_scan_trigger(self, client):
        responses.add(responses.POST, f"{BASE_URL}/api/v1/scan", json={"status": "ok"}, status=200)
        client.scan("abc123")  # Should not raise

    @responses.activate
    def test_scan_failure(self, client):
        responses.add(responses.POST, f"{BASE_URL}/api/v1/scan", body="Error", status=500)
        with pytest.raises(SystemExit):
            client.scan("abc123")


class TestPollForReport:
    @responses.activate
    def test_report_available_immediately(self, client):
        responses.add(
            responses.POST,
            f"{BASE_URL}/api/v1/report_json",
            json={"package_name": "com.test.app", "code_analysis": {}},
            status=200,
        )
        report = client.poll_for_report("abc123", timeout=10, poll_interval=0.1)
        assert report is not None
        assert report["package_name"] == "com.test.app"

    @responses.activate
    def test_report_timeout(self, client):
        responses.add(responses.POST, f"{BASE_URL}/api/v1/report_json", body="Error", status=500)
        report = client.poll_for_report("abc123", timeout=1, poll_interval=0.5)
        # Should return None on timeout (500 returns None from _fetch_report)
        assert report is None
