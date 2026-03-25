"""MobSF REST API client — upload, scan, poll, and fetch report."""

import os
import time
import requests
from utils import print_progress, print_progress_done


class MobSFClient:
    """Client for interacting with a local MobSF instance via REST API."""

    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.headers = {"Authorization": api_key}

    def _check_connection(self):
        """Verify MobSF is reachable."""
        try:
            requests.get(f"{self.base_url}/api/v1/scans", headers=self.headers, timeout=10)
        except (requests.ConnectionError, ConnectionError):
            print(f"MobSF is not running at {self.base_url}. "
                  "Please start MobSF before running this tool.")
            raise SystemExit(1)

    def upload(self, apk_path):
        """Upload an APK file to MobSF.

        Returns the file hash used for subsequent API calls.
        """
        self._check_connection()

        if not os.path.isfile(apk_path):
            print(f"Error: APK file not found: {apk_path}")
            raise SystemExit(1)

        print(f"Uploading {os.path.basename(apk_path)} to MobSF...")
        with open(apk_path, "rb") as f:
            resp = requests.post(
                f"{self.base_url}/api/v1/upload",
                headers=self.headers,
                files={"file": (os.path.basename(apk_path), f, "application/octet-stream")},
                timeout=300,
            )

        if resp.status_code != 200:
            print(f"Error: Upload failed (HTTP {resp.status_code}): {resp.text}")
            raise SystemExit(1)

        data = resp.json()
        file_hash = data.get("hash")
        if not file_hash:
            print(f"Error: Upload response missing file hash: {data}")
            raise SystemExit(1)

        print(f"Upload successful. File hash: {file_hash}")
        return file_hash

    def scan(self, file_hash):
        """Trigger a SAST scan on the uploaded APK."""
        print("Triggering MobSF scan...")
        resp = requests.post(
            f"{self.base_url}/api/v1/scan",
            headers=self.headers,
            data={"hash": file_hash},
            timeout=30,
        )

        if resp.status_code != 200:
            print(f"Error: Scan trigger failed (HTTP {resp.status_code}): {resp.text}")
            raise SystemExit(1)

        print("Scan triggered successfully.")

    def poll_for_report(self, file_hash, timeout=600, poll_interval=5):
        """Poll MobSF for the scan report until it's ready or timeout.

        Returns the full JSON report.
        """
        print("Waiting for scan to complete...")
        start = time.time()

        while True:
            elapsed = time.time() - start
            if elapsed > timeout:
                print(f"\nWarning: Scan timed out after {timeout}s. Attempting to retrieve partial results...")
                return self._fetch_report(file_hash)

            print_progress("Scanning...", elapsed)
            try:
                report = self._fetch_report(file_hash)
                if report:
                    print_progress_done()
                    print("Scan complete. Report retrieved.")
                    return report
            except Exception:
                pass

            time.sleep(poll_interval)

    def _fetch_report(self, file_hash):
        """Fetch the JSON report from MobSF."""
        resp = requests.post(
            f"{self.base_url}/api/v1/report_json",
            headers=self.headers,
            data={"hash": file_hash},
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.json()
        return None

    def get_report(self, file_hash):
        """Download the full JSON report (used after scan is confirmed complete)."""
        report = self._fetch_report(file_hash)
        if not report:
            print("Error: Could not retrieve report from MobSF.")
            raise SystemExit(1)
        return report
