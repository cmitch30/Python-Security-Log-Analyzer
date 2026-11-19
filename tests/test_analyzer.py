import sys
import unittest
import csv
import json
import tempfile
from unittest.mock import patch
from pathlib import Path

# Allow tests to import the analyzer
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from analyzer import (
    LOG_FILE,
    parse_logs,
    detect_brute_force,
    detect_password_spraying,
    detect_suspicious_success,
    export_alerts,
)


class TestSecurityLogAnalyzer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.events = parse_logs(LOG_FILE)

    def test_log_parsing(self):
        self.assertEqual(len(self.events), 15)

    def test_successful_authentication_count(self):
        successful = [
            e for e in self.events
            if e["status"] == "SUCCESS"
        ]
        self.assertEqual(len(successful), 3)

    def test_failed_authentication_count(self):
        failed = [
            e for e in self.events
            if e["status"] == "FAILED"
        ]
        self.assertEqual(len(failed), 12)

    def test_brute_force_detection(self):
        alerts = detect_brute_force(self.events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["source_ip"],
            "198.51.100.23"
        )
        self.assertEqual(
            alerts[0]["failed_attempts"],
            5
        )

    def test_password_spraying_detection(self):
        alerts = detect_password_spraying(self.events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["source_ip"],
            "203.0.113.45"
        )
        self.assertEqual(
            len(alerts[0]["targeted_users"]),
            4
        )

    def test_suspicious_success_detection(self):
        alerts = detect_suspicious_success(self.events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["username"],
            "alice"
        )
        self.assertEqual(
            alerts[0]["source_ip"],
            "192.0.2.99"
        )

    def test_no_alerts_for_normal_activity(self):
        normal_events = [
            e for e in self.events
            if e["source_ip"] in (
                "192.0.2.10",
                "192.0.2.11"
            )
        ]

        self.assertEqual(
            detect_brute_force(normal_events), []
        )
        self.assertEqual(
            detect_password_spraying(normal_events), []
        )
        self.assertEqual(
            detect_suspicious_success(normal_events), []
        )


    def test_report_export(self):
        alerts = (
            detect_brute_force(self.events)
            + detect_password_spraying(self.events)
            + detect_suspicious_success(self.events)
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("analyzer.BASE_DIR", Path(temp_dir)):
                export_alerts(alerts)

            reports_dir = Path(temp_dir) / "reports"
            json_path = reports_dir / "security_alerts.json"
            csv_path = reports_dir / "security_alerts.csv"

            self.assertTrue(json_path.exists())
            self.assertTrue(csv_path.exists())

            with open(json_path, encoding="utf-8") as file:
                json_alerts = json.load(file)

            with open(csv_path, newline="", encoding="utf-8") as file:
                csv_alerts = list(csv.DictReader(file))

            self.assertEqual(len(json_alerts), 3)
            self.assertEqual(len(csv_alerts), 3)

            expected_types = {
                "BRUTE_FORCE",
                "PASSWORD_SPRAYING",
                "SUCCESS_AFTER_FAILURES",
            }

            self.assertEqual(
                {a["alert_type"] for a in json_alerts},
                expected_types
            )

            self.assertEqual(
                {a["alert_type"] for a in csv_alerts},
                expected_types
            )


if __name__ == "__main__":
    unittest.main()
