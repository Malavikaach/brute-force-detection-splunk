
import csv
import tempfile
import unittest

from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import detector


def detect_brute_force(timestamps, threshold=5, window_minutes=5):
    """Return True when enough failures occur within the time window."""
    timestamps = sorted(timestamps)
    recent = deque()

    for timestamp in timestamps:
        cutoff = timestamp - timedelta(minutes=window_minutes)

        while recent and recent[0] < cutoff:
            recent.popleft()

        recent.append(timestamp)

        if len(recent) >= threshold:
            return True

    return False


class TestBruteForceDetection(unittest.TestCase):

    def test_six_failures_within_one_minute(self):
        start = datetime(2026, 10, 27, 10, 0, 0)
        events = [
            start + timedelta(seconds=i * 10)
            for i in range(6)
        ]
        self.assertTrue(detect_brute_force(events))

    def test_four_failures_no_alert(self):
        start = datetime(2026, 10, 27, 10, 0, 0)
        events = [
            start + timedelta(seconds=i * 10)
            for i in range(4)
        ]
        self.assertFalse(detect_brute_force(events))

    def test_five_failures_spread_over_six_minutes(self):
        start = datetime(2026, 10, 27, 10, 0, 0)
        events = [
            start + timedelta(minutes=i * 1.5)
            for i in range(5)
        ]
        self.assertFalse(detect_brute_force(events))

    def test_unsorted_timestamps_still_detected(self):
        start = datetime(2026, 10, 27, 10, 0, 0)
        events = [
            start + timedelta(seconds=i * 10)
            for i in reversed(range(6))
        ]
        self.assertTrue(detect_brute_force(events))


class TestAlertHistory(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.history_path = (
            Path(self.temp_dir.name) / "alert_history.csv"
        )

        self.ip = "192.168.1.10"
        self.window_start = datetime(2026, 10, 27, 10, 0, 0)
        self.window_end = datetime(2026, 10, 27, 10, 0, 40)
        self.message = (
            "HIGH RISK: 192.168.1.10 had at least "
            "5 failed logins within 5 minutes."
        )

        self.history_patch = patch.object(
            detector, "HISTORY_FILE", self.history_path
        )
        self.history_patch.start()

    def tearDown(self):
        self.history_patch.stop()
        self.temp_dir.cleanup()

    def test_new_alert_is_saved(self):
        detector.save_alert(
            self.ip, 5, self.window_start,
            self.window_end, self.message
        )

        with self.history_path.open(
            "r", newline="", encoding="utf-8"
        ) as file:
            rows = list(csv.DictReader(file))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip_address"], self.ip)
        self.assertEqual(rows[0]["failed_attempts"], "5")

    def test_duplicate_alert_is_not_saved_twice(self):
        for _ in range(2):
            detector.save_alert(
                self.ip, 5, self.window_start,
                self.window_end, self.message
            )

        with self.history_path.open(
            "r", newline="", encoding="utf-8"
        ) as file:
            rows = list(csv.DictReader(file))

        self.assertEqual(len(rows), 1)

    def test_different_window_can_be_saved(self):
        detector.save_alert(
            self.ip, 5, self.window_start,
            self.window_end, self.message
        )

        new_start = self.window_end
        new_end = new_start + timedelta(seconds=40)

        detector.save_alert(
            self.ip, 5, new_start,
            new_end, self.message
        )

        with self.history_path.open(
            "r", newline="", encoding="utf-8"
        ) as file:
            rows = list(csv.DictReader(file))

        self.assertEqual(len(rows), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
