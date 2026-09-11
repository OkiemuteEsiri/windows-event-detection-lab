import unittest
from datetime import datetime, timezone

from src.detections import (
    detect_encoded_powershell,
    detect_failed_logon_burst,
    detect_privileged_group_change,
    detect_scheduled_task,
    detect_security_log_cleared,
    detect_service_install,
    run_all,
)
from src.models import WindowsEvent


def event(event_id, code, **kwargs):
    return WindowsEvent(
        event_id=event_id,
        timestamp=datetime(2026, 9, 10, 9, 0, tzinfo=timezone.utc),
        host=kwargs.pop("host", "LAB-01"),
        channel=kwargs.pop("channel", "Security"),
        event_code=code,
        user=kwargs.pop("user", "tester"),
        **kwargs,
    )


class DetectionTests(unittest.TestCase):
    def test_failed_logon_burst_requires_five(self):
        events = [event(f"e{i}", 4625, source_ip="198.51.100.5") for i in range(4)]
        self.assertEqual(detect_failed_logon_burst(events), [])

    def test_failed_logon_burst_detects_five(self):
        events = [event(f"e{i}", 4625, source_ip="198.51.100.5") for i in range(5)]
        self.assertEqual(len(detect_failed_logon_burst(events)), 1)

    def test_privileged_group_change(self):
        findings = detect_privileged_group_change([event("e1", 4728, target_user="svc", group_name="Domain Admins")])
        self.assertEqual(findings[0].attack_technique, "T1098")

    def test_log_clear_is_critical(self):
        finding = detect_security_log_cleared([event("e1", 1102)])[0]
        self.assertEqual(finding.severity, "critical")

    def test_service_install_suspicious_path(self):
        finding = detect_service_install([event("e1", 7045, channel="System", service_name="Updater", details="ImagePath=C:\\Temp\\svc.exe")])[0]
        self.assertGreaterEqual(finding.score, 70)

    def test_scheduled_task(self):
        finding = detect_scheduled_task([event("e1", 4698, task_name="Lab Task")])[0]
        self.assertEqual(finding.attack_technique, "T1053.005")

    def test_encoded_powershell(self):
        finding = detect_encoded_powershell([event("e1", 4104, channel="Microsoft-Windows-PowerShell/Operational", process_name="powershell.exe", command_line="powershell -enc SAFE_PLACEHOLDER")])[0]
        self.assertEqual(finding.attack_technique, "T1059.001")

    def test_benign_process_does_not_match_powershell(self):
        self.assertEqual(detect_encoded_powershell([event("e1", 4688, process_name="notepad.exe", command_line="notepad.exe")]), [])

    def test_finding_ids_are_deterministic(self):
        events = [event(f"e{i}", 4625, source_ip="198.51.100.5") for i in range(5)]
        self.assertEqual(detect_failed_logon_burst(events)[0].finding_id, detect_failed_logon_burst(events)[0].finding_id)

    def test_run_all_prioritizes_highest_score(self):
        events = [event("clear", 1102), event("task", 4698, task_name="Lab Task")]
        findings = run_all(events)
        self.assertGreaterEqual(findings[0].score, findings[1].score)


if __name__ == "__main__":
    unittest.main()
