"""
tests/smoke_test.py

Pure-stdlib smoke tests for the v1.2.0 refactor. No ADB, no network required.

Run with:    python3 tests/smoke_test.py
Exit code 0  -> all assertions passed.
"""

import os
import re
import sys
import socket
import unittest

# Make the project importable when running from the repo root
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


class CorroborationTests(unittest.TestCase):
    """Verify the multi-indicator corroboration rules."""

    def _f(self, label, cls, value="x"):
        from core.findings import Finding
        score = {"CRITICAL": 95, "HIGH": 75, "MEDIUM": 55, "LOW": 25, "INFO": 5}.get(label, 0)
        return Finding(label=label, score=score, family="T", indicator_class=cls, title="t", raw_value=value)

    def test_no_findings_is_clean(self):
        from core.findings import FindingReport
        rep = FindingReport(family="T")
        self.assertEqual(rep.label, "CLEAN")

    def test_hash_match_alone_is_critical(self):
        from core.findings import FindingReport, CLASS_FILE_HASH
        rep = FindingReport(family="T")
        rep.add(self._f("HIGH", CLASS_FILE_HASH))
        self.assertEqual(rep.label, "CRITICAL")

    def test_single_high_is_only_medium(self):
        from core.findings import FindingReport, CLASS_PROCESS
        rep = FindingReport(family="T")
        rep.add(self._f("HIGH", CLASS_PROCESS))
        self.assertEqual(rep.label, "MEDIUM")

    def test_high_plus_medium_independent_is_high(self):
        from core.findings import FindingReport, CLASS_PROCESS, CLASS_NETWORK
        rep = FindingReport(family="T")
        rep.add(self._f("HIGH", CLASS_PROCESS))
        rep.add(self._f("MEDIUM", CLASS_NETWORK))
        self.assertEqual(rep.label, "HIGH")

    def test_two_mediums_independent_is_high(self):
        from core.findings import FindingReport, CLASS_PROCESS, CLASS_PACKAGE
        rep = FindingReport(family="T")
        rep.add(self._f("MEDIUM", CLASS_PROCESS))
        rep.add(self._f("MEDIUM", CLASS_PACKAGE))
        self.assertEqual(rep.label, "HIGH")

    def test_two_highs_same_class_still_medium(self):
        from core.findings import FindingReport, CLASS_PROCESS
        rep = FindingReport(family="T")
        rep.add(self._f("HIGH", CLASS_PROCESS))
        rep.add(self._f("HIGH", CLASS_PROCESS))
        # Both same class -> no corroboration
        self.assertEqual(rep.label, "MEDIUM")

    def test_single_low_is_info(self):
        from core.findings import FindingReport, CLASS_OTHER
        rep = FindingReport(family="T")
        rep.add(self._f("LOW", CLASS_OTHER))
        self.assertEqual(rep.label, "INFO")


class StrictMatchingTests(unittest.TestCase):
    """Verify the strict PS / pkg / proc-tcp parsers."""

    def test_ps_name_extraction_exact(self):
        from modules.pegasus_detector import _parse_ps_names
        sample = (
            "USER  PID  PPID  VSZ  RSS  WCHAN  ADDR  S  NAME\n"
            "u0_a123  4567  1  1234  567  ep_poll  0  S  com.example.app\n"
            "u0_a124  4568  1  1234  567  ep_poll  0  S  pegasus\n"
            "u0_a125  4569  1  1234  567  ep_poll  0  S  alarmmanager\n"
        )
        names = _parse_ps_names(sample)
        self.assertIn("pegasus", names)
        self.assertIn("alarmmanager", names)
        self.assertIn("com.example.app", names)
        # Must NOT contain the literal "NAME" header
        self.assertNotIn("NAME", names)

    def test_ps_name_does_not_substring(self):
        from modules.pegasus_detector import _parse_ps_names
        # AlarmManager is NOT the indicator "alarm"; we only get whole names
        sample = (
            "USER  PID  PPID  VSZ  RSS  WCHAN  ADDR  S  NAME\n"
            "u0_a1  1  1  1  1  x  0  S  alarmmanager\n"
        )
        names = _parse_ps_names(sample)
        # The string "alarm" should NOT be a "name" (no substring extraction)
        self.assertNotIn("alarm", names)
        self.assertIn("alarmmanager", names)

    def test_ip_to_proc_hex(self):
        from modules.pegasus_detector import _ip_to_proc_hex
        # 103.207.85.8 in little-endian hex per /proc/net/tcp convention
        self.assertEqual(_ip_to_proc_hex("103.207.85.8"), "0855cf67")
        self.assertEqual(_ip_to_proc_hex("1.2.3.4"), "04030201")
        self.assertEqual(_ip_to_proc_hex("not.an.ip"), "")

    def test_proc_net_tcp_established_detection(self):
        from modules.pegasus_detector import _established_to_ip
        # /proc/net/tcp uses little-endian hex. 103.207.85.8 = 0855cf67
        # State 01 = ESTABLISHED, state 06 = TIME_WAIT.
        sample = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n"
            "  0:  0100007F:0277 0855CF67:01BB 01 00000000:00000000 0 0 0 0 0 1000 1 1234\n"
        )
        self.assertTrue(_established_to_ip(sample, "0855cf67"))
        # Same IP but in LISTEN state -> not a finding
        sample_listen = sample.replace("01 0000", "0A 0000")
        self.assertFalse(_established_to_ip(sample_listen, "0855cf67"))
        # Different IP
        self.assertFalse(_established_to_ip(sample, "AABBCCDD"))


class GenericValueFilterTests(unittest.TestCase):
    """STIX2 patterns sometimes contain wildcards. We must skip them."""

    def test_generic_values_are_filtered(self):
        from modules.mvt_check import _value_looks_generic
        self.assertTrue(_value_looks_generic("*", "file_path"))
        self.assertTrue(_value_looks_generic("*.apk", "file_path"))
        self.assertTrue(_value_looks_generic("<name>", "file_name"))
        self.assertTrue(_value_looks_generic("${name}", "file_name"))
        self.assertTrue(_value_looks_generic("name", "file_name"))
        # Real indicators should pass
        self.assertFalse(_value_looks_generic("com.nso.pegasus", "app_id_exact"))
        self.assertFalse(_value_looks_generic("attacker.example.com", "domain_exact"))


class ThreatIntelTests(unittest.TestCase):
    """The threat-intel helpers should not need a real device."""

    def test_build_dorks_no_slicing(self):
        from core.threat_intel import build_dorks
        info = {"Model": "Pixel 7", "Product Name": "panther",
                "Manufacturer": "Google", "Android Version": "14"}
        dorks = build_dorks(info)
        # We use every keyword, not just the first
        keywords = {re.sub(r"[^a-zA-Z0-9]+", " ", x.lower()).strip()
                    for x in ("Pixel 7", "panther", "Google", "android 14")}
        joined = " ".join(dorks).lower()
        for kw in keywords:
            self.assertIn(kw.lower(), joined)
        # And we should produce a healthy number
        self.assertGreater(len(dorks), 20)

    def test_intel_item_dedupe(self):
        from core.threat_intel import IntelItem, _dedupe
        a = IntelItem(title="t1", url="https://x", source="s")
        b = IntelItem(title="t1-dup", url="https://x", source="s")  # same url
        c = IntelItem(title="t2", url="https://y", source="s")
        result = _dedupe([a, b, c])
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].title, "t1")
        self.assertEqual(result[1].title, "t2")


class SourceAvailabilityTests(unittest.TestCase):
    """Each source should report is_available() accurately without network."""

    def test_github_code_requires_token(self):
        from core.threat_intel import GitHubCodeIntel
        src = GitHubCodeIntel()
        if not os.environ.get("GITHUB_TOKEN") and not os.environ.get("GH_TOKEN"):
            self.assertFalse(src.is_available())
        else:
            self.assertTrue(src.is_available())

    def test_github_repo_always_available(self):
        from core.threat_intel import GitHubRepoIntel
        self.assertTrue(GitHubRepoIntel().is_available())

    def test_nvd_always_available(self):
        from core.threat_intel import NvdCveIntel
        self.assertTrue(NvdCveIntel().is_available())


class ImportsTests(unittest.TestCase):
    """Make sure all the modules the CLI imports still resolve."""

    def test_all_imports(self):
        # These imports will pull in rich, our modules, etc.
        import cellinspector  # noqa: F401
        from core import threat_intel, findings  # noqa: F401
        from modules import zero_day_checker, mvt_check, pegasus_detector  # noqa: F401


if __name__ == "__main__":
    # Force UTF-8 stdout so the unicode in test names renders cleanly
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    unittest.main(verbosity=2)
