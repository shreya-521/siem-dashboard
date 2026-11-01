import unittest
from siem.parser import parse_line, parse_lines


class ParserTests(unittest.TestCase):
    def test_auth_line(self):
        e = parse_line("2026-10-30T09:15:02 auth service=sshd src=10.0.1.5 user=alice result=FAIL")
        self.assertEqual((e.source, e.src_ip, e.user, e.result), ("auth", "10.0.1.5", "alice", "FAIL"))
        self.assertEqual(e.ts.hour, 9)

    def test_firewall_line(self):
        e = parse_line("2026-10-30T09:15:02 firewall src=203.0.113.7 dst=10.0.0.5 dst_port=22 action=deny")
        self.assertEqual((e.dst_port, e.action), (22, "DENY"))

    def test_web_line(self):
        e = parse_line("2026-10-30T09:15:02 web src=10.0.1.8 method=GET path=/login status=401")
        self.assertEqual((e.http_status, e.path), (401, "/login"))

    def test_malformed_lines_return_none(self):
        bad = ["", "garbage", "### corrupted ###",
               "2026-13-45T99:99:99 web src=1.2.3.4 status=200",          # bad timestamp
               "2026-10-30T09:15:02 auth src=not-an-ip user=a result=FAIL",  # bad IP
               "2026-10-30T09:15:02 auth src=1.2.3.4 user=a result=MAYBE",   # bad result
               "2026-10-30T09:15:02 firewall src=1.2.3.4 dst_port=abc action=DENY",
               "2026-10-30T09:15:02 dns src=1.2.3.4"]                        # unknown source
        for line in bad:
            self.assertIsNone(parse_line(line), line)

    def test_parse_lines_counts_skipped(self):
        events, skipped = parse_lines([
            "2026-10-30T09:15:02 auth src=1.1.1.1 user=a result=FAIL", "oops", "", "also bad"])
        self.assertEqual((len(events), skipped), (1, 2))


if __name__ == "__main__":
    unittest.main()
