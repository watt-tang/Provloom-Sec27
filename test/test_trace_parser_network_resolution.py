from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.runner.trace_parser import parse_trace_dir


class TraceParserNetworkResolutionTests(unittest.TestCase):
    def test_dns_query_name_is_recovered_from_trace_payload(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provloom-trace-") as temp_dir:
            trace_path = Path(temp_dir) / "trace.log.20"
            trace_path.write_text(
                "\n".join(
                    [
                        '17:33:44.056898 connect(4, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("10.255.255.254")}, 16) = 0',
                        '17:33:44.057115 sendmmsg(4, [{msg_hdr={msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="\\336\\256\\1\\0\\0\\1\\0\\0\\0\\0\\0\\0\\3api\\10deepseek\\3com\\0\\0\\1\\0\\1", iov_len=34}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, msg_len=34}], 1, MSG_NOSIGNAL) = 1',
                    ]
                ),
                encoding="utf-8",
            )

            artifacts = parse_trace_dir(Path(temp_dir))

        self.assertEqual(len(artifacts.network), 2)
        event = artifacts.network[0]
        self.assertEqual(event.raw_host, "10.255.255.254")
        self.assertEqual(event.raw_port, 53)
        self.assertEqual(event.original_domain, "api.deepseek.com")
        self.assertIn("dns", event.network_evidence_sources)
        send_event = artifacts.network[1]
        self.assertEqual(send_event.action, "sendmmsg")
        self.assertEqual(send_event.network_evidence_level, "request_observed")
        self.assertEqual(send_event.carrier_type, "socket_payload")


if __name__ == "__main__":
    unittest.main()
