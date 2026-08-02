"""
Golden tests for M2: evidence normalization, source adapters, snapshot mode.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from src.pipeline.evidence import (
    ServiceObservation,
    constraint_matches,
    cpe_in_scope,
    fingerprint_service,
    normalize_version_bounds,
    parse_banner_identity,
)
from src.pipeline.ledger import EventLedger
from src.pipeline.sources import (
    BackendStatus,
    CveListV5Adapter,
    EpssAdapter,
    KEVAdapter,
    NvdAdapter,
    RawCveRecord,
    SourceRegistry,
    VulnxAdapter,
    write_snapshot,
)


class TestEvidenceNormalization(unittest.TestCase):
    def test_protocol_string_rejected_as_version(self) -> None:
        v = parse_banner_identity("HTTP/1.1 200 OK", source="probe", timestamp=0.0)
        self.assertEqual(v[0], "unknown")
        self.assertIsNone(v[2])

    def test_banner_parser_sets_identity(self) -> None:
        v, p, vf = parse_banner_identity("Apache/2.4.49 (Unix)", source="probe", timestamp=0.0)
        self.assertEqual((v, p), ("apache", "httpd"))
        self.assertEqual(vf.parsed, "2.4.49")
        self.assertTrue(vf.observed)

    def test_generic_service_label_does_not_invent_identity(self) -> None:
        fp = fingerprint_service(ServiceObservation(target_ip="10.0.0.5", port=80,
                                                    service_name="http proxy",
                                                    banner="", version=""))
        self.assertEqual(fp.vendor.parsed, "unknown")
        self.assertEqual(fp.product.parsed, "unknown")
        self.assertEqual(fp.applicability_grade(), "unknown")
        # No inferred CPE candidates must be produced for unknown identity.
        self.assertEqual(fp.inferred_cpe_candidates, [])

    def test_ssh_alias_recognized(self) -> None:
        fp = fingerprint_service(ServiceObservation(target_ip="10.0.0.5", port=22,
                                                    service_name="ssh",
                                                    banner="OpenSSH_8.2p1", version=""))
        self.assertEqual((fp.vendor.parsed, fp.product.parsed), ("openbsd", "openssh"))
        self.assertEqual(fp.version.parsed, "8.2p1")
        self.assertEqual(fp.applicability_grade(), "exact")

    def test_date_and_cve_rejected_as_version(self) -> None:
        fp = fingerprint_service(ServiceObservation(target_ip="10.0.0.5", port=80,
                                                    service_name="apache",
                                                    banner="Apache httpd",
                                                    version="2025-04-01"))
        self.assertEqual(fp.version.parsed, "unknown")
        fp2 = fingerprint_service(ServiceObservation(target_ip="10.0.0.5", port=80,
                                                      service_name="apache",
                                                      banner="Apache httpd",
                                                      version="CVE-2024-12345"))
        self.assertEqual(fp2.version.parsed, "unknown")

    def test_port_rejected_as_version(self) -> None:
        fp = fingerprint_service(ServiceObservation(target_ip="10.0.0.5", port=80,
                                                    service_name="apache",
                                                    banner="Apache httpd",
                                                    version="8080"))
        self.assertEqual(fp.version.parsed, "unknown")

    def test_status_code_rejected_as_version(self) -> None:
        fp = fingerprint_service(ServiceObservation(target_ip="10.0.0.5", port=80,
                                                    service_name="apache",
                                                    banner="Apache httpd",
                                                    version="200"))
        self.assertEqual(fp.version.parsed, "unknown")

    def test_inferred_cpe_never_overwrites_observed_cpe(self) -> None:
        fp = fingerprint_service(ServiceObservation(
            target_ip="10.0.0.5", port=80, service_name="apache",
            banner="Apache/2.4.49", version="",
            observed_cpe="cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*",
        ))
        # The observed CPE must be preserved; inferred candidates stay but the
        # primary is the observed one.
        self.assertTrue(fp.observed_cpe.startswith("cpe:2.3:a:apache:httpd:2.4.49"))
        self.assertEqual(fp.cpe_primary(), fp.observed_cpe)

    def test_unknown_version_cannot_get_exact_applicability(self) -> None:
        fp = fingerprint_service(ServiceObservation(target_ip="10.0.0.5", port=22,
                                                    service_name="ssh",
                                                    banner="OpenSSH", version=""))
        self.assertEqual(fp.applicability_grade(), "unknown")

    def test_cross_probe_confirmation_promotes_confidence(self) -> None:
        obs = ServiceObservation(target_ip="10.0.0.5", port=80,
                                  service_name="apache", banner="Apache/2.4.49")
        confirm = ServiceObservation(target_ip="10.0.0.5", port=80,
                                      service_name="apache", banner="Server: Apache/2.4.49")
        fp = fingerprint_service(obs, extra_probes=[confirm])
        self.assertEqual(fp.version.confidence, "high")
        self.assertIn("confirmed by independent probe", fp.version.reason)

    def test_inclusive_exclusive_bounds_normalised(self) -> None:
        start, si, end, ei = normalize_version_bounds("v1.0", "2.0",
                                                       start_inclusive=True,
                                                       end_inclusive=False)
        self.assertEqual((start, si, end, ei), ("1.0", True, "2.0", False))

    def test_constraint_match_mismatch_and_unknown(self) -> None:
        from src.pipeline.evidence import VersionConstraint
        # Exact match
        fp = fingerprint_service(ServiceObservation(target_ip="10.0.0.5", port=80,
                                                    service_name="apache",
                                                    banner="Apache/2.4.49"))
        c = VersionConstraint(vendor="apache", product="httpd", version_start="2.4.49",
                              version_end="2.4.50")
        self.assertEqual(constraint_matches(c, fp), "exact")
        # Mismatch (different product)
        c2 = VersionConstraint(vendor="apache", product="tomcat", version_start="0",
                                version_end="9")
        self.assertEqual(constraint_matches(c2, fp), "mismatch")
        # Unknown version: alias-recognised identity, no parsed version.
        fpu = fingerprint_service(ServiceObservation(target_ip="10.0.0.5", port=80,
                                                     service_name="apache",
                                                     banner="", version=""))
        c3 = VersionConstraint(vendor="apache", product="httpd", version_start="0",
                              version_end="9", is_unknown_version=True)
        self.assertEqual(constraint_matches(c3, fpu), "unknown")

    def test_cpe_in_scope_respects_observed(self) -> None:
        fp = fingerprint_service(ServiceObservation(target_ip="10.0.0.5", port=80,
                                                    service_name="apache",
                                                    banner="Apache/2.4.49"))
        bare = "cpe:2.3:a:apache:httpd:*:*:*:*:*:*:*:*"
        self.assertTrue(cpe_in_scope(fp, bare))
        self.assertFalse(cpe_in_scope(fp, "cpe:2.3:a:apache:tomcat:9:*:*:*:*:*:*"))


class TestSourceAdapters(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ledger = EventLedger("run-1")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_isolated_backend_failure_does_not_fail_others(self) -> None:
        # Snapshot dir contains only NVD; vulnx dataset is missing entirely;
        # cvelist adapter is in live mode (no network) so it must report a
        # backend_failed status rather than raising.
        snap = os.path.join(self.tmp, "snap")
        os.makedirs(snap)
        with open(os.path.join(snap, "cves.json"), "w") as fh:
            json.dump({"nvd": [], "cve_list_v5": [], "vulnx": []}, fh)
        registry = SourceRegistry([
            NvdAdapter(mode="snapshot", snapshot_dir=snap, ledger=self.ledger),
            VulnxAdapter(mode="snapshot", snapshot_dir=snap, ledger=self.ledger),
            CveListV5Adapter(mode="live", snapshot_dir=snap, ledger=self.ledger),
        ], ledger=self.ledger)
        results = registry.collect_cves("httpd", "apache", "2.4.49")
        self.assertIsInstance(results, list)
        statuses = [ev.payload.get("status") for ev in self.ledger.events
                    if ev.payload.get("source") in {"nvd", "vulnx", "cve_list_v5"}]
        # Vulnx snapshot is missing its own record set -> no_match is fine;
        # CveListV5 in live mode reports backend_failed.
        self.assertIn(BackendStatus.BACKEND_FAILED, statuses)
        # Nvd returns empty in snapshot mode (no NVD entries written) -> no_match.
        self.assertIn(BackendStatus.NO_MATCH, statuses)

    def test_query_invalid_for_unknown_product(self) -> None:
        registry = SourceRegistry([NvdAdapter(mode="live", ledger=self.ledger)], ledger=self.ledger)
        registry.collect_cves("unknown", "", "")
        self.assertTrue(any(
            ev.payload.get("status") == BackendStatus.QUERY_INVALID
            for ev in self.ledger.events
        ))

    def test_snapshot_round_trip(self) -> None:
        snap = os.path.join(self.tmp, "snap")
        records = [
            RawCveRecord(source="nvd", cve_id="CVE-2024-1", raw={"x": 1},
                          raw_hash="abc", retrieved_at=0.0,
                          vendor="apache", product="httpd",
                          version_start="2.4.49", version_end="2.4.50",
                          cvss_score=9.8, references=["https://example.com/a"]),
            RawCveRecord(source="cve_list_v5", cve_id="CVE-2024-1", raw={"y": 2},
                          raw_hash="def", retrieved_at=0.0,
                          vendor="apache", product="httpd",
                          version_start="2.4.49", version_end="2.4.50"),
        ]
        write_snapshot(snap, records)
        registry = SourceRegistry([
            NvdAdapter(mode="snapshot", snapshot_dir=snap),
            CveListV5Adapter(mode="replay", snapshot_dir=snap),
        ])
        results = registry.collect_cves("httpd", "apache", "2.4.49")
        self.assertEqual(len(results), 2)
        self.assertEqual({r.source for r in results}, {"nvd", "cve_list_v5"})

    def test_priority_signals_are_priority_only(self) -> None:
        snap = os.path.join(self.tmp, "snap")
        os.makedirs(snap)
        with open(os.path.join(snap, "kev.json"), "w") as fh:
            json.dump({"cves": [{"cve_id": "CVE-2024-1", "date_added": 1700000000}]}, fh)
        with open(os.path.join(snap, "epss.json"), "w") as fh:
            json.dump({"cves": [{"cve_id": "CVE-2024-1", "epss_score": 0.9,
                                  "percentile": 0.95}]}, fh)
        registry = SourceRegistry([
            KEVAdapter(mode="snapshot", snapshot_dir=snap),
            EpssAdapter(mode="snapshot", snapshot_dir=snap),
        ])
        signals = registry.collect_priority("httpd", "apache", "2.4.49")
        self.assertIn("CVE-2024-1", signals)
        self.assertTrue(signals["CVE-2024-1"].in_kev)
        self.assertAlmostEqual(signals["CVE-2024-1"].epss_score, 0.9)

    def test_no_year_cap_in_normalised_records(self) -> None:
        # Verify the source adapters expose no max_year filter that would block
        # recent CVEs.
        for adapter_cls in (CveListV5Adapter, NvdAdapter, VulnxAdapter):
            self.assertFalse(hasattr(adapter_cls, "max_year"),
                              f"{adapter_cls.__name__} still exposes a year cap")

    def test_nvd_live_normalises_mocked_api_response(self) -> None:
        payload = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-41773",
                    "published": "2021-10-05T12:00:00.000Z",
                    "descriptions": [{"lang": "en", "value": "Apache httpd path traversal"}],
                    "references": {"referenceData": [{"url": "https://example.test/advisory"}]},
                    "metrics": {"cvssMetricV31": [{"cvssData": {
                        "baseScore": 7.5,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    }}]},
                    "configurations": [{
                        "nodes": [{"cpeMatch": [{
                            "criteria": "cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*",
                            "versionStartIncluding": "2.4.49",
                            "versionEndExcluding": "2.4.51",
                        }]}],
                    }],
                },
            }],
        }

        class Resp:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def read(self):
                return json.dumps(payload).encode()

        with patch("src.pipeline.sources.request.urlopen", return_value=Resp()) as urlopen:
            adapter = NvdAdapter(mode="live", ledger=self.ledger,
                                 last_mod_start="2026-01-01T00:00:00.000Z",
                                 last_mod_end="2026-01-02T00:00:00.000Z")
            records = adapter.fetch("httpd", "apache", "2.4.49")

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].cve_id, "CVE-2021-41773")
        self.assertEqual(records[0].product, "httpd")
        self.assertEqual(records[0].version_end, "2.4.51")
        self.assertTrue(records[0].raw_hash)
        self.assertIn("cpeName=", urlopen.call_args.args[0].full_url)
        self.assertTrue(any(ev.payload.get("status") == BackendStatus.OK for ev in self.ledger.events))

    def test_cvelist_live_reads_local_clone_before_github(self) -> None:
        cve_path = os.path.join(self.tmp, "cves", "2021", "41xxx")
        os.makedirs(cve_path)
        with open(os.path.join(cve_path, "CVE-2021-41773.json"), "w") as fh:
            json.dump({
                "cveMetadata": {
                    "cveId": "CVE-2021-41773",
                    "datePublished": "2021-10-05T12:00:00.000Z",
                },
                "containers": {"cna": {
                    "affected": [{"vendor": "apache", "product": "httpd",
                                  "versions": [{"status": "affected", "version": "2.4.49",
                                                "lessThan": "2.4.51"}]}],
                    "descriptions": [{"lang": "en", "value": "Apache httpd traversal"}],
                    "references": [{"url": "https://httpd.apache.org/security/vulnerabilities_24.html"}],
                }},
            }, fh)
        with patch("src.pipeline.sources.request.urlopen") as urlopen:
            records = CveListV5Adapter(mode="live", snapshot_dir=self.tmp,
                                       ledger=self.ledger).fetch("httpd", "apache", "2.4.49")
        urlopen.assert_not_called()
        self.assertEqual([r.cve_id for r in records], ["CVE-2021-41773"])
        self.assertEqual(records[0].source, "cve_list_v5")

    def test_vulnx_rate_limit_is_isolated(self) -> None:
        err = HTTPError("https://vulnx.test", 429, "rate limited", hdrs=None, fp=None)
        with patch("src.pipeline.sources.request.urlopen", side_effect=err):
            registry = SourceRegistry([
                VulnxAdapter(mode="live", base_url="https://vulnx.test", ledger=self.ledger),
            ], ledger=self.ledger)
            self.assertEqual(registry.collect_cves("httpd", "apache", "2.4.49"), [])
        self.assertTrue(any(ev.payload.get("rate_limited") for ev in self.ledger.events))

    def test_replay_never_invokes_network(self) -> None:
        snap = os.path.join(self.tmp, "snap")
        write_snapshot(snap, [
            RawCveRecord(source="nvd", cve_id="CVE-2024-1", raw={"x": 1},
                          raw_hash="abc", retrieved_at=0.0,
                          vendor="apache", product="httpd"),
        ])
        with patch("src.pipeline.sources.request.urlopen") as urlopen:
            records = NvdAdapter(mode="replay", snapshot_dir=snap).fetch("httpd", "apache", "")
        urlopen.assert_not_called()
        self.assertEqual(len(records), 1)


if __name__ == "__main__":
    unittest.main()
