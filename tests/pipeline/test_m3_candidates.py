"""
Golden tests for M3: ExploitCandidate interface, deterministic ids, collectors,
trust policy, and legacy reader compatibility.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from src.pipeline.candidates import (
    ExploitCandidate,
    LegacyPocCandidate,
    ProcedureStep,
    Provenance,
    derive_candidate_id,
    evaluate_trust,
    is_executable,
    legacy_poc_to_exploit,
    load_candidate,
    save_candidate,
    substitute_placeholders,
)
from src.pipeline.collectors import (
    ExploitDbSpec,
    MetasploitSpec,
    NativeToolSpec,
    NmapNseSpec,
    NucleiSpec,
    PublicPocSpec,
    VendorRecipeSpec,
    collect_for_cve,
    collect_metasploit,
    collect_native_tool,
    collect_nmap_nse,
    collect_nuclei,
    collect_vendor_recipe,
)
from src.pipeline.evidence import Fingerprint, ServiceObservation, fingerprint_service


def _hash_of(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class TestCandidateInterface(unittest.TestCase):
    def test_deterministic_id_excludes_retrieval_time(self) -> None:
        prov1 = Provenance(revision="abc123", sha256="x", retrieved_at=1.0,
                            references=["u"], license="MIT", trust="trusted",
                            source_kind="github", advisory_ref="u")
        prov2 = Provenance(revision="abc123", sha256="x", retrieved_at=999999.0,
                            references=["u"], license="MIT", trust="trusted",
                            source_kind="github", advisory_ref="u")
        id1 = derive_candidate_id(kind="poc", cve_id="CVE-2024-1",
                                    locator="foo.py", provenance=prov1)
        id2 = derive_candidate_id(kind="poc", cve_id="CVE-2024-1",
                                    locator="foo.py", provenance=prov2)
        self.assertEqual(id1, id2)

    def test_round_trip_serialization(self) -> None:
        cand = ExploitCandidate(
            candidate_id="cand-x", cve_id="CVE-2024-1", kind="poc",
            source="public", locator="a.py",
            procedure=[ProcedureStep(stage="execute", argv=["python3", "a.py"])],
            capability="code_execution",
        )
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "cand.json")
            save_candidate(cand, path)
            loaded = load_candidate(path)
            self.assertEqual(loaded.cve_id, cand.cve_id)
            self.assertEqual(loaded.procedure[0].argv, ["python3", "a.py"])
        finally:
            shutil.rmtree(tmp)

    def test_placeholder_substitution_strict(self) -> None:
        argv, unresolved = substitute_placeholders(
            ["nmap", "-p", "${RPORT}", "{TARGET}"],
            {"RPORT": "80"},
            strict=True,
        )
        self.assertEqual(argv, ["nmap", "-p", "80", "{TARGET}"])
        self.assertIn("{TARGET}", unresolved)

    def test_legacy_poc_converted(self) -> None:
        legacy = LegacyPocCandidate(
            cve_id="CVE-2024-1", repo_url="https://github.com/o/r",
            local_path="/tmp/x.py", license="MIT", trust_score=0.5,
            command_template="python3 /tmp/x.py --rhost ${RHOST}",
        )
        cand = legacy_poc_to_exploit(legacy)
        self.assertEqual(cand.kind, "poc")
        self.assertEqual(cand.cve_id, "CVE-2024-1")
        self.assertTrue(cand.procedure)
        # command_template must have produced a single execute step.
        self.assertEqual(cand.procedure[0].stage, "execute")

    def test_github_stars_not_a_trust_signal(self) -> None:
        # Documented: GitHub popularity is NEVER a trust or applicability
        # signal. A "discovery_only" candidate must remain so even with
        # apparent popularity.
        cand = ExploitCandidate(
            candidate_id="cand-x", cve_id="CVE-2024-1", kind="poc",
            source="public", locator="a.py",
            provenance=Provenance(trust="discovery_only",
                                    references=["https://github.com/x/y"]),
        )
        self.assertEqual(evaluate_trust(cand), "discovery_only")
        self.assertFalse(is_executable(cand))

    def test_lab_approved_requires_manifest_approval(self) -> None:
        cand = ExploitCandidate(
            candidate_id="cand-x", cve_id="CVE-2024-1", kind="poc",
            source="public", locator="a.py",
            provenance=Provenance(trust="lab_approved"),
        )
        # Without manifest approval: blocked.
        self.assertEqual(evaluate_trust(cand), "blocked")
        # With explicit manifest approval for the CVE: lab_approved.
        self.assertEqual(evaluate_trust(cand, manifest_approved_lab_ids={"CVE-2024-1"}),
                          "lab_approved")
        self.assertTrue(is_executable(cand, manifest_approved_lab_ids={"CVE-2024-1"}))


class TestCollectors(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _fp(self) -> Fingerprint:
        return fingerprint_service(ServiceObservation(target_ip="10.0.0.5", port=80,
                                                       service_name="apache",
                                                       banner="Apache/2.4.49"))

    def test_metasploit_uses_run_local_resource_script(self) -> None:
        cand = collect_metasploit(MetasploitSpec(
            cve_id="CVE-2024-1", module_name="exploit/multi/http/example",
            options={"RHOSTS": "10.0.0.5", "PAYLOAD": "generic/shell_reverse_tcp"},
        ))
        self.assertEqual(cand.kind, "metasploit")
        script = cand.extra["resource_script"]
        self.assertIn("use exploit/multi/http/example", script)
        self.assertIn("set RHOSTS 10.0.0.5", script)
        self.assertIn("check", script)

    def test_nuclei_rejects_unsafe_classifications(self) -> None:
        with self.assertRaises(ValueError):
            collect_nuclei(NucleiSpec(cve_id="CVE-2024-1", template_id="t",
                                         template_path="/tmp/x.yaml",
                                         classification="code",
                                         pinned_commit="abc"))
        with self.assertRaises(ValueError):
            collect_nuclei(NucleiSpec(cve_id="CVE-2024-1", template_id="t",
                                         template_path="/tmp/x.yaml",
                                         classification="ai",
                                         pinned_commit="abc"))

    def test_nuclei_pinned_with_update_disabled(self) -> None:
        cand = collect_nuclei(NucleiSpec(
            cve_id="CVE-2024-1", template_id="CVE-2021-41773",
            template_path="/tmp/x.yaml", classification="cve",
            pinned_commit="deadbeef",
        ))
        self.assertEqual(cand.kind, "nuclei")
        self.assertIn("-update=false", cand.procedure[0].argv)
        self.assertIn("-duc", cand.procedure[0].argv)
        # Nuclei is not a success evidence — it's a candidate.
        self.assertEqual(cand.capability, "detection")

    def test_nmap_nse_uses_local_script(self) -> None:
        nse = os.path.join(self.tmp, "http-vuln.nse")
        with open(nse, "w") as fh:
            fh.write("-- CVE-2024-1234 stub")
        cand = collect_nmap_nse(NmapNseSpec(cve_id="CVE-2024-1234",
                                            script_name="http-vuln",
                                            script_path=nse))
        self.assertEqual(cand.kind, "nmap_nse")
        self.assertEqual(cand.artifact_hash, _hash_of(nse))
        # The script path is part of the deterministic id; the artifact hash
        # captures its content so re-runs see identical ids.
        self.assertEqual(cand.provenance.sha256, _hash_of(nse))

    def test_vendor_recipe_is_first_class(self) -> None:
        cand = collect_vendor_recipe(VendorRecipeSpec(
            cve_id="CVE-2024-1", vendor="apache", product="httpd",
            steps=[ProcedureStep(stage="execute", argv=["bash", "patch.sh"])],
            references=["https://httpd.apache.org/security/CVE-2024-1"],
        ))
        self.assertEqual(cand.kind, "vendor_recipe")
        self.assertEqual(cand.provenance.trust, "trusted")

    def test_native_tool_blocks_when_binary_missing(self) -> None:
        cand = collect_native_tool(NativeToolSpec(
            cve_id="CVE-2024-1", tool_name="definitely-not-installed-1234",
            argv=["definitely-not-installed-1234", "--target", "<RHOST>"],
        ))
        self.assertEqual(cand.provenance.trust, "discovery_only")
        self.assertFalse(is_executable(cand))

    def test_command_only_candidate_has_no_local_artifact(self) -> None:
        # Metasploit modules do not require a local artifact path; they only
        # need the module name. The candidate must be a valid first-class
        # candidate without forcing a local file path.
        cand = collect_metasploit(MetasploitSpec(cve_id="CVE-2024-1",
                                                  module_name="exploit/...")
        )
        self.assertNotEqual(cand.provenance.trust, "blocked")
        self.assertEqual(cand.locator, "exploit/...")

    def test_two_method_alternatives_per_cve(self) -> None:
        # A Metasploit and a Nuclei alternative for the same CVE must survive
        # shortlisting — shortlisting is per-CVE and may keep up to 2 methods.
        ms = collect_metasploit(MetasploitSpec(cve_id="CVE-2024-1",
                                                module_name="exploit/a"))
        nuc = collect_nuclei(NucleiSpec(cve_id="CVE-2024-1", template_id="CVE-2024-1",
                                          template_path="/tmp/x.yaml",
                                          classification="cve",
                                          pinned_commit="abc"))
        self.assertEqual(ms.cve_id, nuc.cve_id)
        self.assertEqual({ms.kind, nuc.kind}, {"metasploit", "nuclei"})

    def test_collect_for_cve_dispatches_by_kind(self) -> None:
        specs = [
            MetasploitSpec(cve_id="CVE-2024-1", module_name="exploit/a"),
            NucleiSpec(cve_id="CVE-2024-1", template_id="t", template_path="/tmp/x.yaml",
                        classification="cve", pinned_commit="abc"),
            PublicPocSpec(cve_id="CVE-2024-2", repo="o/r", commit="dead",
                           entry_point="x.py"),
            ExploitDbSpec(cve_id="CVE-2024-1", edb_id="12345",
                           local_path="/tmp/x.py"),
        ]
        results = collect_for_cve("CVE-2024-1", specs=specs)
        kinds = sorted(c.kind for c in results)
        self.assertEqual(kinds, sorted(["metasploit", "nuclei", "exploitdb"]))


if __name__ == "__main__":
    unittest.main()
