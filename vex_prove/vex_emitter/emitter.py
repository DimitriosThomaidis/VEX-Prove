import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any

from vex_prove.ebpf_collector.tracer import RuntimeTraceSnapshot
from vex_prove.smt_verifier.prover import SMTVerificationResult

CYCLONEDX_JUSTIFICATION_MAP = {
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "protected_by_compiler",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}

class MultiStandardVEXEmitter:
    """Emits batch OpenVEX v0.2.0, CycloneDX v1.6, OASIS CSAF 2.0, and Proof Bundle."""

    def emit_batch(
        self,
        product_purl: str,
        trace: RuntimeTraceSnapshot,
        smt_results: List[SMTVerificationResult],
        output_dir: Path,
    ) -> Dict[str, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        now_iso = datetime.now(timezone.utc).isoformat()

        openvex_statements: List[Dict[str, Any]] = []
        cdx_vulns: List[Dict[str, Any]] = []
        csaf_vulns: List[Dict[str, Any]] = []
        smt2_blobs: List[str] = []

        for smt in smt_results:
            proof_summary = (
                f"[VEX-Prove Formal Certificate] Z3={smt.z3_result} | "
                f"UNSAT_Core={smt.unsat_core} | "
                f"eBPF_Mode={trace.ebpf_probe_status} | "
                f"Trace_SHA256={trace.trace_sha256[:16]}"
            )
            smt2_blobs.append(f"; === {smt.vuln_id} ({smt.z3_result}) ===\n{smt.smtlib2_proof_excerpt}\n")

            # 1. OpenVEX Statement
            stmt: Dict[str, Any] = {
                "vulnerability": {"name": smt.vuln_id, "description": smt.title},
                "products": [{"@id": product_purl}],
                "status": smt.status,
            }
            if smt.status == "not_affected" and smt.cisa_justification:
                stmt["justification"] = smt.cisa_justification
                stmt["impact_statement"] = proof_summary
            else:
                stmt["action_statement"] = (
                    f"Exploitable path verified via Z3 SAT! Active preconditions: {smt.counterexample_payload}"
                )
            openvex_statements.append(stmt)

            # 2. CycloneDX Vulnerability Entry
            cdx_state = "not_affected" if smt.status == "not_affected" else "exploitable"
            cdx_just = CYCLONEDX_JUSTIFICATION_MAP.get(
                smt.cisa_justification or "", "protected_by_mitigating_control"
            )
            cdx_vulns.append({
                "id": smt.vuln_id,
                "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{smt.vuln_id}"},
                "analysis": {
                    "state": cdx_state,
                    "justification": cdx_just if smt.status == "not_affected" else None,
                    "detail": proof_summary,
                },
                "affects": [{"ref": product_purl}],
            })

            # 3. CSAF 2.0 Entry
            csaf_key = "known_not_affected" if smt.status == "not_affected" else "known_affected"
            csaf_vulns.append({
                "cve": smt.vuln_id,
                "product_status": {csaf_key: ["PROD-URLLIB3"]},
                "notes": [{"category": "summary", "text": proof_summary}],
            })

        openvex_doc = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://vex-prove.local/openvex/urllib3-batch-attestation",
            "author": "Dimitrios Thomaidis (VEX-Prove Engine)",
            "role": "Automated Concolic & SMT Verification Authority",
            "timestamp": now_iso,
            "version": 1,
            "statements": openvex_statements,
        }
        openvex_path = output_dir / "vex-prove.openvex.json"
        openvex_path.write_text(json.dumps(openvex_doc, indent=2), encoding="utf-8")

        cdx_doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {"timestamp": now_iso},
            "vulnerabilities": cdx_vulns,
        }
        cdx_path = output_dir / "vex-prove.cdx.json"
        cdx_path.write_text(json.dumps(cdx_doc, indent=2), encoding="utf-8")

        csaf_doc = {
            "document": {
                "category": "csaf_vex",
                "csaf_version": "2.0",
                "title": "VEX-Prove Multi-CVE Formal Attestation",
                "publisher": {"category": "vendor", "name": "VEX-Prove", "namespace": "https://vex-prove.local"},
                "tracking": {
                    "id": "VEX-PROVE-BATCH-001",
                    "status": "final",
                    "version": "1",
                    "initial_release_date": now_iso,
                    "current_release_date": now_iso,
                },
            },
            "product_tree": {
                "full_product_names": [
                    {
                        "name": product_purl,
                        "product_id": "PROD-URLLIB3",
                        "product_identification_helper": {"purl": product_purl},
                    }
                ]
            },
            "vulnerabilities": csaf_vulns,
        }
        csaf_path = output_dir / "vex-prove.csaf.json"
        csaf_path.write_text(json.dumps(csaf_doc, indent=2), encoding="utf-8")

        smt2_path = output_dir / "z3_proof_certificate.smt2"
        smt2_path.write_text("\n".join(smt2_blobs), encoding="utf-8")

        bundle_path = output_dir / "cra_annex_vii_proof_bundle.tar.gz"
        with tarfile.open(bundle_path, "w:gz") as tar:
            for p in [openvex_path, cdx_path, csaf_path, smt2_path]:
                tar.add(p, arcname=p.name)

        return {"openvex": openvex_path, "cyclonedx": cdx_path, "csaf": csaf_path, "bundle": bundle_path}
