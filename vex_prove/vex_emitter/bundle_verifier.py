import json
import re
import tarfile
from pathlib import Path
from typing import Dict, List
from pydantic import BaseModel, Field
from z3 import Solver, unsat, sat

class BundleVerificationReport(BaseModel):
    bundle_path: str
    total_openvex_statements: int = 0
    verified_unsat_proofs: int = 0
    verified_sat_warnings: int = 0
    forged_or_unproven_claims: List[str] = Field(default_factory=list)
    k8s_admission_decision: str  # "ADMIT_PROOF_CARRYING_VEX_VERIFIED" or "DENY_FORGED_OR_UNPROVEN_VEX"

class ProofCarryingBundleVerifier:
    """
    Plugin Direction 2 (Kubernetes Admission Webhook & EU CRA Auditor Gate):
    Independently re-verifies the SMT-LIB2 mathematical proofs inside
    `cra_annex_vii_proof_bundle.tar.gz` against the OpenVEX JSON claims.
    """

    def verify_bundle(self, bundle_path: Path) -> BundleVerificationReport:
        with tarfile.open(bundle_path, "r:gz") as tar:
            openvex_bytes = tar.extractfile("vex-prove.openvex.json").read()
            smt2_bytes = tar.extractfile("z3_proof_certificate.smt2").read()

        openvex_doc = json.loads(openvex_bytes.decode("utf-8"))
        smt2_text = smt2_bytes.decode("utf-8")

        # Parse individual SMT-LIB2 blocks keyed by CVE ID
        smt_blocks: Dict[str, str] = {}
        pattern = re.compile(r"; === (CVE-[0-9A-Za-z\-]+) \((UNSAT|SAT)\) ===\n(.*?)(?=\n; === |\Z)", re.DOTALL)
        for match in pattern.finditer(smt2_text):
            cve_id, _, body = match.group(1), match.group(2), match.group(3)
            smt_blocks[cve_id] = body.strip()

        verified_unsat = 0
        verified_sat = 0
        forged: List[str] = []
        statements = openvex_doc.get("statements", [])

        for stmt in statements:
            cve_id = stmt.get("vulnerability", {}).get("name", "")
            claimed_status = stmt.get("status", "")
            smt_body = smt_blocks.get(cve_id)

            if not smt_body:
                forged.append(f"{cve_id}: Missing SMT-LIB2 proof block")
                continue

            # Re-solve the raw SMT-LIB2 formula independently in Z3
            solver = Solver()
            solver.from_string(smt_body)
            actual_res = solver.check()

            if claimed_status == "not_affected":
                if actual_res == unsat:
                    verified_unsat += 1
                else:
                    forged.append(f"{cve_id}: Claimed 'not_affected' but Z3 proof evaluated to {actual_res}!")
            elif claimed_status == "affected":
                if actual_res == sat:
                    verified_sat += 1
                else:
                    forged.append(f"{cve_id}: Claimed 'affected' but Z3 evaluated to {actual_res}")

        decision = (
            "ADMIT_PROOF_CARRYING_VEX_VERIFIED"
            if not forged
            else "DENY_FORGED_OR_UNPROVEN_VEX"
        )
        return BundleVerificationReport(
            bundle_path=str(bundle_path),
            total_openvex_statements=len(statements),
            verified_unsat_proofs=verified_unsat,
            verified_sat_warnings=verified_sat,
            forged_or_unproven_claims=forged,
            k8s_admission_decision=decision,
        )
