import ast
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from z3 import Bool, BoolVal, Solver, And, unsat

from vex_prove.ebpf_collector.tracer import RuntimeTraceSnapshot

class SMTVerificationResult(BaseModel):
    vuln_id: str
    title: str = ""
    status: str  # "not_affected" or "affected"
    cisa_justification: Optional[str] = None
    z3_result: str  # "UNSAT" or "SAT"
    unsat_core: List[str] = Field(default_factory=list)
    smtlib2_proof_excerpt: str = ""
    counterexample_payload: Optional[Dict[str, str]] = None
    remediation_hint: Optional[str] = None
    counterfactual_fix_proof: Optional[str] = None

URLLIB3_CVE_PRECONDITIONS = {
    "CVE-2024-37891": {
        "title": "Proxy-Authorization header not stripped on cross-origin redirect",
        "requires": ["redirect_enabled", "has_proxy_auth_header", "not_strips_proxy_auth"],
        "remediation": "Pass redirect=False or strip 'Proxy-Authorization' in Retry.remove_headers_on_redirect",
        "counterfactual_guard": ("redirect_enabled", False, "Counterfactual_Guard_Set_redirect_False"),
    },
    "CVE-2025-50181": {
        "title": "Redirects not disabled when PoolManager retries disabled",
        "requires": ["redirect_enabled"],
        "remediation": "Enforce redirect=False at the request/Retry caller boundary",
        "counterfactual_guard": ("redirect_enabled", False, "Counterfactual_Guard_Set_redirect_False"),
    },
    "CVE-2026-44431": {
        "title": "Information disclosure via cross-origin redirects",
        "requires": ["redirect_enabled"],
        "remediation": "Enforce redirect=False at the request/Retry caller boundary",
        "counterfactual_guard": ("redirect_enabled", False, "Counterfactual_Guard_Set_redirect_False"),
    },
    "CVE-2026-21441": {
        "title": "Decompression-bomb safeguard bypass on HTTP redirects (streaming)",
        "requires": ["redirect_enabled", "streaming_enabled"],
        "remediation": "Set redirect=False and preload_content=True (stream=False)",
        "counterfactual_guard": ("redirect_enabled", False, "Counterfactual_Guard_Set_redirect_False"),
    },
    "CVE-2025-66471": {
        "title": "Streaming API improperly handles highly compressed data",
        "requires": ["streaming_enabled"],
        "remediation": "Keep stream=False or upgrade urllib3 >= 2.6.0",
        "counterfactual_guard": ("streaming_enabled", False, "Counterfactual_Guard_Set_stream_False"),
    },
    "CVE-2026-97687": {
        "title": "Traffic interception via HTTPS proxy TLS configuration override",
        "requires": ["https_proxy_configured"],
        "remediation": "Do not use untrusted HTTPS ProxyManager or upgrade urllib3 >= 2.8.0",
        "counterfactual_guard": ("https_proxy_configured", False, "Counterfactual_Guard_Disable_HTTPS_Proxy"),
    },
    "CVE-2025-66418": {
        "title": "Unbounded decompression chain leads to resource exhaustion (libz.so)",
        "requires": ["decode_content_enabled"],
        "remediation": "Pass decode_content=False at caller boundary or upgrade urllib3 >= 2.6.0",
        "counterfactual_guard": ("decode_content_enabled", False, "Counterfactual_Guard_Set_decode_content_False"),
    },
    "CVE-2026-97689": {
        "title": "Denial of Service via unbounded memory allocation in chunk parser",
        "requires": ["chunked_response_parsing_enabled"],
        "remediation": "Upgrade urllib3 >= 2.8.0 or enforce strict response max-length at reverse proxy",
        "counterfactual_guard": ("chunked_response_parsing_enabled", False, "Counterfactual_Guard_Disable_Chunked_Encoding"),
    },
}

class UnderConstrainedSMTProver:
    """
    Solves the caller boundary slice (F_caller -> S_vuln) in Z3 for every CVE
    reported by Trivy, and runs Counterfactual Z3 Remediation Proofs on SAT findings.
    """

    def verify_cve_batch(
        self,
        cve_ids: List[str],
        caller_source: Path,
        trace: RuntimeTraceSnapshot,
        stage1_synthesized: Optional[Dict[str, Any]] = None,
    ) -> List[SMTVerificationResult]:
        ast_guards = self._extract_caller_sanitizers(caller_source)
        results: List[SMTVerificationResult] = []

        for cve_id in cve_ids:
            base_spec = URLLIB3_CVE_PRECONDITIONS.get(cve_id)
            if not base_spec and not (stage1_synthesized and cve_id in stage1_synthesized):
                continue
            spec = dict(base_spec) if base_spec else {
                "title": f"Stage-1 Synthesized Advisory ({cve_id})",
                "requires": ["redirect_enabled"],
                "remediation": "Enforce Stage-1 synthesized caller guard",
                "counterfactual_guard": ("redirect_enabled", False, "Counterfactual_Guard_Set_redirect_False"),
            }
            if stage1_synthesized and cve_id in stage1_synthesized:
                syn_obj = stage1_synthesized[cve_id]
                req_list = getattr(syn_obj, "required_flags", None) or syn_obj.get("required_flags")
                if req_list:
                    spec["requires"] = list(req_list)

            solver = Solver()
            solver.set(unsat_core=True)

            var_names = [
                "redirect_enabled",
                "has_proxy_auth_header",
                "not_strips_proxy_auth",
                "streaming_enabled",
                "https_proxy_configured",
                "decode_content_enabled",
                "chunked_response_parsing_enabled",
            ]
            var_map = {name: Bool(name) for name in var_names}

            # 1. Bind Concrete Runtime Context (C_env) from Stage 2
            if "redirect" in trace.captured_kwargs:
                val = bool(trace.captured_kwargs["redirect"])
                solver.assert_and_track(
                    var_map["redirect_enabled"] == BoolVal(val),
                    f"eBPF_Runtime_State_redirect_is_{val}",
                )
            if "remove_headers_on_redirect" in trace.captured_kwargs:
                headers = [h.lower() for h in trace.captured_kwargs["remove_headers_on_redirect"]]
                not_stripped = "proxy-authorization" not in headers
                solver.assert_and_track(
                    var_map["not_strips_proxy_auth"] == BoolVal(not_stripped),
                    "eBPF_Runtime_State_Retry_strips_ProxyAuth",
                )

            stream_val = bool(trace.captured_kwargs.get("stream", False))
            solver.assert_and_track(
                var_map["streaming_enabled"] == BoolVal(stream_val),
                f"eBPF_Runtime_State_stream_is_{stream_val}",
            )
            proxy_val = bool(trace.captured_kwargs.get("proxy_url", False))
            solver.assert_and_track(
                var_map["https_proxy_configured"] == BoolVal(proxy_val),
                f"eBPF_Runtime_State_https_proxy_is_{proxy_val}",
            )

            decode_val = bool(trace.captured_kwargs.get("decode_content", True))
            solver.assert_and_track(
                var_map["decode_content_enabled"] == BoolVal(decode_val),
                f"eBPF_Runtime_Default_decode_content_is_{decode_val}",
            )
            solver.assert_and_track(
                var_map["chunked_response_parsing_enabled"] == BoolVal(True),
                "eBPF_Runtime_Default_HTTP_chunk_parser_active",
            )

            # 2. Bind AST Sanitizer Guards from F_caller
            if ast_guards.get("blocks_proxy_auth_header"):
                solver.assert_and_track(
                    var_map["has_proxy_auth_header"] == BoolVal(False),
                    "AST_Caller_Guard_Pops_Proxy_Authorization",
                )
            if ast_guards.get("forces_redirect_false"):
                solver.assert_and_track(
                    var_map["redirect_enabled"] == BoolVal(False),
                    "AST_Caller_Hardcoded_redirect_False",
                )
            if ast_guards.get("forces_decode_content_false"):
                solver.assert_and_track(
                    var_map["decode_content_enabled"] == BoolVal(False),
                    "AST_Caller_Hardcoded_decode_content_False",
                )

            # 3. Assert CVE Precondition Formula (Phi_crash)
            req_exprs = [var_map[r] == BoolVal(True) for r in spec["requires"]]
            solver.assert_and_track(
                And(*req_exprs),
                f"OSV_Precondition_{cve_id}_Requires_{'_AND_'.join(spec['requires'])}",
            )

            if solver.check() == unsat:
                core = [str(c) for c in solver.unsat_core()]
                if any("stream_is_False" in c or "https_proxy_is_False" in c for c in core):
                    just = "vulnerable_code_not_in_execute_path"
                elif any("Hardcoded" in c or "redirect_is_False" in c for c in core):
                    just = "vulnerable_code_cannot_be_controlled_by_adversary"
                else:
                    just = "inline_mitigations_already_exist"

                results.append(
                    SMTVerificationResult(
                        vuln_id=cve_id,
                        title=spec["title"],
                        status="not_affected",
                        cisa_justification=just,
                        z3_result="UNSAT",
                        unsat_core=core,
                        smtlib2_proof_excerpt=self._export_self_contained_smt2(solver),
                    )
                )
            else:
                model = solver.model()
                ce = {
                    req_var: str(model[var_map[req_var]])
                    for req_var in spec["requires"]
                }
                # Run Counterfactual Z3 Proof: Does injecting the proposed guard flip SAT -> UNSAT?
                cf_proof = self._prove_counterfactual_remediation(spec)
                results.append(
                    SMTVerificationResult(
                        vuln_id=cve_id,
                        title=spec["title"],
                        status="affected",
                        cisa_justification=None,
                        z3_result="SAT",
                        counterexample_payload=ce,
                        remediation_hint=spec["remediation"],
                        counterfactual_fix_proof=cf_proof,
                        smtlib2_proof_excerpt=self._export_self_contained_smt2(solver),
                    )
                )
        return results

    @staticmethod
    def _prove_counterfactual_remediation(spec: Dict[str, Any]) -> str:
        """
        Synthesizes a secondary Z3 solver instance injecting the candidate remediation
        guard to mathematically verify that the fix flips SAT -> UNSAT.
        """
        cf_solver = Solver()
        cf_solver.set(unsat_core=True)
        var_map = {r: Bool(r) for r in spec["requires"]}

        # Assert the CVE crash requirement
        cf_solver.assert_and_track(
            And(*[var_map[r] == BoolVal(True) for r in spec["requires"]]),
            "CVE_Trigger_Precondition",
        )

        # Inject the counterfactual remediation guard
        guard_var, guard_val, guard_label = spec["counterfactual_guard"]
        if guard_var not in var_map:
            var_map[guard_var] = Bool(guard_var)
        cf_solver.assert_and_track(
            var_map[guard_var] == BoolVal(guard_val),
            guard_label,
        )

        if cf_solver.check() == unsat:
            core = [str(c) for c in cf_solver.unsat_core()]
            return f"VERIFIED (SAT -> UNSAT via {core})"
        return "UNVERIFIED_REQUIRES_VERSION_UPGRADE"

    @staticmethod
    def _extract_caller_sanitizers(source_path: Path) -> Dict[str, bool]:
        """
        Fix #2: Context-sensitive AST sanitizer extraction with dead-branch (`if False:`) pruning.
        Only accepts `.pop('Proxy-Authorization')`, `del headers['Proxy-Authorization']`,
        or `remove_headers_on_redirect=[...]` and ignores `print()` or dead code.
        """
        from vex_prove.smt_verifier.backport_prover import SemanticBackportProver
        code = source_path.read_text(encoding="utf-8")
        tree = ast.parse(code)
        stripped_headers = SemanticBackportProver._extract_local_stripped_headers(source_path)
        flags = {
            "blocks_proxy_auth_header": "proxy-authorization" in stripped_headers,
            "forces_redirect_false": False,
            "forces_decode_content_false": False,
        }

        def _walk_live(node: ast.AST):
            if isinstance(node, ast.If):
                if isinstance(node.test, ast.Constant) and bool(node.test.value) is False:
                    for s in node.orelse:
                        _walk_live(s)
                    return
            if isinstance(node, ast.keyword) and node.arg == "redirect":
                if isinstance(node.value, ast.Constant) and node.value.value is False:
                    flags["forces_redirect_false"] = True
            if isinstance(node, ast.keyword) and node.arg == "decode_content":
                if isinstance(node.value, ast.Constant) and node.value.value is False:
                    flags["forces_decode_content_false"] = True
            for child in ast.iter_child_nodes(node):
                _walk_live(child)

        _walk_live(tree)
        return flags

    @staticmethod
    def _export_self_contained_smt2(solver: Solver) -> str:
        """
        Exports standard SMT-LIB2 from a tracked Z3 solver and explicitly asserts
        all tracking assumption literals so standalone `z3` / `from_string()`
        re-evaluates the exact UNSAT/SAT state without dropping tracked guards.
        """
        raw_smt2 = solver.to_smt2()
        import re as _re
        declared = _re.findall(r"\(declare-fun\s+([^\s()]+)\s+\(\)\s+Bool\)", raw_smt2)
        tracking_asserts = [
            f"(assert {name})"
            for name in declared
            if name.startswith(("eBPF_", "AST_", "OSV_"))
        ]
        return raw_smt2 + "\n" + "\n".join(tracking_asserts) + "\n"
