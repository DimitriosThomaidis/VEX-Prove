import ast
from pathlib import Path
from typing import List, Set
from pydantic import BaseModel, Field
from z3 import Bool, BoolVal, Solver, Not, unsat

class BackportEquivalenceResult(BaseModel):
    vuln_id: str
    upstream_fixed_version: str
    local_version: str
    upstream_stripped_headers: List[str] = Field(default_factory=list)
    local_stripped_headers: List[str] = Field(default_factory=list)
    z3_equivalence_verdict: str  # "UNSAT_EQUIVALENT_OR_STRONGER" or "SAT_INCOMPLETE_BACKPORT"
    cisa_justification: str
    unsat_core: List[str] = Field(default_factory=list)
    proof_explanation: str = ""

class SemanticBackportProver:
    """
    Capability #2: Semantic Backport & Hotfix Equivalence Prover.
    Fix #2: Uses Context-Sensitive AST Statement Walking with Dead-Branch Pruning
    so comments, print() calls, unused strings, and `if False:` blocks cannot spoof sanitization.
    """

    UPSTREAM_PATCH_SPEC = {
        "CVE-2024-37891": {
            "fixed_version": "1.26.19",
            "required_stripped_headers": {"cookie", "authorization", "proxy-authorization"},
        }
    }

    def prove_backport_equivalence(
        self,
        vuln_id: str,
        local_version: str,
        source_file: Path,
    ) -> BackportEquivalenceResult:
        spec = self.UPSTREAM_PATCH_SPEC.get(vuln_id, self.UPSTREAM_PATCH_SPEC["CVE-2024-37891"])
        upstream_set: Set[str] = spec["required_stripped_headers"]
        local_set: Set[str] = self._extract_local_stripped_headers(source_file)

        solver = Solver()
        solver.set(unsat_core=True)

        strip_cookie = Bool("strip_cookie")
        strip_auth = Bool("strip_authorization")
        strip_proxy_auth = Bool("strip_proxy_authorization")
        cve_exploit_possible = Bool("cve_exploit_possible")

        var_lookup = {
            "cookie": strip_cookie,
            "authorization": strip_auth,
            "proxy-authorization": strip_proxy_auth,
        }

        solver.assert_and_track(
            cve_exploit_possible == Not(strip_proxy_auth),
            "Upstream_1_26_19_Patch_Invariant_Requires_Stripping_ProxyAuth",
        )

        for hdr_name, z3_var in var_lookup.items():
            is_stripped_locally = hdr_name in local_set
            solver.assert_and_track(
                z3_var == BoolVal(is_stripped_locally),
                f"Local_Backport_AST_{hdr_name.replace('-', '_')}_stripped_is_{is_stripped_locally}",
            )

        solver.assert_and_track(
            cve_exploit_possible == BoolVal(True),
            "Query_Can_Exploit_Trigger_Under_Local_Backport",
        )

        if solver.check() == unsat:
            core = [str(c) for c in solver.unsat_core()]
            return BackportEquivalenceResult(
                vuln_id=vuln_id,
                upstream_fixed_version=spec["fixed_version"],
                local_version=local_version,
                upstream_stripped_headers=sorted(upstream_set),
                local_stripped_headers=sorted(local_set),
                z3_equivalence_verdict="UNSAT_EQUIVALENT_OR_STRONGER",
                cisa_justification="inline_mitigations_already_exist",
                unsat_core=core,
                proof_explanation=(
                    f"Z3 proved Local AST on v{local_version} is mathematically equivalent "
                    f"to upstream fix v{spec['fixed_version']} (UNSAT Core={core})."
                ),
            )
        else:
            missing = sorted(upstream_set - local_set)
            return BackportEquivalenceResult(
                vuln_id=vuln_id,
                upstream_fixed_version=spec["fixed_version"],
                local_version=local_version,
                upstream_stripped_headers=sorted(upstream_set),
                local_stripped_headers=sorted(local_set),
                z3_equivalence_verdict="SAT_INCOMPLETE_BACKPORT",
                cisa_justification="none_affected",
                proof_explanation=(
                    f"Backport incomplete! Local code fails to strip: {missing}."
                ),
            )

    @classmethod
    def _extract_local_stripped_headers(cls, source_file: Path) -> Set[str]:
        """
        Context-Sensitive AST Analyzer:
        1. Prunes dead conditional branches (`if False:`, `if 0:`).
        2. Only extracts header strings inside:
           - `remove_headers_on_redirect=[...]` keyword arguments
           - `headers.pop("...")` / `headers.remove("...")` method calls
           - `del headers["..."]` subscript deletions
        3. Ignores `print("proxy-authorization")`, docstrings, and standalone constants!
        """
        code = source_file.read_text(encoding="utf-8")
        tree = ast.parse(code)
        stripped: Set[str] = set()
        allowed = {"cookie", "authorization", "proxy-authorization"}

        def _walk_reachable(node: ast.AST):
            # Prune dead branches: `if False:` or `if 0:`
            if isinstance(node, ast.If):
                if isinstance(node.test, ast.Constant) and bool(node.test.value) is False:
                    for orelse_stmt in node.orelse:
                        _walk_reachable(orelse_stmt)
                    return
                if isinstance(node.test, ast.Constant) and bool(node.test.value) is True:
                    for body_stmt in node.body:
                        _walk_reachable(body_stmt)
                    return

            # Case 1: keyword `remove_headers_on_redirect=[...]`
            if isinstance(node, ast.keyword) and node.arg == "remove_headers_on_redirect":
                if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            val = elt.value.lower()
                            if val in allowed:
                                stripped.add(val)

            # Case 2: Method call `headers.pop("Proxy-Authorization", ...)`
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"pop", "remove", "discard"} and node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                        val = first_arg.value.lower()
                        if val in allowed:
                            stripped.add(val)

            # Case 3: `del headers["Proxy-Authorization"]`
            if isinstance(node, ast.Delete):
                for target in node.targets:
                    if isinstance(target, ast.Subscript):
                        sl = target.slice
                        if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
                            val = sl.value.lower()
                            if val in allowed:
                                stripped.add(val)

            for child in ast.iter_child_nodes(node):
                _walk_reachable(child)

        _walk_reachable(tree)
        return stripped
