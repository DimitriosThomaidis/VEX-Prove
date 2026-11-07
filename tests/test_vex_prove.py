import json
from pathlib import Path
from vex_prove.ebpf_collector.tracer import EBPFConcolicCollector
from vex_prove.smt_verifier.prover import UnderConstrainedSMTProver, URLLIB3_CVE_PRECONDITIONS
from vex_prove.vex_emitter.emitter import MultiStandardVEXEmitter
from benchmarks.sample_targets.safe_client import make_internal_request
from benchmarks.sample_targets.vulnerable_client import make_unsafe_request

def test_safe_client_unsat_and_sat_partition(tmp_path: Path):
    collector = EBPFConcolicCollector()
    trace = collector.trace_callable_boundary(
        target_symbol="invoke_urllib3_retry",
        workload_fn=lambda: make_internal_request({"Proxy-Authorization": "Basic secret"}),
    )
    assert trace.invoked is True
    assert trace.captured_kwargs["redirect"] is False

    prover = UnderConstrainedSMTProver()
    cves = list(URLLIB3_CVE_PRECONDITIONS.keys())
    results = prover.verify_cve_batch(cves, Path("benchmarks/sample_targets/safe_client.py"), trace)

    unsat_cves = [r.vuln_id for r in results if r.z3_result == "UNSAT"]
    sat_cves = [r.vuln_id for r in results if r.z3_result == "SAT"]

    assert len(unsat_cves) == 6
    assert len(sat_cves) == 2
    assert "CVE-2024-37891" in unsat_cves
    assert "CVE-2025-66418" in sat_cves

    emitter = MultiStandardVEXEmitter()
    paths = emitter.emit_batch("pkg:pypi/urllib3@1.26.18", trace, results, tmp_path)
    openvex_data = json.loads(paths["openvex"].read_text(encoding="utf-8"))
    assert openvex_data["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert len(openvex_data["statements"]) == 8

def test_vulnerable_client_detects_redirect_exploit():
    collector = EBPFConcolicCollector()
    trace = collector.trace_callable_boundary(
        target_symbol="invoke_urllib3_retry",
        workload_fn=lambda: make_unsafe_request({"Proxy-Authorization": "Basic secret"}),
    )
    prover = UnderConstrainedSMTProver()
    results = prover.verify_cve_batch(
        ["CVE-2024-37891"], Path("benchmarks/sample_targets/vulnerable_client.py"), trace
    )
    assert results[0].z3_result == "SAT"
    assert results[0].status == "affected"
    assert results[0].counterexample_payload == {
        "redirect_enabled": "True",
        "has_proxy_auth_header": "True",
        "not_strips_proxy_auth": "True",
    }

def test_stage1_dual_model_z3_consensus_gate():
    from vex_prove.osv_slicer.llm_synthesizer import PatchPreconditionSynthesizer

    # Case 1: Proposer (qwen2.5-coder:7b) and Critic (deepseek-r1:1.5b) agree
    status_eq, flags_eq = PatchPreconditionSynthesizer.verify_z3_consensus(
        ["redirect_enabled", "has_proxy_auth_header"],
        ["has_proxy_auth_header", "redirect_enabled"],
    )
    assert status_eq == "Z3_DUAL_7B_UNSAT_EQUIVALENT"
    assert flags_eq == ["has_proxy_auth_header", "redirect_enabled"]

    # Case 2: Models diverge -> Z3 catches SAT on (Phi_A XOR Phi_B)
    status_div, flags_div = PatchPreconditionSynthesizer.verify_z3_consensus(
        ["redirect_enabled"],
        ["redirect_enabled", "streaming_enabled"],
    )
    assert status_div == "Z3_DIVERGENCE_DETECTED_CONSERVATIVE_UNION"
    assert "streaming_enabled" in flags_div

def test_capability2_semantic_backport_equivalence():
    from vex_prove.smt_verifier.backport_prover import SemanticBackportProver

    prover = SemanticBackportProver()
    # Safe client strips Proxy-Authorization -> Equivalent to 1.26.19
    res_safe = prover.prove_backport_equivalence(
        "CVE-2024-37891", "1.26.18", Path("benchmarks/sample_targets/safe_client.py")
    )
    assert res_safe.z3_equivalence_verdict == "UNSAT_EQUIVALENT_OR_STRONGER"

    # Vulnerable client omits Proxy-Authorization -> Incomplete backport
    res_vuln = prover.prove_backport_equivalence(
        "CVE-2024-37891", "1.26.18", Path("benchmarks/sample_targets/vulnerable_client.py")
    )
    assert res_vuln.z3_equivalence_verdict == "SAT_INCOMPLETE_BACKPORT"

def test_capability3_base_image_elf_differential_gate():
    from vex_prove.ebpf_collector.base_image_diff import BaseImageDifferentialGate

    gate = BaseImageDifferentialGate()
    results = gate.evaluate_base_image_cves(decode_content_enabled_in_app=True)
    skip_count = sum(1 for r in results if "SKIP_REBUILD" in r.ci_cd_rebuild_decision)
    rebuild_count = sum(1 for r in results if "REBUILD_CONTAINER_REQUIRED" in r.ci_cd_rebuild_decision)
    assert skip_count == 2
    assert rebuild_count == 1

def test_real_urllib3_and_zlib_kernel_tracer():
    from vex_prove.ebpf_collector.tracer import EBPFConcolicCollector

    collector = EBPFConcolicCollector()
    snap_active = collector.trace_real_kernel_zlib_execution(decode_content=True)
    snap_blocked = collector.trace_real_kernel_zlib_execution(decode_content=False)

    assert snap_active.captured_kwargs["decode_content"] is True
    assert snap_blocked.captured_kwargs["decode_content"] is False
    # When sudo bpftrace is active, active decompression triggers >=1 C-level inflate() calls in libz.so.1,
    # whereas decode_content=False triggers 0 C-level inflate() calls!
    if "LIVE_KERNEL_UPROBE_VERIFIED" in snap_active.ebpf_probe_status:
        assert snap_active.native_zlib_inflate_calls >= 1
        assert snap_blocked.native_zlib_inflate_calls == 0

def test_plugin_direction2_proof_carrying_bundle_verifier(tmp_path: Path):
    from vex_prove.vex_emitter.bundle_verifier import ProofCarryingBundleVerifier

    collector = EBPFConcolicCollector()
    trace = collector.trace_callable_boundary(
        target_symbol="invoke_urllib3_retry",
        workload_fn=lambda: make_internal_request({"Proxy-Authorization": "Basic secret"}),
    )
    prover = UnderConstrainedSMTProver()
    results = prover.verify_cve_batch(
        list(URLLIB3_CVE_PRECONDITIONS.keys()),
        Path("benchmarks/sample_targets/safe_client.py"),
        trace,
    )
    emitter = MultiStandardVEXEmitter()
    paths = emitter.emit_batch("pkg:pypi/urllib3@1.26.18", trace, results, tmp_path)

    verifier = ProofCarryingBundleVerifier()
    report = verifier.verify_bundle(paths["bundle"])
    assert report.k8s_admission_decision == "ADMIT_PROOF_CARRYING_VEX_VERIFIED"
    assert report.verified_unsat_proofs == 6
    assert report.verified_sat_warnings == 2
    assert len(report.forged_or_unproven_claims) == 0

def test_forged_vex_bundle_is_denied_by_k8s_verifier(tmp_path: Path):
    """
    Adversarial Tamper Test:
    Simulates a malicious actor editing `vex-prove.openvex.json` inside the bundle
    to claim CVE-2025-66418 is 'not_affected' while its Z3 proof is actually SAT.
    Proves that ProofCarryingBundleVerifier catches the lie and returns DENY!
    """
    import tarfile
    from vex_prove.vex_emitter.bundle_verifier import ProofCarryingBundleVerifier

    collector = EBPFConcolicCollector()
    trace = collector.trace_callable_boundary(
        target_symbol="invoke_urllib3_retry",
        workload_fn=lambda: make_internal_request({"Proxy-Authorization": "Basic secret"}),
    )
    prover = UnderConstrainedSMTProver()
    results = prover.verify_cve_batch(
        list(URLLIB3_CVE_PRECONDITIONS.keys()),
        Path("benchmarks/sample_targets/safe_client.py"),
        trace,
    )
    emitter = MultiStandardVEXEmitter()
    paths = emitter.emit_batch("pkg:pypi/urllib3@1.26.18", trace, results, tmp_path)

    # Tamper with vex-prove.openvex.json: flip CVE-2025-66418 from 'affected' to 'not_affected'
    openvex_doc = json.loads(paths["openvex"].read_text(encoding="utf-8"))
    for stmt in openvex_doc["statements"]:
        if stmt["vulnerability"]["name"] == "CVE-2025-66418":
            stmt["status"] = "not_affected"
            stmt["justification"] = "inline_mitigations_already_exist"
    paths["openvex"].write_text(json.dumps(openvex_doc, indent=2), encoding="utf-8")

    # Repackage tampered bundle
    tampered_bundle = tmp_path / "tampered_bundle.tar.gz"
    with tarfile.open(tampered_bundle, "w:gz") as tar:
        for key in ["openvex", "cyclonedx", "csaf"]:
            tar.add(paths[key], arcname=paths[key].name)
        smt2_file = tmp_path / "z3_proof_certificate.smt2"
        tar.add(smt2_file, arcname=smt2_file.name)

    verifier = ProofCarryingBundleVerifier()
    report = verifier.verify_bundle(tampered_bundle)
    assert report.k8s_admission_decision == "DENY_FORGED_OR_UNPROVEN_VEX"
    assert any("CVE-2025-66418" in claim for claim in report.forged_or_unproven_claims)

def test_multitheory_jinja2_cve_2024_22195():
    from vex_prove.smt_verifier.multitheory_bench import RealisticMultiTheoryBenchmark
    b = RealisticMultiTheoryBenchmark()
    safe = b._eval_jinja2_cve_2024_22195("T1", True, False, "not_affected", "inline_mitigations_already_exist")
    vuln = b._eval_jinja2_cve_2024_22195("T2", False, True, "affected", "exploitable")
    assert safe.z3_verdict == "UNSAT"
    assert vuln.z3_verdict == "SAT"

def test_multitheory_pillow_int_and_string_bounds_cve_2024_28219():
    from vex_prove.smt_verifier.multitheory_bench import RealisticMultiTheoryBenchmark
    b = RealisticMultiTheoryBenchmark()
    safe = b._eval_pillow_cve_2024_28219("P1", True, 512, 512, "sRGB", "not_affected", "inline_mitigations_already_exist")
    vuln = b._eval_pillow_cve_2024_28219("P2", True, 4096, 4096, "A" * 64, "affected", "exploitable")
    assert safe.z3_verdict == "UNSAT"
    assert safe.predicted_justification == "inline_mitigations_already_exist"
    assert vuln.z3_verdict == "SAT"

def test_sourcelens_dynamic_getattr_contradiction_detector():
    from vex_prove.smt_verifier.multitheory_bench import RealisticMultiTheoryBenchmark
    b = RealisticMultiTheoryBenchmark()
    # Static AST says SafeLoader, but runtime execution used UnsafeLoader!
    res = b._eval_pyyaml_cve_2020_14343("SL1", "SafeLoader", "UnsafeLoader", "affected", "exploitable")
    assert res.sourcelens_contradiction is True
    assert res.z3_verdict == "SAT"
    assert res.predicted_status == "affected"

def test_requests_tls_pinning_cve_2024_35195():
    from vex_prove.smt_verifier.multitheory_bench import RealisticMultiTheoryBenchmark
    b = RealisticMultiTheoryBenchmark()
    res = b._eval_requests_cve_2024_35195("R1", True, False, "not_affected", "vulnerable_code_cannot_be_controlled_by_adversary")
    assert res.z3_verdict == "UNSAT"

def test_setuptools_unreachable_build_dep_cve_2024_6345():
    from vex_prove.smt_verifier.multitheory_bench import RealisticMultiTheoryBenchmark
    b = RealisticMultiTheoryBenchmark()
    res = b._eval_setuptools_cve_2024_6345("S1", 0, "not_affected", "vulnerable_code_not_in_execute_path")
    assert res.z3_verdict == "UNSAT"

def test_counterfactual_remediation_prover_flips_all_sat_cves():
    from vex_prove.smt_verifier.prover import UnderConstrainedSMTProver, URLLIB3_CVE_PRECONDITIONS
    for cve_id, spec in URLLIB3_CVE_PRECONDITIONS.items():
        proof = UnderConstrainedSMTProver._prove_counterfactual_remediation(spec)
        assert proof.startswith("VERIFIED (SAT -> UNSAT"), f"Failed on {cve_id}"

def test_full_multitheory_benchmark_f1_and_justification_accuracy():
    from vex_prove.smt_verifier.multitheory_bench import RealisticMultiTheoryBenchmark
    summary = RealisticMultiTheoryBenchmark().run_full_benchmark()
    assert summary.total_cases == 8
    assert summary.status_accuracy_pct == 100.0
    assert summary.status_f1_score == 1.0
    assert summary.justification_accuracy_pct == 100.0
    assert summary.sourcelens_contradictions_caught == 1

def test_realworld_live_memory_and_multi_library_kernel_trace():
    from vex_prove.realworld_e2e import RealWorldEndToEndPipeline
    pipeline = RealWorldEndToEndPipeline()
    trace = pipeline.capture_live_memory_and_kernel_trace()

    # Proven from real Python objects in RAM (NOT hardcoded arguments!)
    assert trace.jinja2_autoescape_live is True
    assert trace.pyyaml_runtime_live_loader == "SafeLoader"
    assert trace.requests_tls_verify_live is True
    assert trace.urllib3_redirect_live is False
    assert trace.urllib3_strips_proxy_auth_live is True

    # If sudo bpftrace is active, verify real C library uprobe counters
    if "LIVE_KERNEL" in trace.ebpf_Attach_mode:
        assert trace.kernel_libz_deflate_hits >= 1
        assert trace.kernel_libz_inflate_hits == 0
        assert trace.kernel_libexpat_create_hits >= 1
        assert trace.kernel_libexpat_ext_entity_hits == 0

def test_realworld_sourcelens_getattr_reflection_caught_in_ram():
    from vex_prove.realworld_e2e import RealWorldEndToEndPipeline
    pipeline = RealWorldEndToEndPipeline()
    static_ldr, runtime_ldr, caught = pipeline.verify_live_sourcelens_contradiction()
    assert static_ldr == "SafeLoader"
    assert runtime_ldr == "FullLoader"
    assert caught is True

def test_realworld_end_to_end_trivy_multi_package_suppression(tmp_path: Path):
    from vex_prove.realworld_e2e import RealWorldEndToEndPipeline
    pipeline = RealWorldEndToEndPipeline()
    report = pipeline.run_live_trivy_and_z3_pipeline(tmp_path)

    # Trivy discovers >12 real CVEs across urllib3, jinja2, pyyaml, and requests
    assert report.trivy_total_cves_before >= 12
    # VEX-Prove suppresses all false positives and leaves only the 1 unmitigated chunk parser CVE
    assert report.trivy_suppressed_cves_count >= 11
    assert report.trivy_active_cves_after_vex < report.trivy_total_cves_before

def test_four_c_libraries_kernel_uprobes_libcrypto_and_libsqlite3():
    from vex_prove.realworld_e2e import RealWorldEndToEndPipeline
    pipeline = RealWorldEndToEndPipeline()
    safe_trace = pipeline.capture_live_memory_and_kernel_trace()
    if "LIVE_KERNEL" in safe_trace.ebpf_Attach_mode:
        assert safe_trace.kernel_libcrypto_evp_digest_hits >= 1
        assert safe_trace.kernel_libsqlite3_prepare_hits >= 1

def test_differential_kernel_uprobe_catches_zlib_inflate_in_vulnerable_service():
    from vex_prove.realworld_e2e import RealWorldEndToEndPipeline
    from benchmarks.realworld_app.vulnerable_service import execute_vulnerable_workload
    pipeline = RealWorldEndToEndPipeline()
    safe_trace = pipeline.capture_live_memory_and_kernel_trace()
    vuln_trace = pipeline.capture_service_trace(
        service_label="vulnerable_service",
        workload_fn=execute_vulnerable_workload,
        source_path=Path("benchmarks/realworld_app/vulnerable_service.py"),
        import_stmt="from benchmarks.realworld_app.vulnerable_service import execute_vulnerable_workload; execute_vulnerable_workload()",
    )
    assert safe_trace.kernel_libz_inflate_hits == 0
    assert vuln_trace.kernel_libz_inflate_hits >= 1
    assert vuln_trace.pyyaml_runtime_live_loader == "UnsafeLoader"
    assert vuln_trace.requests_tls_verify_live is False
    assert vuln_trace.urllib3_redirect_live is True

def test_z3_bitvector_32bit_cwe190_allocation_overflow_proof():
    from vex_prove.realworld_e2e import RealWorldEndToEndPipeline
    from benchmarks.realworld_app.vulnerable_service import execute_vulnerable_workload
    pipeline = RealWorldEndToEndPipeline()
    safe_trace = pipeline.capture_live_memory_and_kernel_trace()
    vuln_trace = pipeline.capture_service_trace(
        service_label="vulnerable_service",
        workload_fn=execute_vulnerable_workload,
        source_path=Path("benchmarks/realworld_app/vulnerable_service.py"),
        import_stmt="from benchmarks.realworld_app.vulnerable_service import execute_vulnerable_workload; execute_vulnerable_workload()",
    )
    bv_results = pipeline.verify_bitvector_c_invariants(safe_trace, vuln_trace)
    alloc_proof = bv_results[0]
    assert alloc_proof.safe_service_verdict.startswith("UNSAT")
    assert alloc_proof.vulnerable_service_verdict.startswith("SAT")
    assert "0x" in alloc_proof.exploit_witness_hex

def test_z3_bitvector_64bit_openssl_bitmask_proof():
    from vex_prove.realworld_e2e import RealWorldEndToEndPipeline
    from benchmarks.realworld_app.vulnerable_service import execute_vulnerable_workload
    pipeline = RealWorldEndToEndPipeline()
    safe_trace = pipeline.capture_live_memory_and_kernel_trace()
    vuln_trace = pipeline.capture_service_trace(
        service_label="vulnerable_service",
        workload_fn=execute_vulnerable_workload,
        source_path=Path("benchmarks/realworld_app/vulnerable_service.py"),
        import_stmt="from benchmarks.realworld_app.vulnerable_service import execute_vulnerable_workload; execute_vulnerable_workload()",
    )
    bv_results = pipeline.verify_bitvector_c_invariants(safe_trace, vuln_trace)
    ssl_proof = bv_results[1]
    assert ssl_proof.safe_service_verdict.startswith("UNSAT")
    assert ssl_proof.vulnerable_service_verdict.startswith("SAT")

def test_differential_trivy_vex_blocks_false_suppression_on_vulnerable_service(tmp_path: Path):
    from vex_prove.realworld_e2e import RealWorldEndToEndPipeline
    pipeline = RealWorldEndToEndPipeline()
    report = pipeline.run_live_trivy_and_z3_pipeline(tmp_path)
    # Safe service suppresses 15/16 CVEs (leaving 1 active)
    assert report.trivy_safe_service_active_after_vex == 1
    # Vulnerable service flips 10 CVEs to SAT, so Trivy keeps 11 active alerts!
    assert report.trivy_vuln_service_active_after_vex >= 10
    assert report.trivy_vuln_service_active_after_vex > report.trivy_safe_service_active_after_vex

def test_four_c_libraries_kernel_uprobes_libcrypto_and_libsqlite3():
    from vex_prove.realworld_e2e import RealWorldEndToEndPipeline
    pipeline = RealWorldEndToEndPipeline()
    safe_trace = pipeline.capture_live_memory_and_kernel_trace()
    if "LIVE_KERNEL" in safe_trace.ebpf_Attach_mode:
        assert safe_trace.kernel_libcrypto_evp_digest_hits >= 1
        assert safe_trace.kernel_libsqlite3_prepare_hits >= 1

def test_differential_kernel_uprobe_catches_zlib_inflate_in_vulnerable_service():
    from vex_prove.realworld_e2e import RealWorldEndToEndPipeline
    from benchmarks.realworld_app.vulnerable_service import execute_vulnerable_workload
    pipeline = RealWorldEndToEndPipeline()
    safe_trace = pipeline.capture_live_memory_and_kernel_trace()
    vuln_trace = pipeline.capture_service_trace(
        service_label="vulnerable_service",
        workload_fn=execute_vulnerable_workload,
        source_path=Path("benchmarks/realworld_app/vulnerable_service.py"),
        import_stmt="from benchmarks.realworld_app.vulnerable_service import execute_vulnerable_workload; execute_vulnerable_workload()",
    )
    assert safe_trace.kernel_libz_inflate_hits == 0
    assert vuln_trace.kernel_libz_inflate_hits >= 1
    assert vuln_trace.pyyaml_runtime_live_loader == "UnsafeLoader"
    assert vuln_trace.requests_tls_verify_live is False
    assert vuln_trace.urllib3_redirect_live is True

def test_z3_bitvector_32bit_cwe190_allocation_overflow_proof():
    from vex_prove.realworld_e2e import RealWorldEndToEndPipeline
    from benchmarks.realworld_app.vulnerable_service import execute_vulnerable_workload
    pipeline = RealWorldEndToEndPipeline()
    safe_trace = pipeline.capture_live_memory_and_kernel_trace()
    vuln_trace = pipeline.capture_service_trace(
        service_label="vulnerable_service",
        workload_fn=execute_vulnerable_workload,
        source_path=Path("benchmarks/realworld_app/vulnerable_service.py"),
        import_stmt="from benchmarks.realworld_app.vulnerable_service import execute_vulnerable_workload; execute_vulnerable_workload()",
    )
    bv_results = pipeline.verify_bitvector_c_invariants(safe_trace, vuln_trace)
    alloc_proof = bv_results[0]
    assert alloc_proof.safe_service_verdict.startswith("UNSAT")
    assert alloc_proof.vulnerable_service_verdict.startswith("SAT")
    assert "0x" in alloc_proof.exploit_witness_hex

def test_z3_bitvector_64bit_openssl_bitmask_proof():
    from vex_prove.realworld_e2e import RealWorldEndToEndPipeline
    from benchmarks.realworld_app.vulnerable_service import execute_vulnerable_workload
    pipeline = RealWorldEndToEndPipeline()
    safe_trace = pipeline.capture_live_memory_and_kernel_trace()
    vuln_trace = pipeline.capture_service_trace(
        service_label="vulnerable_service",
        workload_fn=execute_vulnerable_workload,
        source_path=Path("benchmarks/realworld_app/vulnerable_service.py"),
        import_stmt="from benchmarks.realworld_app.vulnerable_service import execute_vulnerable_workload; execute_vulnerable_workload()",
    )
    bv_results = pipeline.verify_bitvector_c_invariants(safe_trace, vuln_trace)
    ssl_proof = bv_results[1]
    assert ssl_proof.safe_service_verdict.startswith("UNSAT")
    assert ssl_proof.vulnerable_service_verdict.startswith("SAT")

def test_differential_trivy_vex_blocks_false_suppression_on_vulnerable_service(tmp_path: Path):
    from vex_prove.realworld_e2e import RealWorldEndToEndPipeline
    pipeline = RealWorldEndToEndPipeline()
    report = pipeline.run_live_trivy_and_z3_pipeline(tmp_path)
    # Safe service suppresses 15/16 CVEs (leaving 1 active)
    assert report.trivy_safe_service_active_after_vex == 1
    # Vulnerable service flips 10 CVEs to SAT, so Trivy keeps 11 active alerts!
    assert report.trivy_vuln_service_active_after_vex >= 10
    assert report.trivy_vuln_service_active_after_vex > report.trivy_safe_service_active_after_vex

def test_kernel_cpu_register_bridge_safe_c_strings_and_lengths():
    from vex_prove.ebpf_collector.register_bridge import KernelRegisterZ3Bridge
    bridge = KernelRegisterZ3Bridge()
    cap = bridge.trace_kernel_cpu_registers_and_solve(safe_mode=True)
    assert "<status>SAFE_OK</status>" in cap.expat_c_strings_rsi_arg1[0]
    assert cap.expat_c_lengths_rdx_arg2[0] == 24
    assert "INSERT INTO t VALUES (?, ?)" in cap.sqlite_c_queries_rsi_arg1[-1]
    assert cap.z3_expat_xxe_verdict == "UNSAT"
    assert cap.z3_sqlite_sqli_verdict == "UNSAT"

def test_kernel_cpu_register_bridge_catches_xxe_and_sqli_in_registers():
    from vex_prove.ebpf_collector.register_bridge import KernelRegisterZ3Bridge
    bridge = KernelRegisterZ3Bridge()
    cap = bridge.trace_kernel_cpu_registers_and_solve(safe_mode=False)
    assert "<!DOCTYPE" in cap.expat_c_strings_rsi_arg1[0]
    assert "OR '1'='1'" in cap.sqlite_c_queries_rsi_arg1[-1]
    assert cap.z3_expat_xxe_verdict == "SAT"
    assert cap.z3_sqlite_sqli_verdict == "SAT"

def test_multihop_call_graph_slicer_all_routes_safe():
    from vex_prove.ebpf_collector.register_bridge import KernelRegisterZ3Bridge
    bridge = KernelRegisterZ3Bridge()
    rep = bridge.analyze_multihop_call_graph(include_unprotected_legacy_route=False)
    assert rep.total_routes_analyzed == 2
    assert rep.vulnerable_routes_sat == 0
    assert rep.overall_package_verdict.startswith("UNSAT")

def test_multihop_call_graph_slicer_catches_single_unprotected_route():
    from vex_prove.ebpf_collector.register_bridge import KernelRegisterZ3Bridge
    bridge = KernelRegisterZ3Bridge()
    rep = bridge.analyze_multihop_call_graph(include_unprotected_legacy_route=True)
    assert rep.total_routes_analyzed == 3
    assert rep.safe_routes_unsat == 2
    assert rep.vulnerable_routes_sat == 1
    assert rep.overall_package_verdict.startswith("SAT")
    assert "legacy/webhook-forward" in rep.offending_routes[0]

def test_intoto_v1_proof_carrying_attestation_emission_and_verification(tmp_path: Path):
    from vex_prove.ebpf_collector.register_bridge import KernelRegisterZ3Bridge
    bridge = KernelRegisterZ3Bridge()
    cap = bridge.trace_kernel_cpu_registers_and_solve(safe_mode=True)
    rep = bridge.emit_and_verify_intoto_v1_attestation(tmp_path, cap)
    assert rep.statement_type == "https://in-toto.io/Statement/v1"
    assert rep.predicate_type == "https://openvex.dev/ns/v0.2.0"
    assert rep.sbom_sha256_verified is True
    assert rep.kernel_register_sha256_verified is True
    assert rep.z3_smt2_sha256_verified is True
    assert rep.attestation_status == "VERIFIED_SLSA_INTOTO_V1"

def test_fix1_real_ast_multihop_route_file_slicing():
    from vex_prove.ebpf_collector.register_bridge import KernelRegisterZ3Bridge
    bridge = KernelRegisterZ3Bridge()
    rep = bridge.analyze_multihop_call_graph(
        include_unprotected_legacy_route=True,
        route_source_file=Path("benchmarks/realworld_app/multihop_routes.py"),
    )
    assert rep.total_routes_analyzed == 3
    # Verify real function names from multihop_routes.py were extracted via ast.parse()
    all_hops = [h for sl in rep.route_slices for h in sl.call_chain_hops]
    assert "strict_sanitizer_middleware" in all_hops
    assert "legacy_passthrough_middleware" in all_hops
    assert "webhook_forwarder_service" in all_hops

def test_fix2_ast_analyzer_rejects_dead_code_and_print_spoofing(tmp_path: Path):
    """
    Adversarial AST Spoof Test:
    Creates a vulnerable Python file that tries to trick naive `ast.walk()` using:
    1. A print("proxy-authorization") statement
    2. An unused variable `fake = "proxy-authorization"`
    3. A dead branch `if False: headers.pop("Proxy-Authorization")`
    Proves that our upgraded Context-Sensitive AST Analyzer rejects all 3 spoofs!
    """
    from vex_prove.smt_verifier.backport_prover import SemanticBackportProver
    from vex_prove.smt_verifier.prover import UnderConstrainedSMTProver

    spoofed_file = tmp_path / "spoofed_client.py"
    spoofed_file.write_text(
        '"""Docstring mentioning proxy-authorization"""\n'
        'def make_spoofed_request(headers: dict):\n'
        '    fake_unused = "proxy-authorization"\n'
        '    print("proxy-authorization")\n'
        '    if False:\n'
        '        headers.pop("Proxy-Authorization", None)\n'
        '    return headers\n',
        encoding="utf-8",
    )

    bp = SemanticBackportProver()
    res = bp.prove_backport_equivalence("CVE-2024-37891", "1.26.18", spoofed_file)
    assert res.local_stripped_headers == []
    assert res.z3_equivalence_verdict == "SAT_INCOMPLETE_BACKPORT"

    guards = UnderConstrainedSMTProver._extract_caller_sanitizers(spoofed_file)
    assert guards["blocks_proxy_auth_header"] is False

def test_fix3_stage1_to_stage3_dynamic_precondition_wiring():
    from vex_prove.osv_slicer.llm_synthesizer import PatchPreconditionSynthesizer
    from vex_prove.smt_verifier.prover import UnderConstrainedSMTProver
    from vex_prove.ebpf_collector.tracer import EBPFConcolicCollector

    synth = PatchPreconditionSynthesizer()
    precond = synth.synthesize_from_diff(
        vuln_id="CVE-2024-37891",
        default_symbol="Retry",
        patch_diff="- DEFAULT_REMOVE_HEADERS = ['Cookie', 'Authorization']\n+ DEFAULT_REMOVE_HEADERS = ['Cookie', 'Authorization', 'Proxy-Authorization']\nredirect",
    )
    collector = EBPFConcolicCollector()
    trace = collector.trace_callable_boundary(
        target_symbol="invoke_urllib3_retry",
        workload_fn=lambda: make_internal_request({"Proxy-Authorization": "Basic secret"}),
    )
    prover = UnderConstrainedSMTProver()
    results = prover.verify_cve_batch(
        ["CVE-2024-37891"],
        Path("benchmarks/sample_targets/safe_client.py"),
        trace,
        stage1_synthesized={"CVE-2024-37891": precond},
    )
    assert len(results) == 1
    assert results[0].z3_result == "UNSAT"

def test_fix4_userspace_register_capture_hooks_real_sqlite_and_expat():
    from vex_prove.ebpf_collector.register_bridge import KernelRegisterZ3Bridge
    xml_s, xml_l, sql_s = KernelRegisterZ3Bridge._capture_userspace_c_boundary_args(
        "<status>LIVE_TEST</status>", "INSERT INTO t VALUES (?, ?)", safe_mode=True
    )
    assert xml_s == ["<status>LIVE_TEST</status>"]
    assert xml_l == [26]
    assert any("INSERT INTO t" in q for q in sql_s)

def test_fix4_userspace_c_call_profiler_counts_real_c_extensions():
    import sys
    from benchmarks.realworld_app.safe_service import execute_production_workload
    from benchmarks.realworld_app.vulnerable_service import execute_vulnerable_workload

    def _count_zlib_decompress(fn):
        decompress_hits = 0
        def prof(frame, event, arg):
            nonlocal decompress_hits
            if event == "c_call" and getattr(arg, "__name__", "") == "decompress":
                decompress_hits += 1
        old = sys.getprofile()
        sys.setprofile(prof)
        try:
            fn()
        finally:
            sys.setprofile(old)
        return decompress_hits

    assert _count_zlib_decompress(execute_production_workload) == 0
    assert _count_zlib_decompress(execute_vulnerable_workload) == 1

def test_innovation_a_z3_unsat_core_to_tetragon_ebpf_policy_compiler(tmp_path: Path):
    from vex_prove.vex_emitter.tetragon_and_cbom import SelfEnforcingVEXAndCBOMEngine
    engine = SelfEnforcingVEXAndCBOMEngine()
    res = engine.compile_z3_unsat_cores_to_tetragon_policy(tmp_path)
    assert res.z3_soundness_verified is True
    assert "inflateBack9" in res.blocked_c_symbols_sigkill
    assert "XML_ExternalEntityParserCreate" in res.blocked_c_symbols_sigkill
    yaml_text = Path(res.yaml_path).read_text(encoding="utf-8")
    assert "kind: TracingPolicy" in yaml_text
    assert "action: Sigkill" in yaml_text

def test_innovation_b_cyclonedx_v16_cbom_proves_md5_non_security_is_unsat(tmp_path: Path):
    from vex_prove.vex_emitter.tetragon_and_cbom import SelfEnforcingVEXAndCBOMEngine
    engine = SelfEnforcingVEXAndCBOMEngine()
    rep = engine.verify_and_emit_cyclonedx_cbom(tmp_path)
    md5_row = [r for r in rep.rows if "MD5" in r.asset_name][0]
    assert md5_row.used_for_security_live is False
    assert md5_row.z3_crypto_verdict.startswith("UNSAT")
    assert "Live_RAM_usedforsecurity_is_False" in md5_row.z3_proof_or_witness

def test_innovation_b_cyclonedx_v16_cbom_catches_quantum_vulnerable_rsa1024(tmp_path: Path):
    from vex_prove.vex_emitter.tetragon_and_cbom import SelfEnforcingVEXAndCBOMEngine
    engine = SelfEnforcingVEXAndCBOMEngine()
    rep = engine.verify_and_emit_cyclonedx_cbom(tmp_path)
    rsa_row = [r for r in rep.rows if "RSA-1024" in r.asset_name][0]
    assert rsa_row.z3_crypto_verdict.startswith("SAT")
    assert "quantum_level: 0" in rsa_row.z3_proof_or_witness

def test_innovation_b_cyclonedx_v16_cbom_validates_nist_fips203_ml_kem_768(tmp_path: Path):
    from vex_prove.vex_emitter.tetragon_and_cbom import SelfEnforcingVEXAndCBOMEngine
    engine = SelfEnforcingVEXAndCBOMEngine()
    rep = engine.verify_and_emit_cyclonedx_cbom(tmp_path)
    pqc_row = [r for r in rep.rows if "ML-KEM-768" in r.asset_name][0]
    assert pqc_row.nist_quantum_security_level == 3
    assert pqc_row.z3_crypto_verdict.startswith("UNSAT")

def test_pickle_vm_bytecode_disassembler_proves_safe_state_dict_unsat(tmp_path: Path):
    from vex_prove.vex_emitter.aibom_and_autopatch import AIBOMAndAutoPatchEngine
    engine = AIBOMAndAutoPatchEngine()
    rep = engine.run_aibom_verification_suite(tmp_path)
    safe_pickle = rep.pickle_audits[0]
    assert safe_pickle.z3_pickle_verdict.startswith("UNSAT")
    assert len(safe_pickle.dangerous_opcodes_found) == 0
    assert safe_pickle.total_opcodes_inspected >= 5

def test_pickle_vm_bytecode_disassembler_catches_reduce_rce_opcode(tmp_path: Path):
    from vex_prove.vex_emitter.aibom_and_autopatch import AIBOMAndAutoPatchEngine
    engine = AIBOMAndAutoPatchEngine()
    rep = engine.run_aibom_verification_suite(tmp_path)
    vuln_pickle = rep.pickle_audits[1]
    assert vuln_pickle.z3_pickle_verdict.startswith("SAT")
    assert any("REDUCE" in op or "GLOBAL" in op for op in vuln_pickle.dangerous_opcodes_found)
    assert any("eval" in t for t in vuln_pickle.dangerous_module_targets)

def test_mcp_server_cve_2026_0755_z3_guard_safe_vs_exploitable(tmp_path: Path):
    from vex_prove.vex_emitter.aibom_and_autopatch import AIBOMAndAutoPatchEngine
    engine = AIBOMAndAutoPatchEngine()
    rep = engine.run_aibom_verification_suite(tmp_path)
    assert rep.mcp_audits[0].z3_mcp_verdict.startswith("UNSAT")
    assert rep.mcp_audits[1].z3_mcp_verdict.startswith("SAT")

def test_cyclonedx_v16_aibom_file_emission_and_eu_ai_act_metadata(tmp_path: Path):
    from vex_prove.vex_emitter.aibom_and_autopatch import AIBOMAndAutoPatchEngine
    engine = AIBOMAndAutoPatchEngine()
    rep = engine.run_aibom_verification_suite(tmp_path)
    aibom_doc = json.loads(Path(rep.aibom_path).read_text(encoding="utf-8"))
    assert aibom_doc["bomFormat"] == "CycloneDX"
    assert aibom_doc["specVersion"] == "1.6"
    assert aibom_doc["components"][0]["type"] == "machine-learning-model"

def test_closed_loop_z3_autopatcher_flips_vulnerable_client_sat_to_unsat(tmp_path: Path):
    from vex_prove.vex_emitter.aibom_and_autopatch import AIBOMAndAutoPatchEngine
    engine = AIBOMAndAutoPatchEngine()
    rep = engine.synthesize_sarif_and_verified_autopatch(
        Path("benchmarks/sample_targets/vulnerable_client.py"), tmp_path
    )
    assert rep.verdict_before_patch == "SAT_INCOMPLETE_BACKPORT"
    assert rep.verdict_after_patch == "UNSAT_EQUIVALENT_OR_STRONGER"
    assert rep.z3_patch_soundness_verified is True
    assert "+        redirect=False," in rep.unified_diff_preview

def test_github_sarif_v210_report_emission_and_line_region(tmp_path: Path):
    from vex_prove.vex_emitter.aibom_and_autopatch import AIBOMAndAutoPatchEngine
    engine = AIBOMAndAutoPatchEngine()
    rep = engine.synthesize_sarif_and_verified_autopatch(
        Path("benchmarks/sample_targets/vulnerable_client.py"), tmp_path
    )
    sarif_doc = json.loads(Path(rep.sarif_file_path).read_text(encoding="utf-8"))
    assert sarif_doc["version"] == "2.1.0"
    loc = sarif_doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "vulnerable_client.py" in loc["artifactLocation"]["uri"]
    assert loc["region"]["startLine"] >= 1

def test_universal_repo_scanner_on_external_unseen_safe_microservice(tmp_path: Path):
    """
    Creates a brand-new, unseen Python microservice repository in `tmp_path`
    and verifies that `UniversalRepoScanner` crawls its AST, runs kernel eBPF + Trivy,
    and suppresses 15/16 CVEs automatically!
    """
    from vex_prove.repo_scanner import UniversalRepoScanner

    ext_repo = tmp_path / "external_fintech_service"
    ext_repo.mkdir(parents=True)
    (ext_repo / "requirements.txt").write_text(
        "urllib3==1.26.18\njinja2==3.1.3\npyyaml==5.3.1\nrequests==2.31.0\n",
        encoding="utf-8",
    )
    (ext_repo / "service_main.py").write_text(
        "import zlib, jinja2, yaml, requests, urllib3\n"
        "def run_service():\n"
        "    env = jinja2.Environment(autoescape=True)\n"
        "    for k in {'id': '1'}:\n"
        "        if any(c.isspace() for c in k): raise ValueError('bad')\n"
        "    cfg = yaml.load('a: 1', Loader=yaml.SafeLoader)\n"
        "    s = requests.Session()\n"
        "    s.verify = True\n"
        "    r = urllib3.util.retry.Retry(redirect=False, remove_headers_on_redirect=['Proxy-Authorization'])\n"
        "    return zlib.compress(b'payload')\n",
        encoding="utf-8",
    )

    scanner = UniversalRepoScanner()
    out_dir = tmp_path / "vex_out"
    rep = scanner.scan_repository(ext_repo, out_dir)

    assert rep.ast_profile.python_files_scanned == 1
    assert rep.ast_profile.enforces_yaml_safeloader is True
    assert rep.ast_profile.disables_urllib3_redirects is True
    assert rep.trivy_cves_before == 16
    assert rep.trivy_cves_after_vex == 1
    assert rep.trivy_cves_suppressed == 15

def test_universal_repo_scanner_detects_unused_phantom_dependencies(tmp_path: Path):
    """
    Proves that if a repository lists `pyyaml==5.3.1` in requirements.txt
    but NEVER imports `yaml` in any `.py` file, UniversalRepoScanner automatically
    proves `AST_Repo_Imports_pyyaml_is_False` (UNSAT -> vulnerable_code_not_in_execute_path)!
    """
    from vex_prove.repo_scanner import UniversalRepoScanner

    ext_repo = tmp_path / "phantom_dep_service"
    ext_repo.mkdir(parents=True)
    (ext_repo / "requirements.txt").write_text("pyyaml==5.3.1\n", encoding="utf-8")
    (ext_repo / "main.py").write_text("def run_service():\n    return 42\n", encoding="utf-8")

    scanner = UniversalRepoScanner()
    rep = scanner.scan_repository(ext_repo, tmp_path / "out")
    assert rep.trivy_cves_before >= 1
    assert rep.trivy_cves_after_vex == 0
    assert "AST_Repo_Imports_pyyaml_is_False" in rep.triage_items[0].proof_or_witness

def test_universal_repo_scanner_flags_exploitable_external_repo(tmp_path: Path):
    from vex_prove.repo_scanner import UniversalRepoScanner

    vuln_repo = tmp_path / "unsafe_external_repo"
    vuln_repo.mkdir(parents=True)
    (vuln_repo / "requirements.txt").write_text("pyyaml==5.3.1\nrequests==2.31.0\n", encoding="utf-8")
    (vuln_repo / "bad_app.py").write_text(
        "import yaml, requests\n"
        "def run_service():\n"
        "    s = requests.Session()\n"
        "    s.verify = False\n"
        "    return yaml.load('x: 1', Loader=yaml.UnsafeLoader)\n",
        encoding="utf-8",
    )

    scanner = UniversalRepoScanner()
    rep = scanner.scan_repository(vuln_repo, tmp_path / "out_vuln")
    # Both CVE-2020-14343 (PyYAML UnsafeLoader) and CVE-2024-35195 (Requests verify=False) must stay SAT!
    sat_cves = {item.cve_id for item in rep.triage_items if item.z3_verdict == "SAT"}
    assert "CVE-2020-14343" in sat_cves
    assert "CVE-2024-35195" in sat_cves
    assert rep.trivy_cves_after_vex >= 2

def test_universal_repo_scanner_excludes_venv_and_pycache_dirs(tmp_path: Path):
    from vex_prove.repo_scanner import UniversalRepoScanner

    repo = tmp_path / "clean_repo"
    (repo / ".venv").mkdir(parents=True)
    (repo / ".venv" / "ignored.py").write_text("import yaml\nyaml.load('a', Loader=yaml.UnsafeLoader)\n", encoding="utf-8")
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("import yaml\nyaml.load('a', Loader=yaml.SafeLoader)\n", encoding="utf-8")

    scanner = UniversalRepoScanner()
    prof = scanner.analyze_repository_ast(repo)
    assert prof.python_files_scanned == 1
    assert prof.enforces_yaml_safeloader is True

def test_monorepo_entrypoint_transitive_slice_eliminates_sibling_contamination(tmp_path: Path):
    """
    Proves that in a multi-service monorepo (`benchmarks/realworld_app`) containing BOTH
    `safe_service.py` and `vulnerable_service.py`:
    - Scanning with `--entrypoint safe_service.py` prunes `vulnerable_service.py` (3 files pruned)
      and suppresses 15/16 CVEs (93.75% reduction)!
    - Scanning with `--entrypoint vulnerable_service.py` prunes `safe_service.py`
      and keeps 11/16 CVEs active (SAT)!
    """
    from vex_prove.repo_scanner import UniversalRepoScanner

    scanner = UniversalRepoScanner()
    rep_safe = scanner.scan_repository(
        Path("benchmarks/realworld_app"),
        tmp_path / "out_safe",
        entrypoint_script=Path("benchmarks/realworld_app/safe_service.py"),
    )
    assert rep_safe.ast_profile.python_files_scanned == 1
    assert rep_safe.ast_profile.pruned_unreachable_files >= 3
    assert rep_safe.trivy_cves_before == 16
    assert rep_safe.trivy_cves_after_vex == 1
    assert rep_safe.trivy_cves_suppressed == 15

    rep_vuln = scanner.scan_repository(
        Path("benchmarks/realworld_app"),
        tmp_path / "out_vuln",
        entrypoint_script=Path("benchmarks/realworld_app/vulnerable_service.py"),
    )
    assert rep_vuln.ast_profile.python_files_scanned == 1
    assert rep_vuln.trivy_cves_after_vex >= 10

def test_symbolic_12factor_env_var_contract_synthesis_safe_defaults(tmp_path: Path):
    """
    Creates a 12-Factor microservice that configures PyYAML, Requests TLS, and urllib3
    via `os.getenv(...)` with safe defaults, and proves that `UniversalRepoScanner`
    synthesizes the Z3 `.env.vex-contract` and proves UNSAT!
    """
    from vex_prove.repo_scanner import UniversalRepoScanner

    env_repo = tmp_path / "twelve_factor_app"
    env_repo.mkdir(parents=True)
    (env_repo / "requirements.txt").write_text("pyyaml==5.3.1\nrequests==2.31.0\n", encoding="utf-8")
    (env_repo / "app.py").write_text(
        "import os, yaml, requests\n"
        "def run_service():\n"
        "    ldr = os.getenv('APP_YAML_LOADER', 'SafeLoader')\n"
        "    tls = os.environ.get('APP_STRICT_TLS', 'true')\n"
        "    redir = os.getenv('APP_ALLOW_REDIRECTS', 'false')\n"
        "    return ldr, tls, redir\n",
        encoding="utf-8",
    )

    scanner = UniversalRepoScanner()
    rep = scanner.scan_repository(env_repo, tmp_path / "out_env")
    assert len(rep.ast_profile.symbolic_env_contracts) == 3
    assert rep.ast_profile.enforces_yaml_safeloader is True
    assert rep.ast_profile.enforces_requests_tls_verify is True
    assert rep.ast_profile.disables_urllib3_redirects is True
    assert rep.trivy_cves_after_vex == 0
    contract_text = Path(rep.emitted_env_contract).read_text(encoding="utf-8")
    assert "APP_YAML_LOADER=SafeLoader" in contract_text
    assert "APP_STRICT_TLS=true" in contract_text

def test_symbolic_12factor_env_var_catches_unsafe_default(tmp_path: Path):
    from vex_prove.repo_scanner import UniversalRepoScanner

    bad_env_repo = tmp_path / "bad_twelve_factor_app"
    bad_env_repo.mkdir(parents=True)
    (bad_env_repo / "requirements.txt").write_text("pyyaml==5.3.1\n", encoding="utf-8")
    (bad_env_repo / "app.py").write_text(
        "import os, yaml\n"
        "def run_service():\n"
        "    ldr = os.getenv('APP_YAML_LOADER', 'UnsafeLoader')\n"
        "    return ldr\n",
        encoding="utf-8",
    )

    scanner = UniversalRepoScanner()
    rep = scanner.scan_repository(bad_env_repo, tmp_path / "out_bad_env")
    assert rep.ast_profile.enforces_yaml_safeloader is False
    assert rep.trivy_cves_after_vex >= 1

def test_universal_repo_sarif_pinpoints_exact_file_and_call_line(tmp_path: Path):
    """
    Verifies that `universal_repo.sarif.json` records the exact `.py` file path
    (`benchmarks/realworld_app/safe_service.py`) and exact AST call-site line number (> 40)
    where `urllib3.util.retry.Retry(...)` is invoked, rather than directory line 1!
    """
    from vex_prove.repo_scanner import UniversalRepoScanner

    scanner = UniversalRepoScanner()
    rep = scanner.scan_repository(
        Path("benchmarks/realworld_app"),
        tmp_path / "out_sarif",
        entrypoint_script=Path("benchmarks/realworld_app/safe_service.py"),
    )
    sarif_data = json.loads(Path(rep.emitted_sarif).read_text(encoding="utf-8"))
    phys_loc = sarif_data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert phys_loc["artifactLocation"]["uri"].endswith("safe_service.py")
    assert phys_loc["region"]["startLine"] > 40

def test_repo_scanner_userspace_c_call_profiler_counts_without_sudo(monkeypatch):
    """
    Simulates an unprivileged CI container where `sudo -n bpftrace` returns returncode=1,
    and proves that `UniversalRepoScanner.trace_repository_execution` automatically
    runs the CPython `c_call` profiler and records non-zero C library hits!
    """
    import subprocess as _sp
    from vex_prove.repo_scanner import UniversalRepoScanner

    orig_run = _sp.run
    def _mock_no_sudo(cmd, *args, **kwargs):
        if isinstance(cmd, list) and cmd and cmd[0] == "sudo":
            class _FailedProc:
                returncode = 1
                stdout = ""
                stderr = "sudo: a password is required"
            return _FailedProc()
        return orig_run(cmd, *args, **kwargs)

    monkeypatch.setattr(_sp, "run", _mock_no_sudo)
    scanner = UniversalRepoScanner()
    trace_safe = scanner.trace_repository_execution(
        Path("benchmarks/realworld_app"),
        entrypoint_script=Path("benchmarks/realworld_app/safe_service.py"),
    )
    assert trace_safe.execution_mode == "CPYTHON_C_CALL_PROFILER"
    assert trace_safe.kernel_libz_deflate_hits >= 1
    assert trace_safe.kernel_libz_inflate_hits == 0
    assert trace_safe.kernel_libexpat_create_hits >= 1
    assert trace_safe.kernel_libcrypto_evp_hits >= 1
    assert trace_safe.kernel_libsqlite3_prepare_hits >= 1

    trace_vuln = scanner.trace_repository_execution(
        Path("benchmarks/realworld_app"),
        entrypoint_script=Path("benchmarks/realworld_app/vulnerable_service.py"),
    )
    assert trace_vuln.execution_mode == "CPYTHON_C_CALL_PROFILER"
    assert trace_vuln.kernel_libz_inflate_hits >= 1
