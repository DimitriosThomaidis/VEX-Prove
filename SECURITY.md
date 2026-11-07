# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Verification Architecture & Trust Boundaries

`VEX-Prove` enforces deterministic formal verification across all stages:
1. **Stage 1 Airlock:** LLM precondition synthesis (`qwen2.5-coder:7b` and `deepseek-r1:7b`) is untrusted until verified by Microsoft Z3 (`Check-SAT(Phi_A XOR Phi_B) == UNSAT`) and constrained to a strict symbol vocabulary.
2. **Stage 2 Hybrid Telemetry:** Static AST claims are cross-checked against live runtime execution (`SourceLens` dynamic `getattr()` contradiction detection) and Linux kernel eBPF `uprobes`.
3. **Stage 4 Proof-Carrying Bundles:** Every `"not_affected"` VEX statement is accompanied by a self-contained SMT-LIB2 mathematical proof (`z3_proof_certificate.smt2`) locked inside an `in-toto` v1 SHA-256 attestation (`output/vex-prove.intoto.v1.json`) and re-verified by `vex-prove verify-bundle`.

## Reporting a Vulnerability

Please report security issues via GitHub Security Advisories on the repository page.
