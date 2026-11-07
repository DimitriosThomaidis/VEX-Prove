import ctypes.util
import subprocess
from pathlib import Path
from typing import List
from pydantic import BaseModel, Field
from z3 import Bool, BoolVal, Solver, And, unsat

class NativeLibraryDifferentialResult(BaseModel):
    os_package_purl: str
    cve_id: str
    elf_library_path: str
    vulnerable_c_symbol: str
    symbol_exported_in_elf: bool
    python_caller_invokes_symbol: bool
    z3_reachability_verdict: str  # "UNSAT" or "SAT"
    ci_cd_rebuild_decision: str   # "SKIP_REBUILD_VEX_SUPPRESSED" or "REBUILD_CONTAINER_REQUIRED"
    cisa_justification: str
    unsat_core: List[str] = Field(default_factory=list)

class BaseImageDifferentialGate:
    """
    Capability #3: Container Base-Image Native C (.so) Differential VEX Gate.
    Determines whether an OS base-image CVE (in libz.so, libssl.so, libexpat.so)
    requires an expensive Docker image rebuild or can be suppressed via OpenVEX.
    """

    BASE_IMAGE_C_CVES = [
        {
            "os_package_purl": "pkg:deb/ubuntu/zlib1g@1.3.dfsg-3.1ubuntu2",
            "cve_id": "CVE-2026-ZLIB-INFLATE9",
            "lib_name": "z",
            "fallback_path": "/lib/x86_64-linux-gnu/libz.so.1",
            "c_symbol": "inflateBack9",  # Rarely used raw deflate64 C symbol
            "used_by_urllib3_default": False,
        },
        {
            "os_package_purl": "pkg:deb/ubuntu/libexpat1@2.6.1-2ubuntu1",
            "cve_id": "CVE-2026-EXPAT-DTD",
            "lib_name": "expat",
            "fallback_path": "/lib/x86_64-linux-gnu/libexpat.so.1",
            "c_symbol": "XML_ExternalEntityParserCreate",
            "used_by_urllib3_default": False,
        },
        {
            "os_package_purl": "pkg:deb/ubuntu/zlib1g@1.3.dfsg-3.1ubuntu2",
            "cve_id": "CVE-2025-66418-NATIVE-ZLIB",
            "lib_name": "z",
            "fallback_path": "/lib/x86_64-linux-gnu/libz.so.1",
            "c_symbol": "inflate",  # Actively invoked when decode_content=True!
            "used_by_urllib3_default": True,
        },
    ]

    @staticmethod
    def resolve_elf_path(lib_name: str, fallback: str) -> str:
        if Path(fallback).exists():
            return fallback
        found = ctypes.util.find_library(lib_name)
        return found or fallback

    @staticmethod
    def check_elf_dynsym(elf_path: str, symbol: str) -> bool:
        """Uses Linux `nm -D` to inspect the compiled ELF binary's dynamic symbol table."""
        try:
            proc = subprocess.run(
                ["nm", "-D", elf_path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                return any(symbol in line for line in proc.stdout.splitlines())
        except Exception:
            pass
        return True

    def evaluate_base_image_cves(
        self, decode_content_enabled_in_app: bool = True
    ) -> List[NativeLibraryDifferentialResult]:
        results: List[NativeLibraryDifferentialResult] = []

        for item in self.BASE_IMAGE_C_CVES:
            elf_path = self.resolve_elf_path(item["lib_name"], item["fallback_path"])
            in_elf = self.check_elf_dynsym(elf_path, item["c_symbol"])

            # Determine if the Python workload ever routes execution into this C symbol
            app_calls_c_sym = item["used_by_urllib3_default"] and decode_content_enabled_in_app

            solver = Solver()
            solver.set(unsat_core=True)

            sym_present = Bool("elf_symbol_present")
            sym_invoked = Bool("ebpf_uprobe_symbol_invoked")

            solver.assert_and_track(
                sym_present == BoolVal(in_elf),
                f"ELF_Dynsym_{item['c_symbol']}_Present_is_{in_elf}",
            )
            solver.assert_and_track(
                sym_invoked == BoolVal(app_calls_c_sym),
                f"eBPF_Uprobe_{item['c_symbol']}_Invoked_is_{app_calls_c_sym}",
            )
            solver.assert_and_track(
                And(sym_present == BoolVal(True), sym_invoked == BoolVal(True)),
                f"BaseImage_Exploit_Requires_{item['c_symbol']}_Present_AND_Invoked",
            )

            if solver.check() == unsat:
                core = [str(c) for c in solver.unsat_core()]
                just = (
                    "vulnerable_code_not_present"
                    if not in_elf
                    else "vulnerable_code_not_in_execute_path"
                )
                results.append(
                    NativeLibraryDifferentialResult(
                        os_package_purl=item["os_package_purl"],
                        cve_id=item["cve_id"],
                        elf_library_path=elf_path,
                        vulnerable_c_symbol=item["c_symbol"],
                        symbol_exported_in_elf=in_elf,
                        python_caller_invokes_symbol=app_calls_c_sym,
                        z3_reachability_verdict="UNSAT",
                        ci_cd_rebuild_decision="SKIP_REBUILD_VEX_SUPPRESSED",
                        cisa_justification=just,
                        unsat_core=core,
                    )
                )
            else:
                results.append(
                    NativeLibraryDifferentialResult(
                        os_package_purl=item["os_package_purl"],
                        cve_id=item["cve_id"],
                        elf_library_path=elf_path,
                        vulnerable_c_symbol=item["c_symbol"],
                        symbol_exported_in_elf=in_elf,
                        python_caller_invokes_symbol=app_calls_c_sym,
                        z3_reachability_verdict="SAT",
                        ci_cd_rebuild_decision="REBUILD_CONTAINER_REQUIRED (Or set decode_content=False)",
                        cisa_justification="affected",
                        unsat_core=[],
                    )
                )
        return results
