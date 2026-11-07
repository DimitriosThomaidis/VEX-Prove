import ast
import re
from pathlib import Path
from typing import List, Optional
import httpx
from pydantic import BaseModel, Field

class VulnerabilityIntel(BaseModel):
    vuln_id: str
    summary: str = ""
    package_name: str = ""
    ecosystem: str = ""
    fix_commit_url: Optional[str] = None
    vulnerable_symbols: List[str] = Field(default_factory=list)
    patch_diff_excerpt: Optional[str] = None

class OSVSlicer:
    """Queries OSV.dev API and slices upstream patch diffs for target symbols."""

    OSV_API_URL = "https://api.osv.dev/v1/vulns"

    def fetch_vuln_intel(self, vuln_id: str) -> VulnerabilityIntel:
        url = f"{self.OSV_API_URL}/{vuln_id}"
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()

        summary = data.get("summary", data.get("details", "")[:160])
        pkg_name, ecosystem = "", ""
        symbols: List[str] = []

        for affected in data.get("affected", []):
            pkg = affected.get("package", {})
            if not pkg_name:
                pkg_name = pkg.get("name", "")
                ecosystem = pkg.get("ecosystem", "")
            eco_spec = affected.get("ecosystem_specific", {})
            for imp in eco_spec.get("imports", []):
                symbols.extend(imp.get("symbols", []))

        fix_url = None
        for ref in data.get("references", []):
            ref_url = ref.get("url", "")
            if "github.com" in ref_url and "/commit/" in ref_url:
                fix_url = ref_url
                break

        diff_excerpt = None
        if fix_url:
            diff_excerpt, diff_symbols = self._fetch_github_commit_diff(fix_url)
            for s in diff_symbols:
                if s not in symbols:
                    symbols.append(s)

        return VulnerabilityIntel(
            vuln_id=vuln_id,
            summary=summary,
            package_name=pkg_name,
            ecosystem=ecosystem,
            fix_commit_url=fix_url,
            vulnerable_symbols=symbols,
            patch_diff_excerpt=diff_excerpt,
        )

    def _fetch_github_commit_diff(self, commit_url: str) -> tuple[Optional[str], List[str]]:
        diff_url = commit_url if commit_url.endswith(".diff") else f"{commit_url}.diff"
        symbols: List[str] = []
        try:
            with httpx.Client(timeout=15.0, follow_redirects=True) as client:
                resp = client.get(diff_url)
                if resp.status_code != 200:
                    return None, symbols
                diff_text = resp.text

            for match in re.finditer(r"@@.*@@\s*(?:def|class|static|int|void)\s+([a-zA-Z0-9_]+)", diff_text):
                sym = match.group(1)
                if sym not in symbols:
                    symbols.append(sym)

            return diff_text[:2000], symbols
        except Exception:
            return None, symbols

    @staticmethod
    def check_static_ast_call(source_file: Path, target_symbols: List[str]) -> List[str]:
        tree = ast.parse(source_file.read_text(encoding="utf-8"))
        matched: List[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in target_symbols:
                matched.append(node.id)
            elif isinstance(node, ast.Attribute) and node.attr in target_symbols:
                matched.append(node.attr)
        return list(set(matched))


if __name__ == "__main__":
    slicer = OSVSlicer()
    intel = slicer.fetch_vuln_intel("GHSA-34jh-p97f-mpxf")
    print("\n[STAGE 1: LIVE OSV.DEV PATCH & SYMBOL EXTRACTION]")
    print(intel.model_dump_json(indent=2))
