"""
Service B (Unmitigated / Vulnerable Legacy Service):
Executes the exact same libraries WITHOUT guards:
- Calls zlib.decompress() -> Triggers kernel uprobe on libz.so.1:inflate!
- Uses yaml.UnsafeLoader -> Triggers CVE-2020-14343 (CRITICAL)!
- Sets urllib3 redirect=True without stripping Proxy-Authorization -> Triggers 4 redirect CVEs!
- Sets requests session.verify=False -> Triggers CVE-2024-35195!
- Disables Jinja2 autoescape -> Triggers CVE-2024-34064!
"""
import hashlib
import sqlite3
import ssl
import xml.parsers.expat
import zlib
import jinja2
import requests
import urllib3
import yaml

def execute_vulnerable_workload():
    # 1. Weak SSL bitmask (clears OP_NO_COMPRESSION) & disables cert verification
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    ssl_ctx.options &= ~ssl.OP_NO_COMPRESSION
    _ = hashlib.sha256(b"legacy-unverified").hexdigest()

    # 2. SQLite3 in-memory call
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE legacy (id INT)")
    conn.close()

    # 3. Vulnerable Jinja2: autoescape=False and no xmlattr key check
    env = jinja2.Environment(autoescape=False)
    tmpl = env.from_string("<div {{ attrs | xmlattr }}>{{ content }}</div>")
    rendered = tmpl.render(attrs={"id": "untrusted"}, content="raw")

    # 4. Vulnerable PyYAML: UnsafeLoader!
    parsed_cfg = yaml.load("service: legacy\n", Loader=yaml.UnsafeLoader)

    # 5. Vulnerable Requests & urllib3: verify=False, redirect=True, Proxy-Auth not stripped!
    session = requests.Session()
    session.verify = False
    retry_cfg = urllib3.util.retry.Retry(
        total=2,
        redirect=True,
        remove_headers_on_redirect=["Cookie", "Authorization"],
    )

    # 6. Vulnerable C libz.so.1 path: Actively calls zlib.decompress() -> triggers libz.so.1:inflate in kernel!
    compressed = zlib.compress(rendered.encode("utf-8"))
    decompressed = zlib.decompress(compressed)

    parser = xml.parsers.expat.ParserCreate()
    parser.Parse("<status>LEGACY</status>", True)

    return {
        "rendered": decompressed.decode("utf-8"),
        "config": parsed_cfg,
        "tls_verify": session.verify,
        "ssl_options_bitmask": int(ssl_ctx.options),
        "max_elements_bound": 0xFFFFFFFF,  # Unbounded 32-bit integer!
        "retry_redirect": retry_cfg.redirect,
        "compressed_bytes": len(compressed),
    }
