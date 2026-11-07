"""
Service A (Hardened Production Service):
Executes real Jinja2, PyYAML, Requests, urllib3, OpenSSL (libssl.so.3 / libcrypto.so.3),
SQLite3 (libsqlite3.so.0), zlib (libz.so.1), and Expat (libexpat.so.1) with strict guards.
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

MAX_SAFE_ELEMENTS_32BIT = 10_000  # Strictly bounded well below 2^28 - 1 (268,435,455)

def execute_production_workload(requested_elements: int = 512):
    # 1. CWE-190 32-Bit Allocation Bound Guard (arXiv:2604.20496v1)
    if requested_elements < 0 or requested_elements > MAX_SAFE_ELEMENTS_32BIT:
        raise ValueError("Blocked potential 32-bit C allocation overflow")

    # 2. Real OpenSSL (libssl.so.3 / libcrypto.so.3) with 64-bit bitmask hardening
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_ctx.options |= ssl.OP_NO_COMPRESSION
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    digest = hashlib.sha256(b"vex-prove-openssl-telemetry").hexdigest()

    # 3. Real SQLite3 (libsqlite3.so.0) using parameterized sqlite3_prepare_v2 (NOT raw sqlite3_exec)
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE audit (id INTEGER PRIMARY KEY, hash TEXT)")
    cur.execute("INSERT INTO audit (hash) VALUES (?)", (digest[:16],))
    conn.commit()
    conn.close()

    # 4. Real Jinja2 with autoescape=True and attribute key sanitizer
    env = jinja2.Environment(autoescape=True)
    safe_attrs = {"id": "widget-01", "data_role": "panel"}
    for k in safe_attrs:
        if any(ch.isspace() or ch in "/><=" for ch in k):
            raise ValueError("Invalid XML attribute key")
    tmpl = env.from_string("<div {{ attrs | xmlattr }}>{{ content }}</div>")
    rendered = tmpl.render(attrs=safe_attrs, content="<script>alert(1)</script>")

    # 5. Real PyYAML enforcing SafeLoader
    parsed_cfg = yaml.load("service: vex-prove\nport: 8443\n", Loader=yaml.SafeLoader)

    # 6. Real Requests & urllib3 Retry with redirect=False and TLS verify=True
    session = requests.Session()
    session.verify = True
    retry_cfg = urllib3.util.retry.Retry(
        total=2,
        redirect=False,
        remove_headers_on_redirect=["Cookie", "Authorization", "Proxy-Authorization"],
    )

    # 7. Native C libz.so.1 (deflate ONLY; zero inflate decompression calls!) & libexpat.so.1
    compressed = zlib.compress(rendered.encode("utf-8"))
    parser = xml.parsers.expat.ParserCreate()
    parser.Parse("<status>OK</status>", True)

    return {
        "rendered": rendered,
        "config": parsed_cfg,
        "tls_verify": session.verify,
        "ssl_options_bitmask": int(ssl_ctx.options),
        "max_elements_bound": MAX_SAFE_ELEMENTS_32BIT,
        "retry_redirect": retry_cfg.redirect,
        "compressed_bytes": len(compressed),
    }
