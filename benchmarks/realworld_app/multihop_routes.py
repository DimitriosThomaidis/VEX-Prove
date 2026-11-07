"""
Real 4-Hop Web Service Call-Graph Target:
[Hop 1: HTTP Route] -> [Hop 2: Middleware] -> [Hop 3: Domain Service] -> [Hop 4: urllib3 Sink]
"""
import urllib3

# === HOP 4: LIBRARY SINKS ===
def urllib3_sink_hardened(headers: dict):
    return urllib3.util.retry.Retry(
        total=2,
        redirect=False,
        remove_headers_on_redirect=["Cookie", "Authorization", "Proxy-Authorization"],
    )

def urllib3_sink_unprotected_redirect(headers: dict):
    return urllib3.util.retry.Retry(
        total=2,
        redirect=True,
        remove_headers_on_redirect=["Cookie", "Authorization"],
    )

# === HOP 3: DOMAIN SERVICES ===
def partner_gateway_service(payload: bytes, headers: dict):
    return urllib3_sink_hardened(headers)

def health_probe_service(headers: dict):
    return urllib3_sink_hardened(headers)

def webhook_forwarder_service(payload: bytes, headers: dict):
    return urllib3_sink_unprotected_redirect(headers)

# === HOP 2: MIDDLEWARES ===
def strict_sanitizer_middleware(payload: bytes, headers: dict, mode: str = "partner"):
    headers.pop("Proxy-Authorization", None)
    headers.pop("Cookie", None)
    if mode == "health":
        return health_probe_service(headers)
    return partner_gateway_service(payload, headers)

def legacy_passthrough_middleware(payload: bytes, headers: dict):
    # Intentionally omits header sanitization!
    return webhook_forwarder_service(payload, headers)

# === HOP 1: HTTP ENTRYPOINT ROUTES ===
def route_post_partner_sync(payload: bytes, headers: dict):
    """POST /api/v1/internal/partner-sync"""
    return strict_sanitizer_middleware(payload, headers, mode="partner")

def route_get_upstream_health(headers: dict):
    """GET /api/v1/health/upstream-check"""
    return strict_sanitizer_middleware(b"", headers, mode="health")

def route_post_legacy_webhook(payload: bytes, headers: dict):
    """POST /api/v1/legacy/webhook-forward (Unprotected Route!)"""
    return legacy_passthrough_middleware(payload, headers)
