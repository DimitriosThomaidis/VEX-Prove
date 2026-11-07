"""
Sample downstream microservice calling urllib3 with inline mitigations:
1. Explicitly strips 'Proxy-Authorization' in Retry configuration
2. Enforces redirect=False at the caller boundary
"""
def make_internal_request(headers: dict | None = None):
    headers = dict(headers or {})
    # Inline Mitigation 1: Sanitize Proxy-Authorization before any request
    headers.pop("Proxy-Authorization", None)
    return invoke_urllib3_retry(
        redirect=False,
        remove_headers_on_redirect=["Cookie", "Authorization", "Proxy-Authorization"],
    )

def invoke_urllib3_retry(redirect: bool, remove_headers_on_redirect: list):
    # Boundary function representing urllib3 Retry initialization
    return {"status": 200, "redirect": redirect, "stripped": remove_headers_on_redirect}
