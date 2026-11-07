"""
Vulnerable downstream microservice calling urllib3 WITHOUT inline mitigations:
1. Leaves redirect=True enabled
2. Uses older Retry header defaults without stripping 'Proxy-Authorization'
"""
def make_unsafe_request(headers: dict | None = None):
    headers = dict(headers or {})
    return invoke_urllib3_retry(
        redirect=True,
        remove_headers_on_redirect=["Cookie", "Authorization"],
    )

def invoke_urllib3_retry(redirect: bool, remove_headers_on_redirect: list):
    return {"status": 200, "redirect": redirect, "stripped": remove_headers_on_redirect}
