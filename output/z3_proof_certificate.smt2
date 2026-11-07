; === CVE-2024-37891 (UNSAT) ===
; benchmark generated from python API
(set-info :status unknown)
(declare-fun redirect_enabled () Bool)
(declare-fun eBPF_Runtime_State_redirect_is_False () Bool)
(declare-fun not_strips_proxy_auth () Bool)
(declare-fun eBPF_Runtime_State_Retry_strips_ProxyAuth () Bool)
(declare-fun streaming_enabled () Bool)
(declare-fun eBPF_Runtime_State_stream_is_False () Bool)
(declare-fun https_proxy_configured () Bool)
(declare-fun eBPF_Runtime_State_https_proxy_is_False () Bool)
(declare-fun decode_content_enabled () Bool)
(declare-fun eBPF_Runtime_Default_decode_content_is_True () Bool)
(declare-fun chunked_response_parsing_enabled () Bool)
(declare-fun eBPF_Runtime_Default_HTTP_chunk_parser_active () Bool)
(declare-fun has_proxy_auth_header () Bool)
(declare-fun AST_Caller_Guard_Pops_Proxy_Authorization () Bool)
(declare-fun AST_Caller_Hardcoded_redirect_False () Bool)
(declare-fun OSV_Precondition_CVE-2024-37891_Requires_redirect_enabled_AND_has_proxy_auth_header_AND_not_strips_proxy_auth () Bool)
(assert
 (let (($x12 (= redirect_enabled false)))
 (=> eBPF_Runtime_State_redirect_is_False $x12)))
(assert
 (let (($x35 (= not_strips_proxy_auth false)))
 (=> eBPF_Runtime_State_Retry_strips_ProxyAuth $x35)))
(assert
 (let (($x41 (= streaming_enabled false)))
 (=> eBPF_Runtime_State_stream_is_False $x41)))
(assert
 (let (($x47 (= https_proxy_configured false)))
 (=> eBPF_Runtime_State_https_proxy_is_False $x47)))
(assert
 (let (($x53 (= decode_content_enabled true)))
 (=> eBPF_Runtime_Default_decode_content_is_True $x53)))
(assert
 (let (($x58 (= chunked_response_parsing_enabled true)))
 (=> eBPF_Runtime_Default_HTTP_chunk_parser_active $x58)))
(assert
 (let (($x63 (= has_proxy_auth_header false)))
 (=> AST_Caller_Guard_Pops_Proxy_Authorization $x63)))
(assert
 (let (($x12 (= redirect_enabled false)))
 (=> AST_Caller_Hardcoded_redirect_False $x12)))
(assert
 (let (($x75 (= not_strips_proxy_auth true)))
(let (($x74 (= has_proxy_auth_header true)))
(let (($x73 (= redirect_enabled true)))
(let (($x76 (and $x73 $x74 $x75)))
(=> OSV_Precondition_CVE-2024-37891_Requires_redirect_enabled_AND_has_proxy_auth_header_AND_not_strips_proxy_auth $x76))))))
(check-sat)

(assert eBPF_Runtime_State_redirect_is_False)
(assert eBPF_Runtime_State_Retry_strips_ProxyAuth)
(assert eBPF_Runtime_State_stream_is_False)
(assert eBPF_Runtime_State_https_proxy_is_False)
(assert eBPF_Runtime_Default_decode_content_is_True)
(assert eBPF_Runtime_Default_HTTP_chunk_parser_active)
(assert AST_Caller_Guard_Pops_Proxy_Authorization)
(assert AST_Caller_Hardcoded_redirect_False)
(assert OSV_Precondition_CVE-2024-37891_Requires_redirect_enabled_AND_has_proxy_auth_header_AND_not_strips_proxy_auth)


; === CVE-2025-50181 (UNSAT) ===
; benchmark generated from python API
(set-info :status unknown)
(declare-fun redirect_enabled () Bool)
(declare-fun eBPF_Runtime_State_redirect_is_False () Bool)
(declare-fun not_strips_proxy_auth () Bool)
(declare-fun eBPF_Runtime_State_Retry_strips_ProxyAuth () Bool)
(declare-fun streaming_enabled () Bool)
(declare-fun eBPF_Runtime_State_stream_is_False () Bool)
(declare-fun https_proxy_configured () Bool)
(declare-fun eBPF_Runtime_State_https_proxy_is_False () Bool)
(declare-fun decode_content_enabled () Bool)
(declare-fun eBPF_Runtime_Default_decode_content_is_True () Bool)
(declare-fun chunked_response_parsing_enabled () Bool)
(declare-fun eBPF_Runtime_Default_HTTP_chunk_parser_active () Bool)
(declare-fun has_proxy_auth_header () Bool)
(declare-fun AST_Caller_Guard_Pops_Proxy_Authorization () Bool)
(declare-fun AST_Caller_Hardcoded_redirect_False () Bool)
(declare-fun OSV_Precondition_CVE-2025-50181_Requires_redirect_enabled () Bool)
(assert
 (let (($x77 (= redirect_enabled false)))
 (=> eBPF_Runtime_State_redirect_is_False $x77)))
(assert
 (let (($x35 (= not_strips_proxy_auth false)))
 (=> eBPF_Runtime_State_Retry_strips_ProxyAuth $x35)))
(assert
 (let (($x79 (= streaming_enabled false)))
 (=> eBPF_Runtime_State_stream_is_False $x79)))
(assert
 (let (($x68 (= https_proxy_configured false)))
 (=> eBPF_Runtime_State_https_proxy_is_False $x68)))
(assert
 (let (($x50 (= decode_content_enabled true)))
 (=> eBPF_Runtime_Default_decode_content_is_True $x50)))
(assert
 (let (($x39 (= chunked_response_parsing_enabled true)))
 (=> eBPF_Runtime_Default_HTTP_chunk_parser_active $x39)))
(assert
 (let (($x14 (= has_proxy_auth_header false)))
 (=> AST_Caller_Guard_Pops_Proxy_Authorization $x14)))
(assert
 (let (($x77 (= redirect_enabled false)))
 (=> AST_Caller_Hardcoded_redirect_False $x77)))
(assert
 (let (($x73 (= redirect_enabled true)))
(let (($x74 (and $x73)))
(=> OSV_Precondition_CVE-2025-50181_Requires_redirect_enabled $x74))))
(check-sat)

(assert eBPF_Runtime_State_redirect_is_False)
(assert eBPF_Runtime_State_Retry_strips_ProxyAuth)
(assert eBPF_Runtime_State_stream_is_False)
(assert eBPF_Runtime_State_https_proxy_is_False)
(assert eBPF_Runtime_Default_decode_content_is_True)
(assert eBPF_Runtime_Default_HTTP_chunk_parser_active)
(assert AST_Caller_Guard_Pops_Proxy_Authorization)
(assert AST_Caller_Hardcoded_redirect_False)
(assert OSV_Precondition_CVE-2025-50181_Requires_redirect_enabled)


; === CVE-2026-44431 (UNSAT) ===
; benchmark generated from python API
(set-info :status unknown)
(declare-fun redirect_enabled () Bool)
(declare-fun eBPF_Runtime_State_redirect_is_False () Bool)
(declare-fun not_strips_proxy_auth () Bool)
(declare-fun eBPF_Runtime_State_Retry_strips_ProxyAuth () Bool)
(declare-fun streaming_enabled () Bool)
(declare-fun eBPF_Runtime_State_stream_is_False () Bool)
(declare-fun https_proxy_configured () Bool)
(declare-fun eBPF_Runtime_State_https_proxy_is_False () Bool)
(declare-fun decode_content_enabled () Bool)
(declare-fun eBPF_Runtime_Default_decode_content_is_True () Bool)
(declare-fun chunked_response_parsing_enabled () Bool)
(declare-fun eBPF_Runtime_Default_HTTP_chunk_parser_active () Bool)
(declare-fun has_proxy_auth_header () Bool)
(declare-fun AST_Caller_Guard_Pops_Proxy_Authorization () Bool)
(declare-fun AST_Caller_Hardcoded_redirect_False () Bool)
(declare-fun OSV_Precondition_CVE-2026-44431_Requires_redirect_enabled () Bool)
(assert
 (let (($x75 (= redirect_enabled false)))
 (=> eBPF_Runtime_State_redirect_is_False $x75)))
(assert
 (let (($x35 (= not_strips_proxy_auth false)))
 (=> eBPF_Runtime_State_Retry_strips_ProxyAuth $x35)))
(assert
 (let (($x49 (= streaming_enabled false)))
 (=> eBPF_Runtime_State_stream_is_False $x49)))
(assert
 (let (($x34 (= https_proxy_configured false)))
 (=> eBPF_Runtime_State_https_proxy_is_False $x34)))
(assert
 (let (($x67 (= decode_content_enabled true)))
 (=> eBPF_Runtime_Default_decode_content_is_True $x67)))
(assert
 (let (($x81 (= chunked_response_parsing_enabled true)))
 (=> eBPF_Runtime_Default_HTTP_chunk_parser_active $x81)))
(assert
 (let (($x76 (= has_proxy_auth_header false)))
 (=> AST_Caller_Guard_Pops_Proxy_Authorization $x76)))
(assert
 (let (($x75 (= redirect_enabled false)))
 (=> AST_Caller_Hardcoded_redirect_False $x75)))
(assert
 (let (($x73 (= redirect_enabled true)))
(let (($x13 (and $x73)))
(=> OSV_Precondition_CVE-2026-44431_Requires_redirect_enabled $x13))))
(check-sat)

(assert eBPF_Runtime_State_redirect_is_False)
(assert eBPF_Runtime_State_Retry_strips_ProxyAuth)
(assert eBPF_Runtime_State_stream_is_False)
(assert eBPF_Runtime_State_https_proxy_is_False)
(assert eBPF_Runtime_Default_decode_content_is_True)
(assert eBPF_Runtime_Default_HTTP_chunk_parser_active)
(assert AST_Caller_Guard_Pops_Proxy_Authorization)
(assert AST_Caller_Hardcoded_redirect_False)
(assert OSV_Precondition_CVE-2026-44431_Requires_redirect_enabled)


; === CVE-2026-21441 (UNSAT) ===
; benchmark generated from python API
(set-info :status unknown)
(declare-fun redirect_enabled () Bool)
(declare-fun eBPF_Runtime_State_redirect_is_False () Bool)
(declare-fun not_strips_proxy_auth () Bool)
(declare-fun eBPF_Runtime_State_Retry_strips_ProxyAuth () Bool)
(declare-fun streaming_enabled () Bool)
(declare-fun eBPF_Runtime_State_stream_is_False () Bool)
(declare-fun https_proxy_configured () Bool)
(declare-fun eBPF_Runtime_State_https_proxy_is_False () Bool)
(declare-fun decode_content_enabled () Bool)
(declare-fun eBPF_Runtime_Default_decode_content_is_True () Bool)
(declare-fun chunked_response_parsing_enabled () Bool)
(declare-fun eBPF_Runtime_Default_HTTP_chunk_parser_active () Bool)
(declare-fun has_proxy_auth_header () Bool)
(declare-fun AST_Caller_Guard_Pops_Proxy_Authorization () Bool)
(declare-fun AST_Caller_Hardcoded_redirect_False () Bool)
(declare-fun OSV_Precondition_CVE-2026-21441_Requires_redirect_enabled_AND_streaming_enabled () Bool)
(assert
 (let (($x36 (= redirect_enabled false)))
 (=> eBPF_Runtime_State_redirect_is_False $x36)))
(assert
 (let (($x35 (= not_strips_proxy_auth false)))
 (=> eBPF_Runtime_State_Retry_strips_ProxyAuth $x35)))
(assert
 (let (($x62 (= streaming_enabled false)))
 (=> eBPF_Runtime_State_stream_is_False $x62)))
(assert
 (let (($x12 (= https_proxy_configured false)))
 (=> eBPF_Runtime_State_https_proxy_is_False $x12)))
(assert
 (let (($x29 (= decode_content_enabled true)))
 (=> eBPF_Runtime_Default_decode_content_is_True $x29)))
(assert
 (let (($x26 (= chunked_response_parsing_enabled true)))
 (=> eBPF_Runtime_Default_HTTP_chunk_parser_active $x26)))
(assert
 (let (($x74 (= has_proxy_auth_header false)))
 (=> AST_Caller_Guard_Pops_Proxy_Authorization $x74)))
(assert
 (let (($x36 (= redirect_enabled false)))
 (=> AST_Caller_Hardcoded_redirect_False $x36)))
(assert
 (let (($x69 (= streaming_enabled true)))
(let (($x73 (= redirect_enabled true)))
(let (($x37 (and $x73 $x69)))
(=> OSV_Precondition_CVE-2026-21441_Requires_redirect_enabled_AND_streaming_enabled $x37)))))
(check-sat)

(assert eBPF_Runtime_State_redirect_is_False)
(assert eBPF_Runtime_State_Retry_strips_ProxyAuth)
(assert eBPF_Runtime_State_stream_is_False)
(assert eBPF_Runtime_State_https_proxy_is_False)
(assert eBPF_Runtime_Default_decode_content_is_True)
(assert eBPF_Runtime_Default_HTTP_chunk_parser_active)
(assert AST_Caller_Guard_Pops_Proxy_Authorization)
(assert AST_Caller_Hardcoded_redirect_False)
(assert OSV_Precondition_CVE-2026-21441_Requires_redirect_enabled_AND_streaming_enabled)


; === CVE-2025-66471 (UNSAT) ===
; benchmark generated from python API
(set-info :status unknown)
(declare-fun redirect_enabled () Bool)
(declare-fun eBPF_Runtime_State_redirect_is_False () Bool)
(declare-fun not_strips_proxy_auth () Bool)
(declare-fun eBPF_Runtime_State_Retry_strips_ProxyAuth () Bool)
(declare-fun streaming_enabled () Bool)
(declare-fun eBPF_Runtime_State_stream_is_False () Bool)
(declare-fun https_proxy_configured () Bool)
(declare-fun eBPF_Runtime_State_https_proxy_is_False () Bool)
(declare-fun decode_content_enabled () Bool)
(declare-fun eBPF_Runtime_Default_decode_content_is_True () Bool)
(declare-fun chunked_response_parsing_enabled () Bool)
(declare-fun eBPF_Runtime_Default_HTTP_chunk_parser_active () Bool)
(declare-fun has_proxy_auth_header () Bool)
(declare-fun AST_Caller_Guard_Pops_Proxy_Authorization () Bool)
(declare-fun AST_Caller_Hardcoded_redirect_False () Bool)
(declare-fun OSV_Precondition_CVE-2025-66471_Requires_streaming_enabled () Bool)
(assert
 (let (($x71 (= redirect_enabled false)))
 (=> eBPF_Runtime_State_redirect_is_False $x71)))
(assert
 (let (($x35 (= not_strips_proxy_auth false)))
 (=> eBPF_Runtime_State_Retry_strips_ProxyAuth $x35)))
(assert
 (let (($x27 (= streaming_enabled false)))
 (=> eBPF_Runtime_State_stream_is_False $x27)))
(assert
 (let (($x23 (= https_proxy_configured false)))
 (=> eBPF_Runtime_State_https_proxy_is_False $x23)))
(assert
 (let (($x51 (= decode_content_enabled true)))
 (=> eBPF_Runtime_Default_decode_content_is_True $x51)))
(assert
 (let (($x48 (= chunked_response_parsing_enabled true)))
 (=> eBPF_Runtime_Default_HTTP_chunk_parser_active $x48)))
(assert
 (let (($x75 (= has_proxy_auth_header false)))
 (=> AST_Caller_Guard_Pops_Proxy_Authorization $x75)))
(assert
 (let (($x71 (= redirect_enabled false)))
 (=> AST_Caller_Hardcoded_redirect_False $x71)))
(assert
 (let (($x69 (= streaming_enabled true)))
(let (($x73 (and $x69)))
(=> OSV_Precondition_CVE-2025-66471_Requires_streaming_enabled $x73))))
(check-sat)

(assert eBPF_Runtime_State_redirect_is_False)
(assert eBPF_Runtime_State_Retry_strips_ProxyAuth)
(assert eBPF_Runtime_State_stream_is_False)
(assert eBPF_Runtime_State_https_proxy_is_False)
(assert eBPF_Runtime_Default_decode_content_is_True)
(assert eBPF_Runtime_Default_HTTP_chunk_parser_active)
(assert AST_Caller_Guard_Pops_Proxy_Authorization)
(assert AST_Caller_Hardcoded_redirect_False)
(assert OSV_Precondition_CVE-2025-66471_Requires_streaming_enabled)


; === CVE-2026-97687 (UNSAT) ===
; benchmark generated from python API
(set-info :status unknown)
(declare-fun redirect_enabled () Bool)
(declare-fun eBPF_Runtime_State_redirect_is_False () Bool)
(declare-fun not_strips_proxy_auth () Bool)
(declare-fun eBPF_Runtime_State_Retry_strips_ProxyAuth () Bool)
(declare-fun streaming_enabled () Bool)
(declare-fun eBPF_Runtime_State_stream_is_False () Bool)
(declare-fun https_proxy_configured () Bool)
(declare-fun eBPF_Runtime_State_https_proxy_is_False () Bool)
(declare-fun decode_content_enabled () Bool)
(declare-fun eBPF_Runtime_Default_decode_content_is_True () Bool)
(declare-fun chunked_response_parsing_enabled () Bool)
(declare-fun eBPF_Runtime_Default_HTTP_chunk_parser_active () Bool)
(declare-fun has_proxy_auth_header () Bool)
(declare-fun AST_Caller_Guard_Pops_Proxy_Authorization () Bool)
(declare-fun AST_Caller_Hardcoded_redirect_False () Bool)
(declare-fun OSV_Precondition_CVE-2026-97687_Requires_https_proxy_configured () Bool)
(assert
 (let (($x42 (= redirect_enabled false)))
 (=> eBPF_Runtime_State_redirect_is_False $x42)))
(assert
 (let (($x35 (= not_strips_proxy_auth false)))
 (=> eBPF_Runtime_State_Retry_strips_ProxyAuth $x35)))
(assert
 (let (($x80 (= streaming_enabled false)))
 (=> eBPF_Runtime_State_stream_is_False $x80)))
(assert
 (let (($x55 (= https_proxy_configured false)))
 (=> eBPF_Runtime_State_https_proxy_is_False $x55)))
(assert
 (let (($x50 (= decode_content_enabled true)))
 (=> eBPF_Runtime_Default_decode_content_is_True $x50)))
(assert
 (let (($x52 (= chunked_response_parsing_enabled true)))
 (=> eBPF_Runtime_Default_HTTP_chunk_parser_active $x52)))
(assert
 (let (($x37 (= has_proxy_auth_header false)))
 (=> AST_Caller_Guard_Pops_Proxy_Authorization $x37)))
(assert
 (let (($x42 (= redirect_enabled false)))
 (=> AST_Caller_Hardcoded_redirect_False $x42)))
(assert
 (let (($x65 (= https_proxy_configured true)))
(let (($x69 (and $x65)))
(=> OSV_Precondition_CVE-2026-97687_Requires_https_proxy_configured $x69))))
(check-sat)

(assert eBPF_Runtime_State_redirect_is_False)
(assert eBPF_Runtime_State_Retry_strips_ProxyAuth)
(assert eBPF_Runtime_State_stream_is_False)
(assert eBPF_Runtime_State_https_proxy_is_False)
(assert eBPF_Runtime_Default_decode_content_is_True)
(assert eBPF_Runtime_Default_HTTP_chunk_parser_active)
(assert AST_Caller_Guard_Pops_Proxy_Authorization)
(assert AST_Caller_Hardcoded_redirect_False)
(assert OSV_Precondition_CVE-2026-97687_Requires_https_proxy_configured)


; === CVE-2025-66418 (SAT) ===
; benchmark generated from python API
(set-info :status unknown)
(declare-fun redirect_enabled () Bool)
(declare-fun eBPF_Runtime_State_redirect_is_False () Bool)
(declare-fun not_strips_proxy_auth () Bool)
(declare-fun eBPF_Runtime_State_Retry_strips_ProxyAuth () Bool)
(declare-fun streaming_enabled () Bool)
(declare-fun eBPF_Runtime_State_stream_is_False () Bool)
(declare-fun https_proxy_configured () Bool)
(declare-fun eBPF_Runtime_State_https_proxy_is_False () Bool)
(declare-fun decode_content_enabled () Bool)
(declare-fun eBPF_Runtime_Default_decode_content_is_True () Bool)
(declare-fun chunked_response_parsing_enabled () Bool)
(declare-fun eBPF_Runtime_Default_HTTP_chunk_parser_active () Bool)
(declare-fun has_proxy_auth_header () Bool)
(declare-fun AST_Caller_Guard_Pops_Proxy_Authorization () Bool)
(declare-fun AST_Caller_Hardcoded_redirect_False () Bool)
(declare-fun OSV_Precondition_CVE-2025-66418_Requires_decode_content_enabled () Bool)
(assert
 (let (($x47 (= redirect_enabled false)))
 (=> eBPF_Runtime_State_redirect_is_False $x47)))
(assert
 (let (($x35 (= not_strips_proxy_auth false)))
 (=> eBPF_Runtime_State_Retry_strips_ProxyAuth $x35)))
(assert
 (let (($x20 (= streaming_enabled false)))
 (=> eBPF_Runtime_State_stream_is_False $x20)))
(assert
 (let (($x36 (= https_proxy_configured false)))
 (=> eBPF_Runtime_State_https_proxy_is_False $x36)))
(assert
 (let (($x43 (= decode_content_enabled true)))
 (=> eBPF_Runtime_Default_decode_content_is_True $x43)))
(assert
 (let (($x76 (= chunked_response_parsing_enabled true)))
 (=> eBPF_Runtime_Default_HTTP_chunk_parser_active $x76)))
(assert
 (let (($x73 (= has_proxy_auth_header false)))
 (=> AST_Caller_Guard_Pops_Proxy_Authorization $x73)))
(assert
 (let (($x47 (= redirect_enabled false)))
 (=> AST_Caller_Hardcoded_redirect_False $x47)))
(assert
 (let (($x43 (= decode_content_enabled true)))
(let (($x65 (and $x43)))
(=> OSV_Precondition_CVE-2025-66418_Requires_decode_content_enabled $x65))))
(check-sat)

(assert eBPF_Runtime_State_redirect_is_False)
(assert eBPF_Runtime_State_Retry_strips_ProxyAuth)
(assert eBPF_Runtime_State_stream_is_False)
(assert eBPF_Runtime_State_https_proxy_is_False)
(assert eBPF_Runtime_Default_decode_content_is_True)
(assert eBPF_Runtime_Default_HTTP_chunk_parser_active)
(assert AST_Caller_Guard_Pops_Proxy_Authorization)
(assert AST_Caller_Hardcoded_redirect_False)
(assert OSV_Precondition_CVE-2025-66418_Requires_decode_content_enabled)


; === CVE-2026-97689 (SAT) ===
; benchmark generated from python API
(set-info :status unknown)
(declare-fun redirect_enabled () Bool)
(declare-fun eBPF_Runtime_State_redirect_is_False () Bool)
(declare-fun not_strips_proxy_auth () Bool)
(declare-fun eBPF_Runtime_State_Retry_strips_ProxyAuth () Bool)
(declare-fun streaming_enabled () Bool)
(declare-fun eBPF_Runtime_State_stream_is_False () Bool)
(declare-fun https_proxy_configured () Bool)
(declare-fun eBPF_Runtime_State_https_proxy_is_False () Bool)
(declare-fun decode_content_enabled () Bool)
(declare-fun eBPF_Runtime_Default_decode_content_is_True () Bool)
(declare-fun chunked_response_parsing_enabled () Bool)
(declare-fun eBPF_Runtime_Default_HTTP_chunk_parser_active () Bool)
(declare-fun has_proxy_auth_header () Bool)
(declare-fun AST_Caller_Guard_Pops_Proxy_Authorization () Bool)
(declare-fun AST_Caller_Hardcoded_redirect_False () Bool)
(declare-fun OSV_Precondition_CVE-2026-97689_Requires_chunked_response_parsing_enabled () Bool)
(assert
 (let (($x86 (= redirect_enabled false)))
 (=> eBPF_Runtime_State_redirect_is_False $x86)))
(assert
 (let (($x35 (= not_strips_proxy_auth false)))
 (=> eBPF_Runtime_State_Retry_strips_ProxyAuth $x35)))
(assert
 (let (($x54 (= streaming_enabled false)))
 (=> eBPF_Runtime_State_stream_is_False $x54)))
(assert
 (let (($x71 (= https_proxy_configured false)))
 (=> eBPF_Runtime_State_https_proxy_is_False $x71)))
(assert
 (let (($x43 (= decode_content_enabled true)))
 (=> eBPF_Runtime_Default_decode_content_is_True $x43)))
(assert
 (let (($x89 (= chunked_response_parsing_enabled true)))
 (=> eBPF_Runtime_Default_HTTP_chunk_parser_active $x89)))
(assert
 (let (($x42 (= has_proxy_auth_header false)))
 (=> AST_Caller_Guard_Pops_Proxy_Authorization $x42)))
(assert
 (let (($x86 (= redirect_enabled false)))
 (=> AST_Caller_Hardcoded_redirect_False $x86)))
(assert
 (let (($x89 (= chunked_response_parsing_enabled true)))
(let (($x78 (and $x89)))
(=> OSV_Precondition_CVE-2026-97689_Requires_chunked_response_parsing_enabled $x78))))
(check-sat)

(assert eBPF_Runtime_State_redirect_is_False)
(assert eBPF_Runtime_State_Retry_strips_ProxyAuth)
(assert eBPF_Runtime_State_stream_is_False)
(assert eBPF_Runtime_State_https_proxy_is_False)
(assert eBPF_Runtime_Default_decode_content_is_True)
(assert eBPF_Runtime_Default_HTTP_chunk_parser_active)
(assert AST_Caller_Guard_Pops_Proxy_Authorization)
(assert AST_Caller_Hardcoded_redirect_False)
(assert OSV_Precondition_CVE-2026-97689_Requires_chunked_response_parsing_enabled)

