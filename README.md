"""
csp_scanner.py
 
Checks HTTPS responses for a missing or misconfigured Content-Security-Policy
(CSP) header. TLS certificate verification is DISABLED by default (use --verify
to enable), so hosts scanned by IP with hostname-only certs are still checked.
 
Prompts for: target file or single host, output format (text/json/both), output file.
 
CSP directives reviewed:
    base-uri, frame-ancestors, script-src, object-src,
    require-trusted-types-for, upgrade-insecure-requests, block-all-mixed-content
 
Requirements:
    pip install requests tqdm --break-system-packages
 
Usage:
    python3 csp_scanner.py
    Optional tuning flags: -t THREADS, --timeout SECS, --verify, --no-redirect, -A UA
"""
