#!/usr/bin/env python3
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

import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

try:
    import requests
    import urllib3
except ImportError:
    print("[!] Missing dependency 'requests'. Install with: pip install requests --break-system-packages")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("[!] Missing dependency 'tqdm'. Install with: pip install tqdm --break-system-packages")
    sys.exit(1)

DEFAULT_UA = "Mozilla/5.0 (compatible; CSPScanner/1.0)"
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")

RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

# --------------------------------------------------------------------------
# CSP directive parsing and checks
# --------------------------------------------------------------------------

CSP_DIRECTIVES_OF_INTEREST = [
    "base-uri",
    "frame-ancestors",
    "script-src",
    "object-src",
    "require-trusted-types-for",
    "upgrade-insecure-requests",
    "block-all-mixed-content",
]

BOOLEAN_DIRECTIVES = {"upgrade-insecure-requests", "block-all-mixed-content"}


def parse_csp(csp_value):
    """Return dict of directive-name -> list of source-value tokens (lowercase key)."""
    directives = {}
    for part in csp_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        directives[name] = tokens[1:]
    return directives


def check_base_uri(values, directives):
    if values is None:
        return "MISSING", "Not set - allows injection of a <base> tag to hijack relative URL resolution"
    vl = [v.lower() for v in values]
    if "*" in vl:
        return "FAIL", "Wildcard (*) permits any base URI"
    if "'self'" in vl or "'none'" in vl:
        return "PASS", "Restricted to 'self'/'none'"
    return "WEAK", f"Restricted to specific origins ({', '.join(values)}) - verify these are fully trusted"


def check_frame_ancestors(values, directives):
    if values is None:
        return "MISSING", "Not set - page can be framed by any origin (clickjacking risk)"
    vl = [v.lower() for v in values]
    if "*" in vl:
        return "FAIL", "Wildcard (*) permits framing from any origin"
    if vl == ["'none'"] or vl == ["'self'"]:
        return "PASS", "Restricted appropriately"
    return "WEAK", f"Restricted to specific origins ({', '.join(values)}) - verify these are fully trusted"


def check_script_src(values, directives):
    if values is None:
        if "default-src" in directives:
            return "INHERIT", "No explicit script-src; inherits from default-src - verify default-src is restrictive"
        return "MISSING", "Not set and no default-src fallback - scripts are effectively unrestricted"
    vl = [v.lower() for v in values]
    issues = []
    if "*" in vl:
        issues.append("wildcard (*) allows any script source")
    if "'unsafe-inline'" in vl:
        issues.append("'unsafe-inline' allows inline script execution (XSS risk)")
    if "'unsafe-eval'" in vl:
        issues.append("'unsafe-eval' allows eval()-based code injection")
    if "data:" in vl:
        issues.append("'data:' scheme allows script injection via data URIs")
    if "http:" in vl or "https:" in vl:
        issues.append("bare scheme (http:/https:) allows loading scripts from any host on that scheme")
    if issues:
        return "FAIL", "; ".join(issues)
    return "PASS", "Restrictive configuration"


def check_object_src(values, directives):
    if values is None:
        default = [v.lower() for v in directives.get("default-src", [])]
        if default == ["'none'"]:
            return "PASS", "Inherited from default-src 'none'"
        return "MISSING", "Not set - should be 'none' to block legacy plugin content (Flash/Java/etc.)"
    vl = [v.lower() for v in values]
    if vl == ["'none'"]:
        return "PASS", "Set to 'none'"
    return "WEAK", f"Set to {values} - recommend 'none' unless plugin content is explicitly required"


def check_trusted_types(values, directives):
    if values is None:
        return "MISSING", "Not set - DOM-based XSS sinks are not mitigated; recommend require-trusted-types-for 'script'"
    vl = [v.lower() for v in values]
    if "'script'" in vl:
        return "PASS", "'script' enforced"
    return "WEAK", f"Present but does not include 'script': {values}"


def check_upgrade_insecure_requests(values, directives):
    if values is None:
        return "MISSING", "Not set - mixed-content HTTP resources on an HTTPS page are not auto-upgraded"
    return "PASS", "Enabled"


def check_block_all_mixed_content(values, directives):
    if values is None:
        return "MISSING", "Not set - consider adding for defense-in-depth (note: directive is deprecated in favor of upgrade-insecure-requests)"
    return "PASS", "Enabled (note: deprecated in modern browsers, upgrade-insecure-requests is preferred)"


CSP_CHECKS = {
    "base-uri": check_base_uri,
    "frame-ancestors": check_frame_ancestors,
    "script-src": check_script_src,
    "object-src": check_object_src,
    "require-trusted-types-for": check_trusted_types,
    "upgrade-insecure-requests": check_upgrade_insecure_requests,
    "block-all-mixed-content": check_block_all_mixed_content,
}


def analyze_csp(headers):
    """
    Returns dict with keys:
        present (bool), report_only_present (bool), report_only_only (bool),
        raw (str or None), raw_report_only (str or None),
        directives: { directive_name: {status, detail} }
    """
    csp_raw = headers.get("Content-Security-Policy")
    cspro_raw = headers.get("Content-Security-Policy-Report-Only")

    result = {
        "present": csp_raw is not None,
        "report_only_present": cspro_raw is not None,
        "report_only_only": csp_raw is None and cspro_raw is not None,
        "raw": csp_raw,
        "raw_report_only": cspro_raw,
        "directives": {},
    }

    effective_raw = csp_raw if csp_raw is not None else cspro_raw
    directives = parse_csp(effective_raw) if effective_raw else {}

    for name in CSP_DIRECTIVES_OF_INTEREST:
        values = directives.get(name)
        if name in BOOLEAN_DIRECTIVES:
            # boolean directives: presence in the dict (even with no value) means "set"
            present_flag = name in directives
            status, detail = CSP_CHECKS[name](None if not present_flag else [], directives)
        else:
            status, detail = CSP_CHECKS[name](values, directives)
        result["directives"][name] = {"status": status, "detail": detail}

    return result


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------


def build_target_url(raw_target):
    """
    Build an HTTPS URL from a bare hostname or IP address.
    Strips any scheme (http://, https://, etc.) and any path/query/fragment
    the user may have included, since only a hostname or IP is expected.
    """
    target = raw_target.strip()
    if not target or target.startswith("#"):
        return None
    target = SCHEME_RE.sub("", target)
    target = target.split("/")[0].split("?")[0].split("#")[0]
    if not target:
        return None
    return f"https://{target}"


def scan_target(raw_target, args):
    url = build_target_url(raw_target)
    if url is None:
        return None
    try:
        resp = requests.get(
            url,
            timeout=args.timeout,
            verify=args.verify,
            allow_redirects=not args.no_redirect,
            headers={"User-Agent": args.user_agent},
        )
    except requests.exceptions.RequestException as e:
        return {"target": raw_target, "success": False, "error": str(e)}

    csp_result = analyze_csp(resp.headers)
    csp_bad = [d for d, info in csp_result["directives"].items()
               if info["status"] in ("MISSING", "FAIL", "WEAK")]
    return {
        "target": raw_target,
        "scanned_url": url,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "success": True,
        "csp": csp_result,
        "csp_issue_directives": csp_bad,
    }


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def short_error(err):
    e = str(err)
    if "Connection refused" in e:
        return "connection refused"
    if "timed out" in e or "ConnectTimeout" in e:
        return "connection timed out"
    if "NameResolutionError" in e or "Name or service not known" in e or "Failed to resolve" in e:
        return "DNS resolution failed"
    if "SSLError" in e:
        return "TLS/SSL error"
    if "NewConnectionError" in e or "ProxyError" in e or "Max retries exceeded" in e:
        return "connection failed / unreachable"
    return e[:80]


def csp_state(r):
    c = r["csp"]
    if c["present"]:
        return "ENFORCED"
    if c["report_only_present"]:
        return "REPORT-ONLY"
    return "MISSING"


def grouped(results):
    """Build the per-finding host lists used by console + text report."""
    ok = [r for r in results if r and r["success"]]
    groups = {
        "No Content-Security-Policy header": [r["target"] for r in ok if csp_state(r) == "MISSING"],
        "Report-Only CSP (not enforced)": [r["target"] for r in ok if csp_state(r) == "REPORT-ONLY"],
    }
    for name in CSP_DIRECTIVES_OF_INTEREST:
        groups[f"{name} (missing/weak/fail)"] = [
            f"{r['target']} [{r['csp']['directives'][name]['status']}]" for r in ok
            if r["csp"]["directives"][name]["status"] in ("MISSING", "FAIL", "WEAK")
        ]
    errors = [r for r in results if r and not r["success"]]
    return groups, errors


def print_console_summary(results):
    print("\n" + "=" * 100)
    print("CSP SCAN SUMMARY")
    print("=" * 100)
    col_target, col_csp, col_state = 46, 11, 12
    print(f"{'TARGET':<{col_target}} {'CSP ISSUES':<{col_csp}} {'CSP':<{col_state}} STATUS")
    print("-" * 100)
    for r in results:
        if r is None:
            continue
        t = (r["target"][:col_target - 1] + "…") if len(r["target"]) > col_target else r["target"]
        if not r["success"]:
            print(f"{t:<{col_target}} {'--':<{col_csp}} {'--':<{col_state}} {RED}ERROR: {short_error(r['error'])}{RESET}")
            continue
        n = len(r["csp_issue_directives"])
        status = "OK" if n == 0 and r["csp"]["present"] else "FINDINGS"
        print(f"{t:<{col_target}} {n:<{col_csp}} {csp_state(r):<{col_state}} HTTP {r['status_code']} - {status}")
    print("-" * 100)

    for r in results:
        if r is None or not r["success"]:
            continue
        if r["csp_issue_directives"] or not r["csp"]["present"]:
            print(f"\n[{r['target']}]")
            if csp_state(r) == "MISSING":
                print("  CSP: no Content-Security-Policy header present at all")
            elif csp_state(r) == "REPORT-ONLY":
                print("  CSP: only Content-Security-Policy-Report-Only present (not enforced)")
            if r["csp_issue_directives"]:
                print("  CSP directive issues:")
                for d in r["csp_issue_directives"]:
                    info = r["csp"]["directives"][d]
                    print(f"    - {d} [{info['status']}]: {info['detail']}")

    groups, errors = grouped(results)
    print("\n" + "=" * 100)
    print("AFFECTED HOSTS BY FINDING")
    print("=" * 100)
    for name, hosts in groups.items():
        print(f"\n{BOLD}{name}{RESET} ({len(hosts)})")
        for h in hosts:
            print(f"  {h}")
    if errors:
        print(f"\n{YELLOW}Not checked (errors) - exclude from findings ({len(errors)}):{RESET}")
        for r in errors:
            print(f"  {r['target']} - {short_error(r['error'])}")
    print("\n" + "=" * 100)


def write_text_report(results, output_path, scan_meta):
    with open(output_path, "w") as f:
        f.write("CSP SCAN - DETAILED REPORT\n")
        f.write(f"Generated: {scan_meta['timestamp']}\n")
        f.write(f"Targets scanned: {scan_meta['total']}\n")
        f.write(f"TLS verification: {'enabled' if scan_meta['tls_verify'] else 'disabled'}\n")
        f.write("=" * 100 + "\n\n")

        for r in results:
            if r is None:
                continue
            f.write("-" * 100 + "\n")
            f.write(f"Target: {r['target']}\n")
            if not r["success"]:
                f.write(f"  ERROR: {r['error']}\n\n")
                continue
            f.write(f"  Scanned URL: {r['scanned_url']}\n")
            f.write(f"  Final URL (after redirects): {r['final_url']}\n")
            f.write(f"  HTTP Status: {r['status_code']}\n\n")
            f.write("  Content-Security-Policy:\n")
            f.write(f"    Raw CSP: {r['csp']['raw'] if r['csp']['present'] else '(not present)'}\n")
            if r["csp"]["report_only_present"]:
                f.write(f"    Raw CSP-Report-Only: {r['csp']['raw_report_only']}\n")
            f.write("    Directive analysis:\n")
            for name in CSP_DIRECTIVES_OF_INTEREST:
                info = r["csp"]["directives"][name]
                f.write(f"      [{info['status']}] {name}: {info['detail']}\n")
            f.write("\n")

        groups, errors = grouped(results)
        f.write("-" * 100 + "\n")
        f.write("AFFECTED HOSTS BY FINDING\n")
        f.write("=" * 100 + "\n")
        for name, hosts in groups.items():
            f.write(f"\n{name} ({len(hosts)})\n")
            for h in hosts:
                f.write(f"  {h}\n")
        if errors:
            f.write(f"\nNot checked (errors) - exclude from findings ({len(errors)}):\n")
            for r in errors:
                f.write(f"  {r['target']} - {short_error(r['error'])}\n")
        f.write("\n" + "-" * 100 + "\n")
        f.write("END OF REPORT\n")


def write_json_report(results, output_path, scan_meta):
    with open(output_path, "w") as f:
        json.dump({"meta": scan_meta, "results": results}, f, indent=2)


# --------------------------------------------------------------------------
# Input handling
# --------------------------------------------------------------------------


def clean_path(p):
    p = p.strip().strip("'\"")
    return os.path.abspath(os.path.expandvars(os.path.expanduser(p))) if p else ""


def enable_tab_completion():
    try:
        import glob
        import readline

        def complete(text, state):
            matches = glob.glob(os.path.expanduser(text) + "*")
            matches = [m + "/" if os.path.isdir(m) else m for m in matches]
            return matches[state] if state < len(matches) else None

        readline.set_completer_delims(" \t\n;")
        readline.parse_and_bind("tab: complete")
        readline.set_completer(complete)
    except ImportError:
        pass


def read_targets_file(path):
    targets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # strip list numbering ("1. host") only when followed by whitespace,
            # so IPs like 192.0.2.72 stay intact
            line = re.sub(r"^\d+[.)]\s+", "", line).split()[0]
            targets.append(line)
    return targets


def ask_choice(prompt, options, default="1"):
    while True:
        ans = input(prompt).strip() or default
        if ans in options:
            return ans
        print(f"{RED}Choose {' or '.join(options)}.{RESET}")


def interactive_setup(args):
    enable_tab_completion()
    print(f"{BOLD}CSP Scanner{RESET}  (TLS verification {'ON' if args.verify else 'OFF'})\n")

    mode = ask_choice("Target type - [1] targets file  [2] single host  [1]: ", ("1", "2"))
    if mode == "1":
        path = clean_path(input("Targets file (full path): "))
        while not os.path.isfile(path):
            path = clean_path(input(f"{RED}Not found.{RESET} Targets file (full path): "))
        targets = read_targets_file(path)
        base_dir = os.path.dirname(path)
    else:
        host = input("Host (hostname or IP): ").strip()
        while not host:
            host = input("Host (hostname or IP): ").strip()
        targets = [host]
        base_dir = os.getcwd()

    fmt = ask_choice("Output format - [1] text  [2] json  [3] both  [1]: ", ("1", "2", "3"))
    args.format = {"1": "text", "2": "json", "3": "both"}[fmt]

    ext = "json" if args.format == "json" else "txt"
    default_out = os.path.join(base_dir, f"csp_scan_{datetime.now():%Y-%m-%d_%H%M}.{ext}")
    hint = " (.json written alongside)" if args.format == "both" else ""
    out = clean_path(input(f"Output file (full path){hint} [{default_out}]: ")) or default_out
    if os.path.isdir(out):
        out = os.path.join(out, os.path.basename(default_out))
    args.output = out
    print()

    seen, deduped = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Scan targets for missing/misconfigured Content-Security-Policy directives over HTTPS.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Prompts for the target file or single host, output format, and output file.

Examples:
  %(prog)s
  %(prog)s -t 20 --timeout 15
""",
    )
    parser.add_argument("-t", "--threads", type=int, default=10, help="Concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("--verify", action="store_true", help="Enable TLS certificate verification (off by default)")
    parser.add_argument("--no-redirect", action="store_true", help="Do not follow redirects")
    parser.add_argument("-A", "--user-agent", default=DEFAULT_UA, help="Custom User-Agent header")
    args = parser.parse_args()

    targets = interactive_setup(args)
    if not targets:
        print(f"{RED}[!] No targets found.{RESET}")
        sys.exit(1)

    if not args.verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    print(f"[*] {len(targets)} target(s) | TLS verify: {'on' if args.verify else 'off'} | output -> {args.output}\n")

    results = [None] * len(targets)
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_idx = {executor.submit(scan_target, t, args): i for i, t in enumerate(targets)}
        with tqdm(total=len(targets), desc="Scanning targets", unit="target") as bar:
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    results[idx] = {"target": targets[idx], "success": False, "error": str(e)}
                bar.set_postfix_str(targets[idx][:40])
                bar.update(1)

    scan_meta = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total": len(targets),
        "tls_verify": args.verify,
    }

    print_console_summary(results)

    if args.format in ("text", "both"):
        write_text_report(results, args.output, scan_meta)
        print(f"\n[+] Text report: {args.output}")
    if args.format in ("json", "both"):
        json_out = args.output if args.format == "json" else os.path.splitext(args.output)[0] + ".json"
        write_json_report(results, json_out, scan_meta)
        print(f"[+] JSON report: {json_out}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted.{RESET}")
        sys.exit(130)
