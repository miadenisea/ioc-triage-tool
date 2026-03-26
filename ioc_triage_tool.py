"""
IOC Triage Tool
Project

This program reads indicators of compromise from a file,
identifies the IOC type, assigns a risk level,
and creates a CTI triage report.
"""

import argparse
import json
import os
from dataclasses import dataclass, asdict

# Always run from the folder where this script lives
os.chdir(os.path.dirname(os.path.abspath(__file__)))

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account",
    "reset", "microsoft", "paypal", "bank", "alert",
    "signin", "auth"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "short.link", "rb.gy", "cutt.ly"
]


# --- Data Class ---

@dataclass
class IOCResult:
    ioc: str
    ioc_type: str
    risk: str
    reason: str


# --- File I/O ---

def read_iocs(filename):
    """Read IOCs from a text file, skip blanks and comments. Deduplicates entries."""
    ioc_list = []
    seen = set()

    with open(filename, "r") as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith("#") and line not in seen:
                ioc_list.append(line)
                seen.add(line)

    return ioc_list


def save_report(filename, report_text):
    """Save the text report to a file."""
    with open(filename, "w") as file:
        file.write(report_text)


def save_json_report(filename, results):
    """Save results as a JSON file."""
    with open(filename, "w") as file:
        json.dump([asdict(r) for r in results], file, indent=2)


# --- IOC Type Detection ---

def is_url(ioc):
    """Return True if the IOC is a URL."""
    return ioc.startswith("http://") or ioc.startswith("https://")


def is_ip(ioc):
    """Return True if the IOC is a valid IPv4 address."""
    parts = ioc.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if not (0 <= int(part) <= 255):
            return False
    return True


def is_hash(ioc):
    """Return the hash type string if the IOC looks like a hash, else None."""
    valid_chars = set("0123456789abcdefABCDEF")
    if not all(char in valid_chars for char in ioc):
        return None
    return {32: "MD5 Hash", 40: "SHA1 Hash", 64: "SHA256 Hash"}.get(len(ioc))


def is_domain(ioc):
    """Return True if the IOC looks like a domain."""
    if " " in ioc or "." not in ioc:
        return False
    if is_url(ioc) or is_ip(ioc):
        return False

    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")
    if not all(char in allowed_chars for char in ioc):
        return False

    parts = ioc.split(".")
    if len(parts) < 2 or len(parts[-1]) < 2:
        return False

    return True


def detect_ioc_type(ioc):
    """Determine and return the IOC type string."""
    if is_url(ioc):
        return "URL"
    elif is_ip(ioc):
        return "IP Address"
    else:
        hash_type = is_hash(ioc)
        if hash_type:
            return hash_type
        elif is_domain(ioc):
            return "Domain"
        else:
            return "Unknown"


# --- Risk Analysis Helpers ---

def count_keywords(ioc):
    """Return a list of suspicious keywords found in the IOC."""
    ioc_lower = ioc.lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in ioc_lower]


def is_private_ip(ioc):
    """Return True if the IP address is in a private range."""
    if ioc.startswith("10.") or ioc.startswith("192.168.") or ioc.startswith("127."):
        return True
    if ioc.startswith("172."):
        second = int(ioc.split(".")[1])
        if 16 <= second <= 31:
            return True
    return False


def is_ip_based_url(ioc):
    """Return True if the URL uses a raw IP address instead of a domain."""
    if not is_url(ioc):
        return False
    # Strip scheme and get host
    host = ioc.split("//", 1)[-1].split("/")[0].split(":")[0]
    return is_ip(host)


def is_url_shortener(ioc):
    """Return True if the domain or URL uses a known URL shortener."""
    ioc_lower = ioc.lower()
    return any(shortener in ioc_lower for shortener in URL_SHORTENERS)


def has_many_subdomains(ioc):
    """Return True if the domain has 3 or more subdomains (suspicious)."""
    host = ioc.split("//", 1)[-1].split("/")[0] if is_url(ioc) else ioc
    return host.count(".") >= 3


# --- Risk Assignment ---

def assign_risk(ioc, ioc_type):
    """Assign a risk level and reason based on IOC type and attributes."""
    keywords_found = count_keywords(ioc)

    if ioc_type in ("Domain", "URL"):
        # Highest risk signals first
        if is_ip_based_url(ioc):
            return "HIGH", "URL uses a raw IP address instead of a domain"
        if len(keywords_found) >= 2:
            return "HIGH", f"Multiple suspicious keywords found: {', '.join(keywords_found)}"
        if is_url_shortener(ioc):
            return "MEDIUM", "URL shortener service detected"
        if has_many_subdomains(ioc):
            return "MEDIUM", "Excessive subdomains detected"
        if len(keywords_found) == 1:
            return "MEDIUM", f"Suspicious keyword found: {keywords_found[0]}"
        return "LOW", "No suspicious indicators found"

    elif ioc_type == "IP Address":
        if is_private_ip(ioc):
            return "LOW", "Private/internal IP address"
        return "MEDIUM", "Public IP address — may warrant investigation"

    elif "Hash" in ioc_type:
        return "MEDIUM", "File hash — submit for malware analysis"

    else:
        return "LOW", "Unknown IOC format — unable to assess"


# --- Report Building ---

def build_report(results):
    """Build and return the full text report."""
    type_counts = {"Domain": 0, "URL": 0, "IP Address": 0, "Hash": 0, "Unknown": 0}
    risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for r in results:
        if "Hash" in r.ioc_type:
            type_counts["Hash"] += 1
        elif r.ioc_type in type_counts:
            type_counts[r.ioc_type] += 1
        else:
            type_counts["Unknown"] += 1

        risk_counts[r.risk] += 1

    lines = [
        "IOC TRIAGE REPORT",
        "=" * 40,
        "",
        "[ Summary ]",
        f"Total IOCs:    {len(results)}",
        f"Domains:       {type_counts['Domain']}",
        f"URLs:          {type_counts['URL']}",
        f"IP Addresses:  {type_counts['IP Address']}",
        f"Hashes:        {type_counts['Hash']}",
        f"Unknown:       {type_counts['Unknown']}",
        "",
        "[ Risk Totals ]",
        f"HIGH:    {risk_counts['HIGH']}",
        f"MEDIUM:  {risk_counts['MEDIUM']}",
        f"LOW:     {risk_counts['LOW']}",
        "",
        "[ Detailed Results ]",
        "=" * 40,
    ]

    for r in results:
        lines += [
            f"IOC:    {r.ioc}",
            f"Type:   {r.ioc_type}",
            f"Risk:   {r.risk}",
            f"Reason: {r.reason}",
            "",
        ]

    return "\n".join(lines)


# --- CLI ---

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="IOC Triage Tool")
    parser.add_argument("-i", "--input", default="sample_iocs.txt", help="Input IOC file (default: sample_iocs.txt)")
    parser.add_argument("-o", "--output", default="ioc_report.txt", help="Output report file (default: ioc_report.txt)")
    parser.add_argument("--json", action="store_true", help="Also save a JSON report")
    parser.add_argument("--filter", choices=["HIGH", "MEDIUM", "LOW"], help="Only show IOCs of this risk level")
    parser.add_argument("--quiet", action="store_true", help="Suppress console output")
    return parser.parse_args()


# --- Main ---

def main():
    args = parse_args()

    try:
        raw_iocs = read_iocs(args.input)
    except FileNotFoundError:
        print(f"Error: input file '{args.input}' was not found.")
        return

    results = []
    for ioc in raw_iocs:
        ioc_type = detect_ioc_type(ioc)
        risk, reason = assign_risk(ioc, ioc_type)
        results.append(IOCResult(ioc=ioc, ioc_type=ioc_type, risk=risk, reason=reason))

    # Apply risk filter if specified
    display_results = results
    if args.filter:
        display_results = [r for r in results if r.risk == args.filter]

    report_text = build_report(display_results)

    if not args.quiet:
        print(report_text)

    save_report(args.output, report_text)
    print(f"Text report saved to {args.output}")

    if args.json:
        json_file = args.output.replace(".txt", ".json")
        save_json_report(json_file, display_results)
        print(f"JSON report saved to {json_file}")


main()
