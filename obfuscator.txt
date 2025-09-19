import argparse
import re
import base64
from urllib.parse import quote

# === Smart Techniques ===
def apply_vectors(payload, vectors):
    for vec in vectors:
        if vec == "utf16LE":
            payload = ''.join(f"\\u{ord(c):04x}" for c in payload)
        elif vec == "base64Copy":
            payload = base64.b64encode(payload.encode()).decode()
        elif vec == "malformedUrl":
            payload = quote(payload).replace('%', '%25')
        elif vec == "splitJoin":
            payload = '"+"'.join(payload)
        # Add other vectors here...
    return payload

def regex_mutation(payload):
    # Example regex-based mutation: replace dot with [.] to bypass filters
    payload = re.sub(r'\.', '[.]', payload)
    return payload

# === Payload Application ===
def inject_payload_to_url(url, payload):
    if "FUZZ" in url:
        return url.replace("FUZZ", payload)
    return url + ("?input=" + payload)

def process_urls(urls, payload):
    results = []
    for url in urls:
        results.append(inject_payload_to_url(url.strip(), payload))
    return results

# === Argument Parser ===
parser = argparse.ArgumentParser(description="Smart Payload Obfuscator")
parser.add_argument("-p", "--payload", help="Raw payload input")
parser.add_argument("-v", "--vectors", nargs="*", default=[], help="Optional vector tags (e.g., utf16LE splitJoin)")
parser.add_argument("--noregex", action="store_true", help="Disable regex-based mutation")
parser.add_argument("--url", help="Single target URL with optional FUZZ placeholder")
parser.add_argument("--url-list", help="File containing list of URLs (one per line)")
args = parser.parse_args()

# === Main Logic ===
if not args.payload:
    print("[!] Payload (-p) is required.")
    exit(1)

payload = args.payload

# Apply vector tags
payload = apply_vectors(payload, args.vectors)

# Regex-based mutation (if not disabled)
if not args.noregex:
    payload = regex_mutation(payload)

# Output mode
if args.url or args.url_list:
    if args.url:
        urls = [args.url]
    else:
        with open(args.url_list) as f:
            urls = f.readlines()
    results = process_urls(urls, payload)
    print("\n[+] Injected URLs:")
    for r in results:
        print(r)
else:
    print("\n[+] Obfuscated Payload:")
    print(payload)
