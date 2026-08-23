"""
CyberGuard Navigation Diagnostic Test
Tests tab navigation, DOM structure, and JavaScript functionality
"""

import requests
import re
import json

BASE_URL = "http://127.0.0.1:8000"
APP_URL = f"{BASE_URL}/app"

def test_server_running():
    """Test if server is running"""
    print("[1] Testing if server is running...")
    try:
        resp = requests.get(BASE_URL, timeout=2)
        print(f"    ✓ Server responding with status {resp.status_code}")
        return True
    except Exception as e:
        print(f"    ✗ Server not responding: {e}")
        return False

def test_html_loads():
    """Test if HTML template loads"""
    print("[2] Testing if HTML template loads...")
    try:
        resp = requests.get(APP_URL, timeout=5)
        if resp.status_code == 200:
            print(f"    ✓ HTML loaded ({len(resp.text)} bytes)")
            return resp.text
        else:
            print(f"    ✗ HTML returned status {resp.status_code}")
            return None
    except Exception as e:
        print(f"    ✗ Failed to load HTML: {e}")
        return None

def test_tab_buttons(html):
    """Test if tab buttons are in HTML"""
    print("[3] Checking for tab button elements...")
    tabs = ['dashboard', 'password', 'breaches', 'kb', 'chat']
    found = []
    
    for tab in tabs:
        if f'data-tab="{tab}"' in html:
            found.append(tab)
            print(f"    ✓ Found tab: {tab}")
        else:
            print(f"    ✗ Missing tab: {tab}")
    
    return len(found) == len(tabs)

def test_tab_panels(html):
    """Test if tab panels are in HTML"""
    print("[4] Checking for tab panel elements...")
    tabs = ['dashboard', 'password', 'breaches', 'kb', 'chat']
    found = []
    
    for tab in tabs:
        if f'id="tab-{tab}"' in html:
            found.append(tab)
            print(f"    ✓ Found panel: tab-{tab}")
        else:
            print(f"    ✗ Missing panel: tab-{tab}")
    
    return len(found) == len(tabs)

def test_initTabs_function(html):
    """Test if initTabs function is defined"""
    print("[5] Checking for initTabs() function...")
    if 'function initTabs()' in html:
        print(f"    ✓ initTabs() function found")
        # Extract the function
        match = re.search(r'function initTabs\(\)\s*\{(.*?)\n\s*\}', html, re.DOTALL)
        if match:
            func_body = match.group(1)
            checks = {
                'querySelectorAll': '.querySelectorAll(".tab-btn")' in func_body or "querySelectorAll('.tab-btn')" in func_body,
                'addEventListener': 'addEventListener' in func_body,
                'classList.remove': 'classList.remove' in func_body,
                'classList.add': 'classList.add' in func_body,
            }
            for check, found in checks.items():
                status = "✓" if found else "✗"
                print(f"      {status} Contains: {check}")
            return all(checks.values())
    else:
        print(f"    ✗ initTabs() function not found")
    return False

def test_dom_event_listeners(html):
    """Test if DOMContentLoaded calls initTabs"""
    print("[6] Checking DOMContentLoaded initialization...")
    if 'DOMContentLoaded' in html and 'initTabs()' in html:
        # Find if initTabs is called in DOMContentLoaded
        match = re.search(r'addEventListener\("DOMContentLoaded".*?\{(.*?)\}\);', html, re.DOTALL)
        if match:
            event_body = match.group(1)
            if 'initTabs()' in event_body:
                print(f"    ✓ initTabs() is called on DOMContentLoaded")
                return True
            else:
                print(f"    ✗ initTabs() NOT called on DOMContentLoaded")
        else:
            print(f"    ✗ Could not parse DOMContentLoaded handler")
    else:
        print(f"    ✗ DOMContentLoaded not found in HTML")
    return False

def test_css_loaded():
    """Test if CSS file loads"""
    print("[7] Testing if CSS loads...")
    try:
        resp = requests.get(f"{BASE_URL}/static/style.css", timeout=2)
        if resp.status_code == 200:
            print(f"    ✓ CSS loaded ({len(resp.text)} bytes)")
            # Check for tab CSS rules
            if '.tab-panel { display: none' in resp.text or '.tab-panel{display:none' in resp.text:
                print(f"    ✓ Found tab panel CSS rule")
            if '.tab-panel.active { display: block' in resp.text or '.tab-panel.active{display:block' in resp.text:
                print(f"    ✓ Found active tab panel CSS rule")
            return True
        else:
            print(f"    ✗ CSS returned status {resp.status_code}")
            return False
    except Exception as e:
        print(f"    ✗ Failed to load CSS: {e}")
        return False

def test_js_bundle():
    """Test if JavaScript bundle loads"""
    print("[8] Testing if JavaScript bundle loads...")
    try:
        resp = requests.get(f"{BASE_URL}/static/html2pdf.bundle.min.js", timeout=2)
        if resp.status_code == 200:
            print(f"    ✓ JS bundle loaded ({len(resp.text)} bytes)")
            return True
        else:
            print(f"    ✗ JS bundle returned status {resp.status_code}")
            return False
    except Exception as e:
        print(f"    ✗ Failed to load JS bundle: {e}")
        return False

def test_api_endpoints():
    """Test if API endpoints are working"""
    print("[9] Testing API endpoints...")
    endpoints = [
        '/api/phishing',
        '/api/password',
        '/api/breach-email',
        '/api/chat',
        '/api/threat-intel',
        '/api/rules',
        '/api/session-summary'
    ]
    
    working = 0
    for endpoint in endpoints:
        try:
            resp = requests.get(f"{BASE_URL}{endpoint}", timeout=2)
            if resp.status_code in [200, 405, 422]:  # OK or POST required or missing fields
                print(f"    ✓ {endpoint} exists (status {resp.status_code})")
                working += 1
            else:
                print(f"    ? {endpoint} returned {resp.status_code}")
        except Exception as e:
            print(f"    ✗ {endpoint} error: {e}")
    
    return working == len(endpoints)

def main():
    print("=" * 60)
    print("CyberGuard Navigation Diagnostic Test")
    print("=" * 60)
    print()
    
    # Run tests
    if not test_server_running():
        print("\n✗ Server not running. Start it with: python run_cyberguard.py")
        return
    
    html = test_html_loads()
    if not html:
        print("\n✗ Could not load HTML template")
        return
    
    print()
    results = {
        "HTML Template": test_html_loads() is not None,
        "Tab Buttons": test_tab_buttons(html),
        "Tab Panels": test_tab_panels(html),
        "initTabs() Function": test_initTabs_function(html),
        "DOMContentLoaded Hook": test_dom_event_listeners(html),
        "CSS Loads": test_css_loaded(),
        "JS Bundle Loads": test_js_bundle(),
        "API Endpoints": test_api_endpoints(),
    }
    
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    passed = 0
    for test_name, passed_test in results.items():
        status = "✓ PASS" if passed_test else "✗ FAIL"
        print(f"{status}: {test_name}")
        if passed_test:
            passed += 1
    
    print()
    print(f"Results: {passed}/{len(results)} tests passed")
    print()
    
    if passed == len(results):
        print("✓ All tests passed! The issue is likely in the browser/webview.")
        print("  Next steps:")
        print("  1. Open the CyberGuard window")
        print("  2. Press F12 to open Developer Tools")
        print("  3. Go to Console tab")
        print("  4. Look for any red error messages")
        print("  5. Try clicking a tab and watch the console output")
    else:
        print("✗ Some tests failed. Check the output above for details.")

if __name__ == "__main__":
    main()
