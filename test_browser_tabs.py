"""
Browser-based navigation test
Opens the app in the default browser and performs tab clicks via Playwright
"""

import subprocess
import time
import sys
from pathlib import Path

# Try to import selenium for browser testing
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
except ImportError:
    print("Selenium not installed. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "selenium"])
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options

def test_tabs_in_browser():
    """Test tab navigation in a real Chrome browser"""
    print("=" * 60)
    print("CyberGuard Browser Tab Test")
    print("=" * 60)
    print()
    
    url = "http://127.0.0.1:8000/app"
    
    print("[1] Opening Chrome browser...")
    chrome_options = Options()
    # Don't use headless mode - we want to see what's happening
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--no-sandbox")
    
    try:
        driver = webdriver.Chrome(options=chrome_options)
    except Exception as e:
        print(f"✗ Could not start Chrome: {e}")
        print("  Make sure ChromeDriver is installed and in PATH")
        return
    
    try:
        print(f"[2] Loading {url}...")
        driver.get(url)
        driver.set_window_size(1200, 800)
        
        # Wait for page to load
        time.sleep(2)
        
        print("[3] Testing tab clicks...")
        tabs = ['password', 'breaches', 'kb', 'chat']
        
        for tab_name in tabs:
            print(f"\n    Testing tab: {tab_name}")
            try:
                # Find the tab button
                tab_button = driver.find_element(By.CSS_SELECTOR, f'button[data-tab="{tab_name}"]')
                print(f"      ✓ Found tab button")
                
                # Click it
                tab_button.click()
                print(f"      ✓ Clicked tab button")
                
                # Wait for panel to become active
                time.sleep(0.5)
                
                # Check if the panel is visible
                panel = driver.find_element(By.ID, f'tab-{tab_name}')
                is_active = 'active' in panel.get_attribute('class')
                is_visible = driver.execute_script(f"return document.getElementById('tab-{tab_name}').offsetParent !== null")
                
                if is_active and is_visible:
                    print(f"      ✓ Panel is now active and visible")
                else:
                    print(f"      ✗ Panel is NOT active (active class: {is_active}, visible: {is_visible})")
                
            except Exception as e:
                print(f"      ✗ Error: {e}")
        
        print("\n[4] Checking for JavaScript errors...")
        
        # Get browser logs
        logs = driver.get_log('browser')
        errors = [log for log in logs if log['level'] == 'SEVERE']
        
        if errors:
            print(f"    ✗ Found {len(errors)} error(s):")
            for error in errors:
                print(f"      - {error['message']}")
        else:
            print(f"    ✓ No JavaScript errors found")
        
        print("\n" + "=" * 60)
        print("TEST COMPLETE")
        print("=" * 60)
        print("\nThe browser is still open. Check:")
        print("1. Can you click the tabs?")
        print("2. Do the pages switch?")
        print("3. Check F12 console for errors")
        print("\nPress Enter to close the browser...")
        input()
        
    finally:
        driver.quit()

if __name__ == "__main__":
    test_tabs_in_browser()
