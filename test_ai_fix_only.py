#!/usr/bin/env python3
"""
Test AI Fix Generation Feature Only
"""

import requests
import json
import sys

BASE_URL = "https://syntax-error-solver.preview.emergentagent.com/api"
TEST_USER_EMAIL = "testuser@bugbustersx.com"
TEST_USER_PASSWORD = "SecurePassword123!"

def get_auth_token():
    """Get authentication token"""
    login_data = {
        "email": TEST_USER_EMAIL,
        "password": TEST_USER_PASSWORD
    }
    
    response = requests.post(f"{BASE_URL}/auth/login", json=login_data)
    if response.status_code == 200:
        return response.json()["token"]
    return None

def test_ai_fix_generation():
    """Test AI fix generation with existing vulnerabilities"""
    token = get_auth_token()
    if not token:
        print("❌ Failed to get auth token")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Get existing vulnerabilities
    response = requests.get(f"{BASE_URL}/vulnerabilities", headers=headers)
    if response.status_code != 200:
        print("❌ Failed to get vulnerabilities")
        return False
    
    vulnerabilities = response.json()
    if not vulnerabilities:
        print("❌ No vulnerabilities found to test with")
        return False
    
    print(f"Found {len(vulnerabilities)} vulnerabilities to test with")
    
    # Test with first vulnerability
    vuln = vulnerabilities[0]
    print(f"Testing with vulnerability: {vuln.get('title', 'Unknown')}")
    
    fix_request = {
        "vulnerability_id": vuln["id"],
        "code_snippet": vuln.get("code_snippet", "console.log('test');"),
        "language": "javascript",
        "file_path": vuln.get("file_path", "test.js")
    }
    
    print("Generating AI fix...")
    response = requests.post(f"{BASE_URL}/vulnerabilities/generate-fix", 
                           json=fix_request, headers=headers, timeout=30)
    
    print(f"Response status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print("✅ AI Fix Generation successful!")
        print(f"Fixed code length: {len(data.get('fixed_code', ''))}")
        print(f"Explanation length: {len(data.get('explanation', ''))}")
        print(f"Improvements count: {len(data.get('improvements', []))}")
        return True
    else:
        print(f"❌ AI Fix Generation failed: {response.status_code}")
        print(f"Response: {response.text}")
        return False

if __name__ == "__main__":
    success = test_ai_fix_generation()
    sys.exit(0 if success else 1)