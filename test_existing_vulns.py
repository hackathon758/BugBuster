#!/usr/bin/env python3
"""
Test AI Fix Generation with existing vulnerabilities
"""

import requests
import json

BASE_URL = "https://bug-fixer-35.preview.emergentagent.com/api"
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

def main():
    token = get_auth_token()
    if not token:
        print("❌ Failed to get auth token")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Get all vulnerabilities
    response = requests.get(f"{BASE_URL}/vulnerabilities", headers=headers)
    print(f"Vulnerabilities response: {response.status_code}")
    
    if response.status_code == 200:
        vulnerabilities = response.json()
        print(f"Found {len(vulnerabilities)} vulnerabilities")
        
        for i, vuln in enumerate(vulnerabilities[:3]):
            print(f"\nVulnerability {i+1}:")
            print(f"  ID: {vuln['id']}")
            print(f"  Title: {vuln.get('title', 'Unknown')}")
            print(f"  Severity: {vuln.get('severity', 'Unknown')}")
            print(f"  File: {vuln.get('file_path', 'Unknown')}")
            print(f"  Code snippet length: {len(vuln.get('code_snippet', ''))}")
            
            # Test AI fix generation
            fix_request = {
                "vulnerability_id": vuln["id"],
                "code_snippet": vuln.get("code_snippet", "console.log('test');"),
                "language": "javascript",
                "file_path": vuln.get("file_path", "test.js")
            }
            
            print(f"  Testing AI fix generation...")
            fix_response = requests.post(f"{BASE_URL}/vulnerabilities/generate-fix", 
                                       json=fix_request, headers=headers, timeout=30)
            
            print(f"  Fix response: {fix_response.status_code}")
            
            if fix_response.status_code == 200:
                fix_data = fix_response.json()
                print(f"  ✅ AI fix successful!")
                print(f"  Fixed code length: {len(fix_data.get('fixed_code', ''))}")
                print(f"  Explanation length: {len(fix_data.get('explanation', ''))}")
                print(f"  Improvements: {len(fix_data.get('improvements', []))}")
                
                # Test download
                print(f"  Testing download...")
                download_response = requests.post(f"{BASE_URL}/vulnerabilities/download-fix", 
                                                json=fix_request, headers=headers, timeout=30)
                print(f"  Download response: {download_response.status_code}")
                
                if download_response.status_code == 200:
                    print(f"  ✅ Download successful! Size: {len(download_response.content)} bytes")
                    content_disposition = download_response.headers.get('Content-Disposition', '')
                    print(f"  Content-Disposition: {content_disposition}")
                else:
                    print(f"  ❌ Download failed: {download_response.text}")
                
                break  # Test with first working vulnerability
            else:
                print(f"  ❌ AI fix failed: {fix_response.text}")
    else:
        print(f"Failed to get vulnerabilities: {response.text}")

if __name__ == "__main__":
    main()