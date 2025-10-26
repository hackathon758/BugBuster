#!/usr/bin/env python3
"""
BUGBUSTERSX Backend Testing Suite
Tests the GitHub repository scanning feature
"""

import requests
import json
import time
import sys
from typing import Dict, Any, Optional

# Configuration
BASE_URL = "https://secrepo-monitor.preview.emergentagent.com/api"
TEST_USER_EMAIL = "testuser@bugbustersx.com"
TEST_USER_NAME = "Test User"
TEST_USER_PASSWORD = "SecurePassword123!"

class BugBustersXTester:
    def __init__(self):
        self.base_url = BASE_URL
        self.auth_token = None
        self.test_results = []
        
    def log_test(self, test_name: str, success: bool, message: str, details: Any = None):
        """Log test results"""
        result = {
            "test": test_name,
            "success": success,
            "message": message,
            "details": details
        }
        self.test_results.append(result)
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}: {message}")
        if details and not success:
            print(f"   Details: {details}")
    
    def make_request(self, method: str, endpoint: str, data: Dict = None, headers: Dict = None) -> requests.Response:
        """Make HTTP request with proper error handling"""
        url = f"{self.base_url}{endpoint}"
        default_headers = {"Content-Type": "application/json"}
        
        if self.auth_token:
            default_headers["Authorization"] = f"Bearer {self.auth_token}"
        
        if headers:
            default_headers.update(headers)
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=default_headers, timeout=30)
            elif method.upper() == "POST":
                response = requests.post(url, json=data, headers=default_headers, timeout=60)
            elif method.upper() == "PUT":
                response = requests.put(url, json=data, headers=default_headers, timeout=30)
            elif method.upper() == "DELETE":
                response = requests.delete(url, headers=default_headers, timeout=30)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            return response
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            raise
    
    def test_api_health(self):
        """Test if API is accessible"""
        try:
            response = self.make_request("GET", "/")
            if response.status_code == 200:
                data = response.json()
                self.log_test("API Health Check", True, f"API is operational: {data.get('message', 'OK')}")
                return True
            else:
                self.log_test("API Health Check", False, f"API returned status {response.status_code}")
                return False
        except Exception as e:
            self.log_test("API Health Check", False, f"Failed to connect to API: {str(e)}")
            return False
    
    def test_user_registration(self):
        """Test user registration"""
        try:
            user_data = {
                "email": TEST_USER_EMAIL,
                "name": TEST_USER_NAME,
                "password": TEST_USER_PASSWORD
            }
            
            response = self.make_request("POST", "/auth/register", user_data)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("email") == TEST_USER_EMAIL:
                    self.log_test("User Registration", True, "User registered successfully")
                    return True
                else:
                    self.log_test("User Registration", False, "Registration response missing user data", data)
                    return False
            elif response.status_code == 400 and "already registered" in response.text:
                self.log_test("User Registration", True, "User already exists (expected)")
                return True
            else:
                self.log_test("User Registration", False, f"Registration failed with status {response.status_code}", response.text)
                return False
        except Exception as e:
            self.log_test("User Registration", False, f"Registration error: {str(e)}")
            return False
    
    def test_user_login(self):
        """Test user login and get JWT token"""
        try:
            login_data = {
                "email": TEST_USER_EMAIL,
                "password": TEST_USER_PASSWORD
            }
            
            response = self.make_request("POST", "/auth/login", login_data)
            
            if response.status_code == 200:
                data = response.json()
                token = data.get("token")
                user = data.get("user")
                
                if token and user:
                    self.auth_token = token
                    self.log_test("User Login", True, f"Login successful for user: {user.get('name')}")
                    return True
                else:
                    self.log_test("User Login", False, "Login response missing token or user data", data)
                    return False
            else:
                self.log_test("User Login", False, f"Login failed with status {response.status_code}", response.text)
                return False
        except Exception as e:
            self.log_test("User Login", False, f"Login error: {str(e)}")
            return False
    
    def test_github_scan_valid_repo(self):
        """Test GitHub scanning with a valid small repository"""
        try:
            # Using a small public repository with actual code files for testing
            scan_data = {
                "github_url": "https://github.com/octocat/Spoon-Knife"
            }
            
            print("   Starting GitHub repository scan (this may take 30-60 seconds)...")
            response = self.make_request("POST", "/repositories/scan-github", scan_data)
            
            if response.status_code == 200:
                data = response.json()
                required_fields = ["repository_id", "scan_id", "total_files", "files_analyzed", 
                                 "total_vulnerabilities", "severity_counts", "security_score"]
                
                missing_fields = [field for field in required_fields if field not in data]
                
                if not missing_fields:
                    self.log_test("GitHub Scan - Valid Repo", True, 
                                f"Scan completed: {data['files_analyzed']} files analyzed, "
                                f"{data['total_vulnerabilities']} vulnerabilities found, "
                                f"security score: {data['security_score']}")
                    return data
                else:
                    self.log_test("GitHub Scan - Valid Repo", False, 
                                f"Response missing required fields: {missing_fields}", data)
                    return None
            else:
                self.log_test("GitHub Scan - Valid Repo", False, 
                            f"Scan failed with status {response.status_code}", response.text)
                return None
        except Exception as e:
            self.log_test("GitHub Scan - Valid Repo", False, f"Scan error: {str(e)}")
            return None
    
    def test_github_scan_invalid_url(self):
        """Test GitHub scanning with invalid URL format"""
        try:
            scan_data = {
                "github_url": "https://invalid-url.com/not-github"
            }
            
            response = self.make_request("POST", "/repositories/scan-github", scan_data)
            
            if response.status_code == 400:
                self.log_test("GitHub Scan - Invalid URL", True, "Correctly rejected invalid URL format")
                return True
            else:
                self.log_test("GitHub Scan - Invalid URL", False, 
                            f"Expected 400 error but got {response.status_code}", response.text)
                return False
        except Exception as e:
            self.log_test("GitHub Scan - Invalid URL", False, f"Test error: {str(e)}")
            return False
    
    def test_github_scan_nonexistent_repo(self):
        """Test GitHub scanning with non-existent repository"""
        try:
            scan_data = {
                "github_url": "https://github.com/nonexistent-user/nonexistent-repo-12345"
            }
            
            response = self.make_request("POST", "/repositories/scan-github", scan_data)
            
            if response.status_code == 400 or response.status_code == 500:
                self.log_test("GitHub Scan - Nonexistent Repo", True, "Correctly rejected non-existent repository")
                return True
            else:
                self.log_test("GitHub Scan - Nonexistent Repo", False, 
                            f"Expected 400/500 error but got {response.status_code}", response.text)
                return False
        except Exception as e:
            self.log_test("GitHub Scan - Nonexistent Repo", False, f"Test error: {str(e)}")
            return False
    
    def test_github_scan_no_code_files(self):
        """Test GitHub scanning with repository that has no code files"""
        try:
            scan_data = {
                "github_url": "https://github.com/octocat/Hello-World"
            }
            
            response = self.make_request("POST", "/repositories/scan-github", scan_data)
            
            if response.status_code == 400 and "No code files found" in response.text:
                self.log_test("GitHub Scan - No Code Files", True, "Correctly rejected repository with no code files")
                return True
            elif response.status_code == 500 and "No code files found" in response.text:
                self.log_test("GitHub Scan - No Code Files", True, "Correctly detected repository with no code files (500 status)")
                return True
            else:
                self.log_test("GitHub Scan - No Code Files", False, 
                            f"Expected 400 error for no code files but got {response.status_code}", response.text)
                return False
        except Exception as e:
            self.log_test("GitHub Scan - No Code Files", False, f"Test error: {str(e)}")
            return False
    
    def test_data_storage_verification(self, scan_result: Dict):
        """Verify that scan data was properly stored"""
        if not scan_result:
            self.log_test("Data Storage Verification", False, "No scan result to verify")
            return False
        
        try:
            # Test repository storage
            response = self.make_request("GET", "/repositories")
            if response.status_code == 200:
                repositories = response.json()
                repo_found = any(repo["id"] == scan_result["repository_id"] for repo in repositories)
                
                if repo_found:
                    self.log_test("Repository Storage", True, "Repository was stored correctly")
                else:
                    self.log_test("Repository Storage", False, "Repository not found in storage")
                    return False
            else:
                self.log_test("Repository Storage", False, f"Failed to fetch repositories: {response.status_code}")
                return False
            
            # Test scan storage
            response = self.make_request("GET", "/scans")
            if response.status_code == 200:
                scans = response.json()
                scan_found = any(scan["id"] == scan_result["scan_id"] for scan in scans)
                
                if scan_found:
                    self.log_test("Scan Storage", True, "Scan record was stored correctly")
                else:
                    self.log_test("Scan Storage", False, "Scan record not found in storage")
                    return False
            else:
                self.log_test("Scan Storage", False, f"Failed to fetch scans: {response.status_code}")
                return False
            
            # Test vulnerability storage (if vulnerabilities were found)
            if scan_result["total_vulnerabilities"] > 0:
                response = self.make_request("GET", f"/vulnerabilities?scan_id={scan_result['scan_id']}")
                if response.status_code == 200:
                    vulnerabilities = response.json()
                    if len(vulnerabilities) == scan_result["total_vulnerabilities"]:
                        self.log_test("Vulnerability Storage", True, 
                                    f"All {len(vulnerabilities)} vulnerabilities stored correctly")
                    else:
                        self.log_test("Vulnerability Storage", False, 
                                    f"Expected {scan_result['total_vulnerabilities']} vulnerabilities, "
                                    f"found {len(vulnerabilities)}")
                        return False
                else:
                    self.log_test("Vulnerability Storage", False, 
                                f"Failed to fetch vulnerabilities: {response.status_code}")
                    return False
            else:
                self.log_test("Vulnerability Storage", True, "No vulnerabilities found (as expected)")
            
            return True
            
        except Exception as e:
            self.log_test("Data Storage Verification", False, f"Verification error: {str(e)}")
            return False
    
    def test_authentication_required(self):
        """Test that authentication is required for protected endpoints"""
        try:
            # Temporarily remove auth token
            original_token = self.auth_token
            self.auth_token = None
            
            scan_data = {
                "github_url": "https://github.com/octocat/Hello-World"
            }
            
            response = self.make_request("POST", "/repositories/scan-github", scan_data)
            
            # Restore auth token
            self.auth_token = original_token
            
            if response.status_code == 401 or response.status_code == 403:
                self.log_test("Authentication Required", True, "Correctly requires authentication")
                return True
            else:
                self.log_test("Authentication Required", False, 
                            f"Expected 401/403 but got {response.status_code}")
                return False
        except Exception as e:
            self.auth_token = original_token  # Restore token even on error
            self.log_test("Authentication Required", False, f"Test error: {str(e)}")
            return False
    
    def run_all_tests(self):
        """Run all tests in sequence"""
        print("🚀 Starting BUGBUSTERSX Backend Tests")
        print("=" * 50)
        
        # Basic connectivity
        if not self.test_api_health():
            print("❌ API is not accessible. Stopping tests.")
            return False
        
        # Authentication tests
        self.test_user_registration()
        if not self.test_user_login():
            print("❌ Cannot authenticate. Stopping tests.")
            return False
        
        # Authentication requirement test
        self.test_authentication_required()
        
        # GitHub scanning tests
        scan_result = self.test_github_scan_valid_repo()
        self.test_github_scan_invalid_url()
        self.test_github_scan_nonexistent_repo()
        self.test_github_scan_no_code_files()
        
        # Data storage verification
        if scan_result:
            self.test_data_storage_verification(scan_result)
        
        # Summary
        print("\n" + "=" * 50)
        print("📊 TEST SUMMARY")
        print("=" * 50)
        
        passed = sum(1 for result in self.test_results if result["success"])
        total = len(self.test_results)
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Success Rate: {(passed/total)*100:.1f}%")
        
        if total - passed > 0:
            print("\n❌ FAILED TESTS:")
            for result in self.test_results:
                if not result["success"]:
                    print(f"  - {result['test']}: {result['message']}")
        
        return passed == total

def main():
    """Main test execution"""
    tester = BugBustersXTester()
    success = tester.run_all_tests()
    
    if success:
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()