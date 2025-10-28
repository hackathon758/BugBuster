"""Pattern Recognition System for Known Vulnerability Signatures"""
from typing import Dict, List, Any
import re
import logging

logger = logging.getLogger(__name__)

class PatternRecognizer:
    """Recognize known vulnerability patterns in code"""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize vulnerability pattern database"""
        return {
            'sql_injection': [
                {
                    'pattern': r'query\s*=\s*["\'].*\+.*["\']',
                    'description': 'SQL query with string concatenation',
                    'severity': 'critical',
                    'cwe': 'CWE-89',
                    'languages': ['python', 'javascript', 'java', 'php']
                },
                {
                    'pattern': r'execute\s*\(["\'].*%s.*["\']\s*%',
                    'description': 'SQL execution with string formatting',
                    'severity': 'critical',
                    'cwe': 'CWE-89',
                    'languages': ['python']
                },
                {
                    'pattern': r'cursor\.execute\s*\([^)]*\+[^)]*\)',
                    'description': 'Database cursor execution with concatenation',
                    'severity': 'critical',
                    'cwe': 'CWE-89',
                    'languages': ['python']
                }
            ],
            'xss': [
                {
                    'pattern': r'innerHTML\s*=\s*[^;]*(request|params|query)',
                    'description': 'innerHTML assignment with user input',
                    'severity': 'high',
                    'cwe': 'CWE-79',
                    'languages': ['javascript', 'typescript']
                },
                {
                    'pattern': r'document\.write\s*\([^)]*(request|params)',
                    'description': 'document.write with user input',
                    'severity': 'high',
                    'cwe': 'CWE-79',
                    'languages': ['javascript', 'typescript']
                },
                {
                    'pattern': r'dangerouslySetInnerHTML.*__html',
                    'description': 'React dangerouslySetInnerHTML usage',
                    'severity': 'high',
                    'cwe': 'CWE-79',
                    'languages': ['javascript', 'typescript']
                }
            ],
            'command_injection': [
                {
                    'pattern': r'os\.system\s*\([^)]*input|request|argv',
                    'description': 'System command execution with user input',
                    'severity': 'critical',
                    'cwe': 'CWE-78',
                    'languages': ['python']
                },
                {
                    'pattern': r'subprocess\.call\s*\(.*shell\s*=\s*True',
                    'description': 'Subprocess call with shell=True',
                    'severity': 'critical',
                    'cwe': 'CWE-78',
                    'languages': ['python']
                },
                {
                    'pattern': r'Runtime\.getRuntime\s*\(\)\.exec',
                    'description': 'Java Runtime.exec() usage',
                    'severity': 'high',
                    'cwe': 'CWE-78',
                    'languages': ['java']
                },
                {
                    'pattern': r'exec\.Command\s*\([^)]*os\.Args',
                    'description': 'Go command execution with os.Args',
                    'severity': 'high',
                    'cwe': 'CWE-78',
                    'languages': ['go']
                }
            ],
            'code_injection': [
                {
                    'pattern': r'eval\s*\(',
                    'description': 'Use of eval() function',
                    'severity': 'critical',
                    'cwe': 'CWE-95',
                    'languages': ['python', 'javascript', 'typescript']
                },
                {
                    'pattern': r'exec\s*\(',
                    'description': 'Use of exec() function',
                    'severity': 'critical',
                    'cwe': 'CWE-95',
                    'languages': ['python']
                },
                {
                    'pattern': r'Function\s*\(.*\)',
                    'description': 'Dynamic function creation',
                    'severity': 'high',
                    'cwe': 'CWE-95',
                    'languages': ['javascript', 'typescript']
                }
            ],
            'path_traversal': [
                {
                    'pattern': r'open\s*\([^)]*\.\.\/|\.\.\\\\',
                    'description': 'File open with path traversal sequences',
                    'severity': 'high',
                    'cwe': 'CWE-22',
                    'languages': ['python', 'java', 'go']
                },
                {
                    'pattern': r'readFile\s*\([^)]*request|params|query',
                    'description': 'File read with user input',
                    'severity': 'high',
                    'cwe': 'CWE-22',
                    'languages': ['javascript', 'typescript']
                }
            ],
            'insecure_crypto': [
                {
                    'pattern': r'hashlib\.md5\s*\(',
                    'description': 'Use of weak MD5 hash',
                    'severity': 'medium',
                    'cwe': 'CWE-327',
                    'languages': ['python']
                },
                {
                    'pattern': r'hashlib\.sha1\s*\(',
                    'description': 'Use of weak SHA1 hash',
                    'severity': 'medium',
                    'cwe': 'CWE-327',
                    'languages': ['python']
                },
                {
                    'pattern': r'MessageDigest\.getInstance\s*\(["\']MD5["\']',
                    'description': 'Java MD5 usage',
                    'severity': 'medium',
                    'cwe': 'CWE-327',
                    'languages': ['java']
                }
            ],
            'hardcoded_secrets': [
                {
                    'pattern': r'password\s*=\s*["\'][^"\'{]+["\']',
                    'description': 'Hardcoded password',
                    'severity': 'high',
                    'cwe': 'CWE-798',
                    'languages': ['python', 'javascript', 'java', 'go', 'rust']
                },
                {
                    'pattern': r'api[_-]?key\s*=\s*["\'][^"\'{]+["\']',
                    'description': 'Hardcoded API key',
                    'severity': 'high',
                    'cwe': 'CWE-798',
                    'languages': ['python', 'javascript', 'java', 'go', 'rust']
                },
                {
                    'pattern': r'secret\s*=\s*["\'][^"\'{]+["\']',
                    'description': 'Hardcoded secret',
                    'severity': 'high',
                    'cwe': 'CWE-798',
                    'languages': ['python', 'javascript', 'java', 'go', 'rust']
                }
            ],
            'deserialization': [
                {
                    'pattern': r'pickle\.loads?\s*\(',
                    'description': 'Insecure deserialization with pickle',
                    'severity': 'critical',
                    'cwe': 'CWE-502',
                    'languages': ['python']
                },
                {
                    'pattern': r'yaml\.load\s*\([^,)]*\)(?!.*Loader)',
                    'description': 'Unsafe YAML loading',
                    'severity': 'critical',
                    'cwe': 'CWE-502',
                    'languages': ['python']
                },
                {
                    'pattern': r'JSON\.parse\s*\([^)]*user',
                    'description': 'JSON parsing of user data',
                    'severity': 'medium',
                    'cwe': 'CWE-502',
                    'languages': ['javascript', 'typescript']
                }
            ],
            'race_condition': [
                {
                    'pattern': r'if\s+os\.path\.exists.*:\s*open',
                    'description': 'Time-of-check time-of-use (TOCTOU)',
                    'severity': 'medium',
                    'cwe': 'CWE-367',
                    'languages': ['python']
                }
            ],
            'xxe': [
                {
                    'pattern': r'xml\.etree\.ElementTree\.parse',
                    'description': 'XML parsing without protection against XXE',
                    'severity': 'high',
                    'cwe': 'CWE-611',
                    'languages': ['python']
                },
                {
                    'pattern': r'DocumentBuilder\.parse',
                    'description': 'Java XML parsing potentially vulnerable to XXE',
                    'severity': 'high',
                    'cwe': 'CWE-611',
                    'languages': ['java']
                }
            ]
        }
    
    def analyze(self, code: str, language: str, file_path: str = '') -> List[Dict[str, Any]]:
        """Analyze code for known vulnerability patterns"""
        vulnerabilities = []
        language = language.lower()
        
        try:
            for category, patterns in self.patterns.items():
                for pattern_def in patterns:
                    # Check if pattern applies to this language
                    if language not in pattern_def['languages']:
                        continue
                    
                    # Search for pattern
                    matches = re.finditer(pattern_def['pattern'], code, re.MULTILINE | re.IGNORECASE)
                    
                    for match in matches:
                        line_num = code[:match.start()].count('\n') + 1
                        
                        # Extract code snippet
                        lines = code.split('\n')
                        start_line = max(0, line_num - 2)
                        end_line = min(len(lines), line_num + 2)
                        snippet = '\n'.join(lines[start_line:end_line])
                        
                        vulnerabilities.append({
                            'type': 'PATTERN_MATCH',
                            'category': category,
                            'severity': pattern_def['severity'],
                            'title': f'{category.replace("_", " ").title()} Vulnerability',
                            'description': pattern_def['description'],
                            'line': line_num,
                            'code_snippet': snippet,
                            'matched_pattern': match.group(0),
                            'cwe_id': pattern_def['cwe'],
                            'owasp_category': self._get_owasp_category(category),
                            'remediation': self._get_remediation(category),
                            'file_path': file_path
                        })
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error in pattern recognition: {str(e)}")
            return []
    
    def _get_owasp_category(self, category: str) -> str:
        """Map vulnerability category to OWASP Top 10"""
        mapping = {
            'sql_injection': 'A03:2021 - Injection',
            'xss': 'A03:2021 - Injection (XSS)',
            'command_injection': 'A03:2021 - Injection',
            'code_injection': 'A03:2021 - Injection',
            'path_traversal': 'A01:2021 - Broken Access Control',
            'insecure_crypto': 'A02:2021 - Cryptographic Failures',
            'hardcoded_secrets': 'A02:2021 - Cryptographic Failures',
            'deserialization': 'A08:2021 - Software and Data Integrity Failures',
            'race_condition': 'A04:2021 - Insecure Design',
            'xxe': 'A05:2021 - Security Misconfiguration'
        }
        return mapping.get(category, 'A04:2021 - Insecure Design')
    
    def _get_remediation(self, category: str) -> str:
        """Get remediation advice for category"""
        remediations = {
            'sql_injection': 'Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.',
            'xss': 'Sanitize user input and use safe methods like textContent. Implement Content Security Policy (CSP).',
            'command_injection': 'Avoid system commands when possible. Use safe APIs and validate/sanitize all inputs.',
            'code_injection': 'Never use eval() or exec() with user input. Use safe alternatives like JSON.parse().',
            'path_traversal': 'Validate and sanitize file paths. Use allowlists and resolve paths to prevent directory traversal.',
            'insecure_crypto': 'Use strong cryptographic algorithms like SHA-256, SHA-3, or bcrypt for passwords.',
            'hardcoded_secrets': 'Use environment variables or secure secret management systems. Never commit secrets to code.',
            'deserialization': 'Avoid deserializing untrusted data. Use safe alternatives and validate data structure.',
            'race_condition': 'Use atomic operations or proper locking mechanisms to prevent TOCTOU vulnerabilities.',
            'xxe': 'Disable external entity processing in XML parsers. Use defusedxml library in Python.'
        }
        return remediations.get(category, 'Review code and implement security best practices.')
