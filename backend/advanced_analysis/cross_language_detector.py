"""Cross-Language Security Gap Detector"""
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)

class CrossLanguageSecurityDetector:
    """Detect security gaps and inconsistencies across language boundaries"""
    
    def __init__(self):
        self.security_contexts = self._initialize_security_contexts()
        self.sanitization_functions = self._initialize_sanitization_functions()
    
    def _initialize_security_contexts(self) -> Dict[str, Dict[str, Any]]:
        """Initialize security context mappings"""
        return {
            'SQL': {
                'dangerous_chars': ["'", '"', ';', '--', '/*', '*/'],
                'escape_rules': {
                    'python': "Use parameterized queries with '?' or '%s' placeholders",
                    'javascript': "Use parameterized queries or ORM escape methods",
                    'java': 'Use PreparedStatement with setString()',
                    'go': 'Use parameterized queries with $1, $2 placeholders',
                    'rust': 'Use parameterized queries with prepared statements'
                }
            },
            'HTML': {
                'dangerous_chars': ['<', '>', '&', '"', "'"],
                'escape_rules': {
                    'python': 'Use html.escape() or template engine auto-escaping',
                    'javascript': 'Use textContent or DOMPurify.sanitize()',
                    'java': 'Use OWASP Java HTML Sanitizer',
                    'go': 'Use html/template package',
                    'rust': 'Use ammonia crate for HTML sanitization'
                }
            },
            'SHELL': {
                'dangerous_chars': ['|', '&', ';', '`', '$', '(', ')', '<', '>'],
                'escape_rules': {
                    'python': 'Use shlex.quote() or avoid shell=True',
                    'javascript': 'Avoid shell execution, use safe subprocess methods',
                    'java': 'Use ProcessBuilder with argument array',
                    'go': 'Use exec.Command with separate arguments',
                    'rust': 'Use std::process::Command with separate arguments'
                }
            },
            'URL': {
                'dangerous_chars': ['../', '../', '%2e%2e%2f'],
                'escape_rules': {
                    'python': 'Use urllib.parse.quote()',
                    'javascript': 'Use encodeURIComponent()',
                    'java': 'Use URLEncoder.encode()',
                    'go': 'Use url.QueryEscape()',
                    'rust': 'Use percent_encoding crate'
                }
            },
            'JSON': {
                'dangerous_patterns': ['__proto__', 'constructor', 'prototype'],
                'escape_rules': {
                    'python': 'Use json.dumps() with safe defaults',
                    'javascript': 'Validate JSON structure, avoid eval()',
                    'java': 'Use Jackson or Gson with type validation',
                    'go': 'Use json.Marshal/Unmarshal with struct validation',
                    'rust': 'Use serde with proper type validation'
                }
            }
        }
    
    def _initialize_sanitization_functions(self) -> Dict[str, Dict[str, List[str]]]:
        """Initialize known sanitization functions per language"""
        return {
            'python': {
                'SQL': ['parameterized queries', 'cursor.execute with ?', 'psycopg2 mogrify'],
                'HTML': ['html.escape', 'markupsafe.escape', 'bleach.clean'],
                'SHELL': ['shlex.quote', 'subprocess without shell=True'],
                'URL': ['urllib.parse.quote', 'urllib.parse.quote_plus'],
                'JSON': ['json.dumps', 'json.loads with validation']
            },
            'javascript': {
                'SQL': ['parameterized queries', 'ORM methods', 'mysql.escape'],
                'HTML': ['textContent', 'DOMPurify.sanitize', 'escape-html'],
                'SHELL': ['avoid shell execution', 'child_process.execFile'],
                'URL': ['encodeURIComponent', 'encodeURI'],
                'JSON': ['JSON.parse with validation', 'JSON.stringify']
            },
            'java': {
                'SQL': ['PreparedStatement', 'setString', 'JPA parameterized'],
                'HTML': ['OWASP Sanitizer', 'StringEscapeUtils.escapeHtml'],
                'SHELL': ['ProcessBuilder with array', 'avoid Runtime.exec string'],
                'URL': ['URLEncoder.encode'],
                'JSON': ['Jackson', 'Gson with TypeToken']
            },
            'go': {
                'SQL': ['$1, $2 placeholders', 'prepared statements'],
                'HTML': ['html/template', 'text/template'],
                'SHELL': ['exec.Command with separate args'],
                'URL': ['url.QueryEscape', 'url.PathEscape'],
                'JSON': ['json.Marshal', 'json.Unmarshal with struct']
            },
            'rust': {
                'SQL': ['prepared statements', 'parameterized queries'],
                'HTML': ['ammonia crate'],
                'SHELL': ['std::process::Command with separate args'],
                'URL': ['percent_encoding crate'],
                'JSON': ['serde with type validation']
            }
        }
    
    def analyze(self, all_files_ir: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze for cross-language security gaps"""
        vulnerabilities = []
        
        try:
            # Group files by language
            files_by_language = {}
            for ir in all_files_ir:
                lang = ir.get('source_language', 'unknown')
                if lang not in files_by_language:
                    files_by_language[lang] = []
                files_by_language[lang].append(ir)
            
            # If only one language, no cross-language analysis needed
            if len(files_by_language) <= 1:
                return []
            
            # Analyze data flows between languages
            for i, ir1 in enumerate(all_files_ir):
                for ir2 in all_files_ir[i+1:]:
                    vulns = self._analyze_boundary(ir1, ir2)
                    vulnerabilities.extend(vulns)
            
            # Check for inconsistent validation
            input_validation_vulns = self._check_input_validation_consistency(all_files_ir)
            vulnerabilities.extend(input_validation_vulns)
            
            # Check for missing sanitization at boundaries
            sanitization_vulns = self._check_sanitization_at_boundaries(all_files_ir)
            vulnerabilities.extend(sanitization_vulns)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error in cross-language analysis: {str(e)}")
            return []
    
    def _analyze_boundary(self, ir1: Dict[str, Any], ir2: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze security at boundary between two languages"""
        vulnerabilities = []
        lang1 = ir1.get('source_language')
        lang2 = ir2.get('source_language')
        
        # Skip if same language
        if lang1 == lang2:
            return []
        
        # Check for function calls crossing boundary
        for call in ir1.get('external_calls', []):
            call_name = call.get('original_name', '')
            category = call.get('category', '')
            
            # Check if this is a dangerous category
            if category in ['DATABASE', 'SYSTEM_COMMAND', 'CODE_EXECUTION']:
                # Check if proper sanitization exists
                context = self._map_category_to_context(category)
                
                if context:
                    lang1_rules = self.security_contexts.get(context, {}).get('escape_rules', {}).get(lang1, '')
                    lang2_rules = self.security_contexts.get(context, {}).get('escape_rules', {}).get(lang2, '')
                    
                    if lang1_rules != lang2_rules:
                        vulnerabilities.append({
                            'type': 'CROSS_LANGUAGE_SECURITY_GAP',
                            'severity': 'high',
                            'title': f'Inconsistent Security Rules at {lang1.title()}-{lang2.title()} Boundary',
                            'description': f'Security rules differ between {lang1} and {lang2} for {context} context. Data sanitized in {lang1} may not be safe in {lang2}.',
                            'from_language': lang1,
                            'to_language': lang2,
                            'security_context': context,
                            'function': call_name,
                            'line': call.get('line'),
                            'lang1_rules': lang1_rules,
                            'lang2_rules': lang2_rules,
                            'cwe_id': 'CWE-20',
                            'owasp_category': 'A04:2021 - Insecure Design',
                            'remediation': f'Ensure data is sanitized according to {lang2} rules before crossing language boundary. {lang2_rules}'
                        })
        
        return vulnerabilities
    
    def _check_input_validation_consistency(self, all_files_ir: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for inconsistent input validation across languages"""
        vulnerabilities = []
        
        # Track input sources by language
        input_by_language = {}
        for ir in all_files_ir:
            lang = ir.get('source_language')
            input_by_language[lang] = ir.get('data_sources', [])
        
        # If multiple languages handle input differently
        if len(input_by_language) > 1:
            languages = list(input_by_language.keys())
            for i, lang1 in enumerate(languages):
                for lang2 in languages[i+1:]:
                    if input_by_language[lang1] and input_by_language[lang2]:
                        vulnerabilities.append({
                            'type': 'INCONSISTENT_INPUT_VALIDATION',
                            'severity': 'medium',
                            'title': f'Inconsistent Input Validation Between {lang1.title()} and {lang2.title()}',
                            'description': f'Input validation may differ between {lang1} and {lang2}, potentially allowing bypass through one language\'s validation.',
                            'from_language': lang1,
                            'to_language': lang2,
                            'cwe_id': 'CWE-20',
                            'owasp_category': 'A04:2021 - Insecure Design',
                            'remediation': 'Standardize input validation rules across all languages in the application. Use a centralized validation service.'
                        })
        
        return vulnerabilities
    
    def _check_sanitization_at_boundaries(self, all_files_ir: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check if data is properly sanitized when crossing boundaries"""
        vulnerabilities = []
        
        for ir in all_files_ir:
            lang = ir.get('source_language')
            
            # Check if dangerous operations exist
            for sink in ir.get('data_sinks', []):
                sink_func = sink.get('function', '')
                category = self._categorize_sink(sink_func)
                
                if category:
                    # Check if appropriate sanitization function is present
                    has_sanitization = self._check_for_sanitization(ir, category, lang)
                    
                    if not has_sanitization:
                        vulnerabilities.append({
                            'type': 'MISSING_BOUNDARY_SANITIZATION',
                            'severity': 'high',
                            'title': f'Missing Sanitization for {category} Context',
                            'description': f'Data may cross into {category} context without proper sanitization in {lang} code',
                            'language': lang,
                            'context': category,
                            'function': sink_func,
                            'line': sink.get('line'),
                            'cwe_id': 'CWE-20',
                            'owasp_category': 'A03:2021 - Injection',
                            'remediation': f'Implement proper sanitization: {self.security_contexts.get(category, {}).get("escape_rules", {}).get(lang, "Use appropriate sanitization")}'
                        })
        
        return vulnerabilities
    
    def _map_category_to_context(self, category: str) -> str:
        """Map call category to security context"""
        mapping = {
            'DATABASE': 'SQL',
            'HTML_MANIPULATION': 'HTML',
            'SYSTEM_COMMAND': 'SHELL',
            'CODE_EXECUTION': 'SHELL'
        }
        return mapping.get(category, '')
    
    def _categorize_sink(self, sink_func: str) -> str:
        """Categorize sink function to security context"""
        sink_lower = sink_func.lower()
        
        if any(x in sink_lower for x in ['query', 'execute', 'sql']):
            return 'SQL'
        elif any(x in sink_lower for x in ['html', 'innerHTML', 'write']):
            return 'HTML'
        elif any(x in sink_lower for x in ['system', 'shell', 'exec', 'command']):
            return 'SHELL'
        
        return ''
    
    def _check_for_sanitization(self, ir: Dict[str, Any], context: str, language: str) -> bool:
        """Check if sanitization functions are present for given context"""
        sanitization_funcs = self.sanitization_functions.get(language, {}).get(context, [])
        
        # Check if any sanitization function is called
        for call in ir.get('external_calls', []):
            call_name = call.get('original_name', '').lower()
            for san_func in sanitization_funcs:
                if san_func.lower() in call_name:
                    return True
        
        return False
