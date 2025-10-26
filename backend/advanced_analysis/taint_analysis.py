"""Taint Analysis for Cross-Language Vulnerability Detection"""
from typing import Dict, List, Any, Set
import logging

logger = logging.getLogger(__name__)

class TaintAnalyzer:
    """Perform taint analysis to track vulnerable data flow across language boundaries"""
    
    def __init__(self):
        self.tainted_variables: Set[str] = set()
        self.taint_flows: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
    
    def analyze(self, ir_data: Dict[str, Any], all_files_ir: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Perform taint analysis on unified IR"""
        try:
            self.tainted_variables.clear()
            self.taint_flows.clear()
            self.vulnerabilities.clear()
            
            # Step 1: Identify taint sources (user inputs)
            self._mark_sources(ir_data)
            
            # Step 2: Track taint propagation through data flows
            self._track_propagation(ir_data)
            
            # Step 3: Check if tainted data reaches dangerous sinks
            self._check_sinks(ir_data)
            
            # Step 4: Cross-language boundary analysis
            if all_files_ir:
                self._cross_language_analysis(ir_data, all_files_ir)
            
            return {
                'tainted_variables': list(self.tainted_variables),
                'taint_flows': self.taint_flows,
                'vulnerabilities': self.vulnerabilities,
                'risk_score': self._calculate_risk_score()
            }
            
        except Exception as e:
            logger.error(f"Error in taint analysis: {str(e)}")
            return {'error': str(e)}
    
    def _mark_sources(self, ir_data: Dict[str, Any]) -> None:
        """Mark data sources as tainted"""
        for source in ir_data.get('data_sources', []):
            source_name = source.get('function', '')
            self.tainted_variables.add(source_name)
            
            self.taint_flows.append({
                'type': 'SOURCE',
                'variable': source_name,
                'line': source.get('line'),
                'risk': source.get('risk', 'medium')
            })
    
    def _track_propagation(self, ir_data: Dict[str, Any]) -> None:
        """Track how tainted data propagates through the code"""
        data_flows = ir_data.get('data_flow', [])
        
        # Iterate multiple times to catch transitive flows
        changed = True
        iterations = 0
        max_iterations = 10
        
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            
            for flow in data_flows:
                from_var = flow.get('from')
                to_var = flow.get('to')
                
                # If source is tainted and target isn't, propagate taint
                if from_var in self.tainted_variables and to_var not in self.tainted_variables:
                    self.tainted_variables.add(to_var)
                    changed = True
                    
                    self.taint_flows.append({
                        'type': 'PROPAGATION',
                        'from': from_var,
                        'to': to_var,
                        'from_line': flow.get('from_line'),
                        'to_line': flow.get('to_line')
                    })
    
    def _check_sinks(self, ir_data: Dict[str, Any]) -> None:
        """Check if tainted data reaches dangerous sinks"""
        for sink in ir_data.get('data_sinks', []):
            sink_name = sink.get('function', '')
            sink_line = sink.get('line')
            
            # Check if any tainted variable reaches this sink
            for tainted_var in self.tainted_variables:
                # Check data flows leading to this sink
                has_flow = any(
                    flow.get('to') == sink_name or tainted_var in sink_name
                    for flow in ir_data.get('data_flow', [])
                )
                
                if has_flow or self._check_proximity(ir_data, tainted_var, sink_name):
                    severity = self._determine_severity(sink_name, sink.get('type'))
                    
                    self.vulnerabilities.append({
                        'type': 'TAINT_SINK',
                        'severity': severity,
                        'title': f'Tainted Data Reaches {sink.get("type", "Dangerous Operation")}',
                        'description': f'User-controlled data from {tainted_var} may reach dangerous operation {sink_name} without proper sanitization',
                        'tainted_variable': tainted_var,
                        'sink_function': sink_name,
                        'line': sink_line,
                        'cwe_id': self._get_cwe_for_sink(sink_name),
                        'owasp_category': self._get_owasp_for_sink(sink_name),
                        'remediation': self._get_remediation(sink_name)
                    })
    
    def _cross_language_analysis(self, current_ir: Dict[str, Any], all_files_ir: List[Dict[str, Any]]) -> None:
        """Analyze taint flows across language boundaries"""
        current_lang = current_ir.get('source_language')
        
        for other_ir in all_files_ir:
            other_lang = other_ir.get('source_language')
            
            # Skip same language or same file
            if other_lang == current_lang:
                continue
            
            # Check for cross-language data flows
            self._check_cross_language_flow(current_ir, other_ir)
    
    def _check_cross_language_flow(self, ir1: Dict[str, Any], ir2: Dict[str, Any]) -> None:
        """Check for data flows between two different languages"""
        # Look for function calls that might cross boundaries
        lang1 = ir1.get('source_language')
        lang2 = ir2.get('source_language')
        
        # Check if functions from ir1 might call into ir2
        for call in ir1.get('external_calls', []):
            call_name = call.get('original_name', '')
            
            # Check if this call matches a function in ir2
            for func in ir2.get('function_definitions', []):
                if func.get('name') == call_name:
                    # Potential cross-language call
                    if call.get('is_dangerous'):
                        self.vulnerabilities.append({
                            'type': 'CROSS_LANGUAGE_BOUNDARY',
                            'severity': 'high',
                            'title': f'Cross-Language Call to Dangerous Function',
                            'description': f'Code in {lang1} calls dangerous function {call_name} in {lang2}',
                            'from_language': lang1,
                            'to_language': lang2,
                            'function': call_name,
                            'line': call.get('line'),
                            'cwe_id': 'CWE-501',
                            'owasp_category': 'A04:2021 - Insecure Design',
                            'remediation': 'Implement proper input validation and sanitization at language boundaries'
                        })
    
    def _check_proximity(self, ir_data: Dict[str, Any], var_name: str, sink_name: str) -> bool:
        """Check if variable and sink are in close proximity (heuristic)"""
        # Find variable line
        var_line = None
        for var in ir_data.get('nodes', []):
            if var.get('name') == var_name:
                var_line = var.get('line')
                break
        
        # Find sink line  
        sink_line = None
        for sink in ir_data.get('data_sinks', []):
            if sink.get('function') == sink_name:
                sink_line = sink.get('line')
                break
        
        # If within 10 lines, consider it related
        if var_line and sink_line:
            return abs(var_line - sink_line) <= 10
        
        return False
    
    def _determine_severity(self, sink_name: str, sink_type: str) -> str:
        """Determine vulnerability severity based on sink type"""
        critical_sinks = ['eval', 'exec', 'system', 'shell_exec']
        high_sinks = ['query', 'execute', 'innerHTML', 'dangerouslySetInnerHTML']
        
        sink_lower = sink_name.lower()
        
        if any(s in sink_lower for s in critical_sinks):
            return 'critical'
        elif any(s in sink_lower for s in high_sinks):
            return 'high'
        else:
            return 'medium'
    
    def _get_cwe_for_sink(self, sink_name: str) -> str:
        """Get CWE ID for sink type"""
        sink_lower = sink_name.lower()
        
        if 'eval' in sink_lower or 'exec' in sink_lower:
            return 'CWE-95'
        elif 'system' in sink_lower or 'shell' in sink_lower:
            return 'CWE-78'
        elif 'query' in sink_lower or 'execute' in sink_lower:
            return 'CWE-89'
        elif 'innerHTML' in sink_lower or 'html' in sink_lower:
            return 'CWE-79'
        else:
            return 'CWE-20'
    
    def _get_owasp_for_sink(self, sink_name: str) -> str:
        """Get OWASP category for sink type"""
        sink_lower = sink_name.lower()
        
        if 'eval' in sink_lower or 'exec' in sink_lower or 'system' in sink_lower:
            return 'A03:2021 - Injection'
        elif 'query' in sink_lower or 'sql' in sink_lower:
            return 'A03:2021 - Injection'
        elif 'innerHTML' in sink_lower or 'html' in sink_lower:
            return 'A03:2021 - Injection (XSS)'
        else:
            return 'A04:2021 - Insecure Design'
    
    def _get_remediation(self, sink_name: str) -> str:
        """Get remediation advice for sink type"""
        sink_lower = sink_name.lower()
        
        if 'eval' in sink_lower or 'exec' in sink_lower:
            return 'Avoid using eval/exec. Use safe alternatives like JSON.parse() or ast.literal_eval()'
        elif 'system' in sink_lower or 'shell' in sink_lower:
            return 'Validate and sanitize all inputs. Use parameterized commands or safe subprocess calls'
        elif 'query' in sink_lower or 'execute' in sink_lower:
            return 'Use parameterized queries or prepared statements to prevent SQL injection'
        elif 'innerHTML' in sink_lower:
            return 'Use textContent instead of innerHTML, or sanitize HTML with a library like DOMPurify'
        else:
            return 'Implement input validation and sanitization before using user data'
    
    def _calculate_risk_score(self) -> int:
        """Calculate overall risk score based on findings"""
        if not self.vulnerabilities:
            return 0
        
        score = 0
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'low')
            if severity == 'critical':
                score += 25
            elif severity == 'high':
                score += 15
            elif severity == 'medium':
                score += 8
            else:
                score += 3
        
        return min(score, 100)
