"""Unified Intermediate Representation Generator"""
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)

class UnifiedIRGenerator:
    """Generate unified intermediate representation for cross-language analysis"""
    
    def __init__(self):
        self.unified_vocabulary = {
            # Control flow
            'if': 'COND_BRANCH',
            'else': 'ELSE_BRANCH',
            'for': 'LOOP',
            'while': 'LOOP',
            'return': 'RETURN',
            'break': 'BREAK',
            'continue': 'CONTINUE',
            
            # Function related
            'function': 'FUNC_DEF',
            'def': 'FUNC_DEF',
            'fn': 'FUNC_DEF',
            'func': 'FUNC_DEF',
            'call': 'FUNC_CALL',
            
            # Data operations
            'assign': 'ASSIGN',
            '=': 'ASSIGN',
            'variable': 'VAR',
            'const': 'CONST',
            'let': 'VAR',
            'var': 'VAR',
            
            # I/O operations
            'print': 'OUTPUT',
            'console.log': 'OUTPUT',
            'println': 'OUTPUT',
            'input': 'INPUT',
            'read': 'INPUT',
            'scanf': 'INPUT',
            
            # Dangerous operations
            'eval': 'EVAL_CALL',
            'exec': 'EXEC_CALL',
            'system': 'SYSTEM_CALL',
            'shell': 'SHELL_CALL',
            'sql': 'SQL_EXEC',
            'query': 'DB_QUERY'
        }
    
    def generate(self, ast_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate unified IR from language-specific AST"""
        language = ast_data.get('language', 'unknown')
        
        try:
            ir = {
                'source_language': language,
                'nodes': [],
                'control_flow': [],
                'data_flow': [],
                'function_definitions': [],
                'external_calls': [],
                'data_sources': [],
                'data_sinks': []
            }
            
            # Process functions
            if 'functions' in ast_data:
                ir['function_definitions'] = self._process_functions(ast_data['functions'], language)
            
            # Process calls
            if 'calls' in ast_data:
                ir['external_calls'] = self._process_calls(ast_data['calls'], language)
            
            # Process variables
            if 'variables' in ast_data:
                self._process_variables(ast_data['variables'], ir, language)
            
            # Process imports
            if 'imports' in ast_data:
                ir['imports'] = self._process_imports(ast_data['imports'], language)
            
            # Identify data sources and sinks
            self._identify_sources_and_sinks(ast_data, ir)
            
            # Generate control and data flow
            self._generate_flows(ast_data, ir)
            
            return ir
            
        except Exception as e:
            logger.error(f"Error generating IR for {language}: {str(e)}")
            return {'error': str(e), 'source_language': language}
    
    def _process_functions(self, functions: List[Dict], language: str) -> List[Dict]:
        """Convert functions to unified representation"""
        unified_functions = []
        for func in functions:
            unified_functions.append({
                'unified_type': 'FUNC_DEF',
                'name': func.get('name'),
                'line': func.get('line'),
                'parameters': func.get('args') or func.get('params', []),
                'language_tag': f"[{language.upper()}]"
            })
        return unified_functions
    
    def _process_calls(self, calls: List[Dict], language: str) -> List[Dict]:
        """Convert function calls to unified representation"""
        unified_calls = []
        for call in calls:
            func_name = call.get('function', '')
            unified_type = self._map_to_unified(func_name)
            
            unified_calls.append({
                'unified_type': unified_type,
                'original_name': func_name,
                'line': call.get('line'),
                'is_dangerous': self._is_dangerous_call(func_name),
                'category': self._categorize_call(func_name),
                'language_tag': f"[{language.upper()}]"
            })
        return unified_calls
    
    def _process_variables(self, variables: List[Dict], ir: Dict, language: str) -> None:
        """Process variables and add to IR"""
        for var in variables:
            ir['nodes'].append({
                'unified_type': 'VAR',
                'name': var.get('name'),
                'line': var.get('line'),
                'language_tag': f"[{language.upper()}]"
            })
    
    def _process_imports(self, imports: List[Dict], language: str) -> List[Dict]:
        """Process imports/includes"""
        unified_imports = []
        for imp in imports:
            unified_imports.append({
                'unified_type': 'IMPORT',
                'module': imp.get('module') or imp.get('package'),
                'line': imp.get('line'),
                'language_tag': f"[{language.upper()}]"
            })
        return unified_imports
    
    def _identify_sources_and_sinks(self, ast_data: Dict, ir: Dict) -> None:
        """Identify data sources (user input) and sinks (dangerous operations)"""
        sources = [
            'input', 'raw_input', 'stdin', 'argv', 'request', 'query', 'params',
            'body', 'form', 'file', 'upload', 'read', 'readLine', 'scanner',
            'req.body', 'req.query', 'req.params', '$_GET', '$_POST', '$_REQUEST'
        ]
        
        sinks = [
            'eval', 'exec', 'system', 'shell_exec', 'passthru', 'popen',
            'subprocess', 'os.system', 'Runtime.exec', 'innerHTML', 'document.write',
            'dangerouslySetInnerHTML', 'query', 'execute', 'cursor.execute',
            'Statement.execute', 'Connection.prepareStatement'
        ]
        
        if 'calls' in ast_data:
            for call in ast_data['calls']:
                func_name = call.get('function', '').lower()
                
                if any(source in func_name for source in sources):
                    ir['data_sources'].append({
                        'type': 'USER_INPUT',
                        'function': call.get('function'),
                        'line': call.get('line'),
                        'risk': 'high'
                    })
                
                if any(sink in func_name for sink in sinks):
                    ir['data_sinks'].append({
                        'type': 'DANGEROUS_OPERATION',
                        'function': call.get('function'),
                        'line': call.get('line'),
                        'risk': 'critical'
                    })
    
    def _generate_flows(self, ast_data: Dict, ir: Dict) -> None:
        """Generate control flow and data flow graphs"""
        # Build control flow based on function calls and structure
        if 'functions' in ast_data:
            for i, func in enumerate(ast_data['functions']):
                ir['control_flow'].append({
                    'node_id': i,
                    'type': 'function',
                    'name': func.get('name'),
                    'line': func.get('line')
                })
        
        # Build data flow from variables to calls
        if 'variables' in ast_data and 'calls' in ast_data:
            for var in ast_data['variables']:
                for call in ast_data['calls']:
                    if var.get('line', 0) < call.get('line', 0):
                        ir['data_flow'].append({
                            'from': var.get('name'),
                            'to': call.get('function'),
                            'from_line': var.get('line'),
                            'to_line': call.get('line'),
                            'type': 'potential_flow'
                        })
    
    def _map_to_unified(self, token: str) -> str:
        """Map language-specific token to unified vocabulary"""
        token_lower = token.lower()
        
        for key, value in self.unified_vocabulary.items():
            if key in token_lower:
                return value
        
        return 'FUNC_CALL'
    
    def _is_dangerous_call(self, func_name: str) -> bool:
        """Check if function call is potentially dangerous"""
        dangerous = [
            'eval', 'exec', 'system', 'shell', 'passthru', 'popen',
            'innerHTML', 'dangerouslySetInnerHTML', 'query', 'execute'
        ]
        return any(d in func_name.lower() for d in dangerous)
    
    def _categorize_call(self, func_name: str) -> str:
        """Categorize function call by type"""
        func_lower = func_name.lower()
        
        if any(x in func_lower for x in ['eval', 'exec']):
            return 'CODE_EXECUTION'
        elif any(x in func_lower for x in ['system', 'shell', 'command']):
            return 'SYSTEM_COMMAND'
        elif any(x in func_lower for x in ['query', 'execute', 'sql', 'database']):
            return 'DATABASE'
        elif any(x in func_lower for x in ['file', 'open', 'read', 'write']):
            return 'FILE_IO'
        elif any(x in func_lower for x in ['html', 'innerHTML', 'render']):
            return 'HTML_MANIPULATION'
        else:
            return 'GENERAL'
