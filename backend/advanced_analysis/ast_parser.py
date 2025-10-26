"""Multi-Language AST Parser"""
import ast
import re
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

class MultiLanguageASTParser:
    """Parse source code into Abstract Syntax Trees for multiple languages"""
    
    def __init__(self):
        self.supported_languages = ['python', 'javascript', 'typescript', 'java', 'go', 'rust']
    
    def parse(self, code: str, language: str) -> Dict[str, Any]:
        """Parse code into AST based on language"""
        language = language.lower()
        
        if language not in self.supported_languages:
            logger.warning(f"Language {language} not fully supported for AST parsing")
            return self._basic_parse(code, language)
        
        try:
            if language == 'python':
                return self._parse_python(code)
            elif language in ['javascript', 'typescript']:
                return self._parse_javascript(code, language)
            elif language == 'java':
                return self._parse_java(code)
            elif language == 'go':
                return self._parse_go(code)
            elif language == 'rust':
                return self._parse_rust(code)
            else:
                return self._basic_parse(code, language)
        except Exception as e:
            logger.error(f"Error parsing {language} code: {str(e)}")
            return self._basic_parse(code, language)
    
    def _parse_python(self, code: str) -> Dict[str, Any]:
        """Parse Python code using built-in AST module"""
        try:
            tree = ast.parse(code)
            return {
                'language': 'python',
                'ast': tree,
                'functions': self._extract_python_functions(tree),
                'variables': self._extract_python_variables(tree),
                'imports': self._extract_python_imports(tree),
                'calls': self._extract_python_calls(tree),
                'raw_ast': ast.dump(tree)
            }
        except SyntaxError as e:
            logger.error(f"Python syntax error: {e}")
            return self._basic_parse(code, 'python')
    
    def _extract_python_functions(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Extract function definitions from Python AST"""
        functions = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                functions.append({
                    'name': node.name,
                    'line': node.lineno,
                    'args': [arg.arg for arg in node.args.args],
                    'decorators': [d.id if isinstance(d, ast.Name) else str(d) for d in node.decorator_list]
                })
        return functions
    
    def _extract_python_variables(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Extract variable assignments from Python AST"""
        variables = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        variables.append({
                            'name': target.id,
                            'line': node.lineno,
                            'type': 'assignment'
                        })
        return variables
    
    def _extract_python_imports(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Extract imports from Python AST"""
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append({
                        'module': alias.name,
                        'alias': alias.asname,
                        'line': node.lineno
                    })
            elif isinstance(node, ast.ImportFrom):
                imports.append({
                    'module': node.module,
                    'names': [alias.name for alias in node.names],
                    'line': node.lineno
                })
        return imports
    
    def _extract_python_calls(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Extract function calls from Python AST"""
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                else:
                    func_name = 'unknown'
                
                calls.append({
                    'function': func_name,
                    'line': node.lineno,
                    'args_count': len(node.args)
                })
        return calls
    
    def _parse_javascript(self, code: str, language: str) -> Dict[str, Any]:
        """Parse JavaScript/TypeScript using regex patterns (simplified)"""
        return {
            'language': language,
            'functions': self._extract_js_functions(code),
            'variables': self._extract_js_variables(code),
            'imports': self._extract_js_imports(code),
            'calls': self._extract_js_calls(code),
            'patterns': self._extract_js_patterns(code)
        }
    
    def _extract_js_functions(self, code: str) -> List[Dict[str, Any]]:
        """Extract JavaScript function definitions"""
        functions = []
        # Match function declarations
        func_pattern = r'(?:function|async\s+function)\s+(\w+)\s*\(([^)]*)\)'
        for match in re.finditer(func_pattern, code):
            line = code[:match.start()].count('\n') + 1
            functions.append({
                'name': match.group(1),
                'line': line,
                'params': [p.strip() for p in match.group(2).split(',') if p.strip()]
            })
        # Match arrow functions
        arrow_pattern = r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>'
        for match in re.finditer(arrow_pattern, code):
            line = code[:match.start()].count('\n') + 1
            functions.append({
                'name': match.group(1),
                'line': line,
                'params': [p.strip() for p in match.group(2).split(',') if p.strip()],
                'type': 'arrow'
            })
        return functions
    
    def _extract_js_variables(self, code: str) -> List[Dict[str, Any]]:
        """Extract JavaScript variable declarations"""
        variables = []
        var_pattern = r'(?:const|let|var)\s+(\w+)'
        for match in re.finditer(var_pattern, code):
            line = code[:match.start()].count('\n') + 1
            variables.append({
                'name': match.group(1),
                'line': line
            })
        return variables
    
    def _extract_js_imports(self, code: str) -> List[Dict[str, Any]]:
        """Extract JavaScript imports"""
        imports = []
        # ES6 imports
        import_pattern = r'import\s+(?:{([^}]+)}|([\w]+))\s+from\s+["\']([^"\']+)["\']'
        for match in re.finditer(import_pattern, code):
            line = code[:match.start()].count('\n') + 1
            imports.append({
                'module': match.group(3),
                'names': match.group(1).split(',') if match.group(1) else [match.group(2)],
                'line': line
            })
        # require statements
        require_pattern = r'(?:const|let|var)\s+(\w+)\s*=\s*require\(["\']([^"\']+)["\']\)'
        for match in re.finditer(require_pattern, code):
            line = code[:match.start()].count('\n') + 1
            imports.append({
                'module': match.group(2),
                'names': [match.group(1)],
                'line': line,
                'type': 'require'
            })
        return imports
    
    def _extract_js_calls(self, code: str) -> List[Dict[str, Any]]:
        """Extract JavaScript function calls"""
        calls = []
        call_pattern = r'(\w+)\s*\('
        for match in re.finditer(call_pattern, code):
            line = code[:match.start()].count('\n') + 1
            calls.append({
                'function': match.group(1),
                'line': line
            })
        return calls
    
    def _extract_js_patterns(self, code: str) -> Dict[str, List[int]]:
        """Extract special patterns from JavaScript"""
        patterns = {
            'eval': [],
            'innerHTML': [],
            'dangerouslySetInnerHTML': [],
            'setTimeout': [],
            'setInterval': []
        }
        for pattern_name, pattern_list in patterns.items():
            for match in re.finditer(pattern_name, code):
                line = code[:match.start()].count('\n') + 1
                pattern_list.append(line)
        return patterns
    
    def _parse_java(self, code: str) -> Dict[str, Any]:
        """Parse Java code using regex patterns"""
        return {
            'language': 'java',
            'classes': self._extract_java_classes(code),
            'methods': self._extract_java_methods(code),
            'variables': self._extract_java_variables(code),
            'imports': self._extract_java_imports(code)
        }
    
    def _extract_java_classes(self, code: str) -> List[Dict[str, Any]]:
        """Extract Java class definitions"""
        classes = []
        class_pattern = r'(?:public|private|protected)?\s*(?:static)?\s*class\s+(\w+)'
        for match in re.finditer(class_pattern, code):
            line = code[:match.start()].count('\n') + 1
            classes.append({
                'name': match.group(1),
                'line': line
            })
        return classes
    
    def _extract_java_methods(self, code: str) -> List[Dict[str, Any]]:
        """Extract Java method definitions"""
        methods = []
        method_pattern = r'(?:public|private|protected)\s+(?:static\s+)?(?:\w+)\s+(\w+)\s*\(([^)]*)\)'
        for match in re.finditer(method_pattern, code):
            line = code[:match.start()].count('\n') + 1
            methods.append({
                'name': match.group(1),
                'line': line,
                'params': [p.strip() for p in match.group(2).split(',') if p.strip()]
            })
        return methods
    
    def _extract_java_variables(self, code: str) -> List[Dict[str, Any]]:
        """Extract Java variable declarations"""
        variables = []
        var_pattern = r'(?:private|public|protected)?\s*(\w+)\s+(\w+)\s*[=;]'
        for match in re.finditer(var_pattern, code):
            line = code[:match.start()].count('\n') + 1
            variables.append({
                'type': match.group(1),
                'name': match.group(2),
                'line': line
            })
        return variables
    
    def _extract_java_imports(self, code: str) -> List[Dict[str, Any]]:
        """Extract Java imports"""
        imports = []
        import_pattern = r'import\s+([\w.]+);'
        for match in re.finditer(import_pattern, code):
            line = code[:match.start()].count('\n') + 1
            imports.append({
                'package': match.group(1),
                'line': line
            })
        return imports
    
    def _parse_go(self, code: str) -> Dict[str, Any]:
        """Parse Go code using regex patterns"""
        return {
            'language': 'go',
            'functions': self._extract_go_functions(code),
            'imports': self._extract_go_imports(code),
            'structs': self._extract_go_structs(code)
        }
    
    def _extract_go_functions(self, code: str) -> List[Dict[str, Any]]:
        """Extract Go function definitions"""
        functions = []
        func_pattern = r'func\s+(\w+)\s*\(([^)]*)\)'
        for match in re.finditer(func_pattern, code):
            line = code[:match.start()].count('\n') + 1
            functions.append({
                'name': match.group(1),
                'line': line,
                'params': [p.strip() for p in match.group(2).split(',') if p.strip()]
            })
        return functions
    
    def _extract_go_imports(self, code: str) -> List[Dict[str, Any]]:
        """Extract Go imports"""
        imports = []
        import_pattern = r'import\s+"([^"]+)"'
        for match in re.finditer(import_pattern, code):
            line = code[:match.start()].count('\n') + 1
            imports.append({
                'package': match.group(1),
                'line': line
            })
        return imports
    
    def _extract_go_structs(self, code: str) -> List[Dict[str, Any]]:
        """Extract Go struct definitions"""
        structs = []
        struct_pattern = r'type\s+(\w+)\s+struct'
        for match in re.finditer(struct_pattern, code):
            line = code[:match.start()].count('\n') + 1
            structs.append({
                'name': match.group(1),
                'line': line
            })
        return structs
    
    def _parse_rust(self, code: str) -> Dict[str, Any]:
        """Parse Rust code using regex patterns"""
        return {
            'language': 'rust',
            'functions': self._extract_rust_functions(code),
            'imports': self._extract_rust_imports(code),
            'structs': self._extract_rust_structs(code)
        }
    
    def _extract_rust_functions(self, code: str) -> List[Dict[str, Any]]:
        """Extract Rust function definitions"""
        functions = []
        func_pattern = r'fn\s+(\w+)\s*\(([^)]*)\)'
        for match in re.finditer(func_pattern, code):
            line = code[:match.start()].count('\n') + 1
            functions.append({
                'name': match.group(1),
                'line': line,
                'params': [p.strip() for p in match.group(2).split(',') if p.strip()]
            })
        return functions
    
    def _extract_rust_imports(self, code: str) -> List[Dict[str, Any]]:
        """Extract Rust use statements"""
        imports = []
        use_pattern = r'use\s+([\w:]+);'
        for match in re.finditer(use_pattern, code):
            line = code[:match.start()].count('\n') + 1
            imports.append({
                'module': match.group(1),
                'line': line
            })
        return imports
    
    def _extract_rust_structs(self, code: str) -> List[Dict[str, Any]]:
        """Extract Rust struct definitions"""
        structs = []
        struct_pattern = r'struct\s+(\w+)'
        for match in re.finditer(struct_pattern, code):
            line = code[:match.start()].count('\n') + 1
            structs.append({
                'name': match.group(1),
                'line': line
            })
        return structs
    
    def _basic_parse(self, code: str, language: str) -> Dict[str, Any]:
        """Basic parsing fallback for unsupported languages"""
        return {
            'language': language,
            'lines': code.split('\n'),
            'line_count': len(code.split('\n')),
            'functions': [],
            'variables': [],
            'imports': []
        }
