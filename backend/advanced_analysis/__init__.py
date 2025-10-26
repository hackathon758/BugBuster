"""Advanced Cross-Language Vulnerability Analysis Module"""

from .vulnerability_engine import AdvancedVulnerabilityEngine
from .ast_parser import MultiLanguageASTParser
from .unified_representation import UnifiedIRGenerator
from .taint_analysis import TaintAnalyzer
from .pattern_recognition import PatternRecognizer
from .cross_language_detector import CrossLanguageSecurityDetector

__all__ = [
    'AdvancedVulnerabilityEngine',
    'MultiLanguageASTParser',
    'UnifiedIRGenerator',
    'TaintAnalyzer',
    'PatternRecognizer',
    'CrossLanguageSecurityDetector'
]
