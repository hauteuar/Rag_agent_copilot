"""
COBOL RAG MCP Agent - Complete Implementation
==============================================
A comprehensive system for parsing COBOL/JCL code, building semantic indexes,
creating program call graphs, and serving queries via MCP protocol.

Installation Requirements:
pip install tree-sitter sentence-transformers faiss-cpu networkx numpy PyPDF2 python-docx markdown beautifulsoup4
"""

import os
import json
import sys
import re
import pickle
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

# Tree-sitter imports
try:
    from tree_sitter import Language, Parser
except ImportError:
    print("Please install: pip install tree-sitter")

# Vector search
try:
    import faiss
    import numpy as np
    from sentence_transformers import SentenceTransformer
except ImportError:
    print("Please install: pip install faiss-cpu sentence-transformers")
    sys.exit(1)

# Graph
try:
    import networkx as nx
except ImportError:
    print("Please install: pip install networkx")
    sys.exit(1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class CodeChunk:
    """Represents a chunk of code with metadata"""
    id: str
    source_file: str
    content: str
    chunk_type: str  # 'program', 'paragraph', 'section', 'copybook', 'document'
    line_start: int
    line_end: int
    metadata: Dict[str, Any]


@dataclass
class GraphNode:
    """Represents a node in the program call graph"""
    id: str
    node_type: str  # 'program', 'paragraph', 'table', 'mq_queue', 'file'
    name: str
    source_file: str
    metadata: Dict[str, Any]


@dataclass
class FlowDiagram:
    """Represents a Mermaid flow diagram"""
    mermaid_code: str
    nodes: List[str]
    edges: List[Tuple[str, str, str]]


# ============================================================================
# TREE-SITTER COBOL PARSER
# ============================================================================

class COBOLParser:
    """
    Enhanced COBOL Parser with complete call detection
    
    Detects:
    - Static CALL statements
    - Dynamic CALL statements (with variable resolution)
    - CICS LINK (static and dynamic)
    - CICS XCTL (static and dynamic)
    - Multi-line CICS commands
    - DB2 operations
    - MQ operations
    """
    
    def __init__(self):
        self.parser = None
        self._init_parser()
    
    def _init_parser(self):
        """Initialize Tree-Sitter parser for COBOL (if available)"""
        try:
            from tree_sitter import Language, Parser
            COBOL_LANGUAGE = Language('build/cobol.so', 'cobol')
            self.parser = Parser()
            self.parser.set_language(COBOL_LANGUAGE)
            logger.info("✓ Tree-Sitter COBOL parser initialized")
        except Exception as e:
            logger.warning(f"Tree-sitter COBOL not available: {e}")
            logger.info("Using heuristic parser (fully functional)")
            self.parser = None
    
    def parse_cobol(self, source_code: str, filename: str) -> List[CodeChunk]:
        """Parse COBOL source code into structured chunks"""
        if self.parser:
            return self._parse_with_treesitter(source_code, filename)
        else:
            return self._parse_with_heuristics(source_code, filename)
    
    def _parse_with_heuristics(self, source_code: str, filename: str) -> List[CodeChunk]:
        """Fallback heuristic parser for COBOL"""
        chunks = []
        lines = source_code.split('\n')
        
        # Extract PROGRAM-ID
        program_id = "UNKNOWN"
        for i, line in enumerate(lines):
            if 'PROGRAM-ID' in line.upper():
                match = re.search(r'PROGRAM-ID\.\s+(\S+)', line, re.IGNORECASE)
                if match:
                    program_id = match.group(1).strip('.')
                    break
        
        # Extract divisions
        current_division = None
        division_start = 0
        
        for i, line in enumerate(lines):
            clean_line = line[6:72].strip() if len(line) > 6 else line.strip()
            
            if re.match(r'^\s*(IDENTIFICATION|ENVIRONMENT|DATA|PROCEDURE)\s+DIVISION', 
                       clean_line, re.IGNORECASE):
                if current_division:
                    chunks.append(CodeChunk(
                        id=f"{program_id}::{current_division}",
                        source_file=filename,
                        content='\n'.join(lines[division_start:i]),
                        chunk_type='division',
                        line_start=division_start,
                        line_end=i,
                        metadata={'program_id': program_id, 'division': current_division}
                    ))
                current_division = clean_line.split()[0]
                division_start = i
        
        # Extract paragraphs
        paragraph_pattern = re.compile(r'^([A-Z0-9][\w-]*)\s*\.\s*$')
        current_para = None
        para_start = 0
        
        for i, line in enumerate(lines):
            clean_line = line[6:72].strip() if len(line) > 6 else line.strip()
            
            if paragraph_pattern.match(clean_line):
                if current_para:
                    chunks.append(CodeChunk(
                        id=f"{program_id}::{current_para}",
                        source_file=filename,
                        content='\n'.join(lines[para_start:i]),
                        chunk_type='paragraph',
                        line_start=para_start,
                        line_end=i,
                        metadata={'program_id': program_id, 'paragraph': current_para}
                    ))
                current_para = paragraph_pattern.match(clean_line).group(1)
                para_start = i
        
        return chunks
    
    # ============================================================================
    # ENHANCED CALL EXTRACTION - Main Method
    # ============================================================================
    
    def extract_calls(self, source_code: str) -> List[Dict[str, Any]]:
        """
        Extract ALL program calls:
        - Regular CALL (static: CALL 'PROG', dynamic: CALL WS-VAR)
        - CICS LINK (static: PROGRAM('PROG'), dynamic: PROGRAM(WS-VAR))
        - CICS XCTL (static: PROGRAM('PROG'), dynamic: PROGRAM(WS-VAR))
        
        Returns list of call dictionaries with:
        - type: 'static', 'dynamic', 'cics_link', 'cics_xctl', etc.
        - call_mechanism: STATIC_CALL, DYNAMIC_CALL, CICS_LINK, CICS_XCTL, etc.
        - target: Program name or variable name
        - variable: Variable name (for dynamic calls)
        - is_dynamic: Boolean
        - possible_targets: List of resolved program names (for dynamic)
        - resolution_details: Details of MOVE statements found
        """
        calls = []
        lines = source_code.split('\n')
        
        # Track multi-line CICS statements
        in_cics_statement = False
        cics_buffer = []
        cics_start_line = 0
        
        logger.debug(f"Starting call extraction, {len(lines)} lines")
        
        for i, line in enumerate(lines, 1):
            line_upper = line.upper().strip()
            clean_line = line[6:72] if len(line) > 6 else line
            
            # Handle multi-line CICS statements
            if 'EXEC CICS' in line_upper or in_cics_statement:
                if 'EXEC CICS' in line_upper and not in_cics_statement:
                    in_cics_statement = True
                    cics_buffer = [line]
                    cics_start_line = i
                elif in_cics_statement:
                    cics_buffer.append(line)
                
                if 'END-EXEC' in line_upper:
                    # Process complete CICS statement
                    full_cics = ' '.join(cics_buffer)
                    cics_calls = self._extract_cics_program_calls(full_cics, cics_start_line)
                    calls.extend(cics_calls)
                    
                    in_cics_statement = False
                    cics_buffer = []
                    cics_start_line = 0
                continue
            
            # Extract regular CALL statements
            if 'CALL' in line_upper:
                regular_calls = self._extract_regular_call_statements(clean_line, i)
                calls.extend(regular_calls)
        
        logger.info(f"Found {len(calls)} calls before resolution")
        
        # Resolve dynamic calls by analyzing MOVE statements
        calls = self._resolve_dynamic_call_variables(calls, source_code)
        
        logger.info(f"Extracted {len(calls)} total program calls")
        self._log_call_summary(calls)
        
        return calls
    
    # ============================================================================
    # CICS Program Call Extraction
    # ============================================================================
    
    def _extract_cics_program_calls(self, cics_statement: str, line_num: int) -> List[Dict[str, Any]]:
        """
        Extract CICS LINK and XCTL calls with program names.
        Handles both:
        - Static: EXEC CICS LINK PROGRAM('LITERAL')
        - Dynamic: EXEC CICS LINK PROGRAM(VARIABLE)
        """
        calls = []
        
        # Define patterns for CICS calls
        cics_patterns = {
            'CICS_LINK': {
                'static': re.compile(
                    r"EXEC\s+CICS\s+LINK\s+.*?PROGRAM\s*\(\s*['\"]([A-Z0-9\-]+)['\"]\s*\)",
                    re.IGNORECASE | re.DOTALL
                ),
                'dynamic': re.compile(
                    r"EXEC\s+CICS\s+LINK\s+.*?PROGRAM\s*\(\s*([A-Z0-9\-]+)\s*\)",
                    re.IGNORECASE | re.DOTALL
                )
            },
            'CICS_XCTL': {
                'static': re.compile(
                    r"EXEC\s+CICS\s+XCTL\s+.*?PROGRAM\s*\(\s*['\"]([A-Z0-9\-]+)['\"]\s*\)",
                    re.IGNORECASE | re.DOTALL
                ),
                'dynamic': re.compile(
                    r"EXEC\s+CICS\s+XCTL\s+.*?PROGRAM\s*\(\s*([A-Z0-9\-]+)\s*\)",
                    re.IGNORECASE | re.DOTALL
                )
            }
        }
        
        for call_type, patterns in cics_patterns.items():
            # Check if this is the right CICS command type
            if call_type.split('_')[1] not in cics_statement.upper():
                continue
            
            # Try static pattern first (quoted literal)
            match = patterns['static'].search(cics_statement)
            if match:
                calls.append({
                    'type': call_type.lower(),
                    'call_mechanism': call_type,
                    'target': match.group(1),
                    'line': line_num,
                    'source_line': cics_statement.strip(),
                    'is_dynamic': False,
                    'variable': None
                })
                logger.debug(f"Found {call_type}: {match.group(1)} at line {line_num}")
                continue
            
            # Try dynamic pattern (variable)
            match = patterns['dynamic'].search(cics_statement)
            if match and not self._is_quoted_literal(match.group(1)):
                variable_name = match.group(1)
                calls.append({
                    'type': f"{call_type.lower()}_dynamic",
                    'call_mechanism': f"{call_type}_DYNAMIC",
                    'target': variable_name,  # Will be resolved later
                    'line': line_num,
                    'source_line': cics_statement.strip(),
                    'is_dynamic': True,
                    'variable': variable_name
                })
                logger.debug(f"Found {call_type} (dynamic): {variable_name} at line {line_num}")
        
        return calls
    
    # ============================================================================
    # Regular CALL Statement Extraction
    # ============================================================================
    
    def _extract_regular_call_statements(self, line: str, line_num: int) -> List[Dict[str, Any]]:
        """
        Extract regular COBOL CALL statements.
        - Static: CALL 'PROGRAM-NAME'
        - Dynamic: CALL WS-PROGRAM-NAME
        """
        calls = []
        
        # Static CALL pattern: CALL 'LITERAL' or CALL "LITERAL"
        static_pattern = re.compile(r"CALL\s+['\"]([A-Z0-9\-]+)['\"]", re.IGNORECASE)
        match = static_pattern.search(line)
        if match:
            calls.append({
                'type': 'static',
                'call_mechanism': 'STATIC_CALL',
                'target': match.group(1),
                'line': line_num,
                'source_line': line.strip(),
                'is_dynamic': False,
                'variable': None
            })
            logger.debug(f"Found STATIC_CALL: {match.group(1)} at line {line_num}")
            return calls
        
        # Dynamic CALL pattern: CALL VARIABLE-NAME (not quoted)
        dynamic_pattern = re.compile(r"CALL\s+([A-Z0-9\-]+)(?!\s*['\"])", re.IGNORECASE)
        match = dynamic_pattern.search(line)
        if match:
            variable_name = match.group(1)
            
            # Exclude COBOL keywords that shouldn't be treated as variables
            keywords = ['USING', 'RETURNING', 'BY', 'REFERENCE', 'CONTENT', 'VALUE', 
                       'PROCEDURE', 'FUNCTION']
            if variable_name.upper() not in keywords:
                calls.append({
                    'type': 'dynamic',
                    'call_mechanism': 'DYNAMIC_CALL',
                    'target': variable_name,  # Will be resolved later
                    'line': line_num,
                    'source_line': line.strip(),
                    'is_dynamic': True,
                    'variable': variable_name
                })
                logger.debug(f"Found DYNAMIC_CALL: {variable_name} at line {line_num}")
        
        return calls
    
    # ============================================================================
    # Dynamic Call Resolution
    # ============================================================================
    
    def _resolve_dynamic_call_variables(self, calls: List[Dict], source_code: str) -> List[Dict]:
        """
        Resolve dynamic call variables by analyzing MOVE statements.
        Finds all possible values that can be moved to the call variable.
        
        Example:
            IF UPDATE-MODE
                MOVE 'PROG1' TO WS-PROGRAM
            ELSE
                MOVE 'PROG2' TO WS-PROGRAM
            END-IF
            CALL WS-PROGRAM
        
        Result: WS-PROGRAM resolves to ['PROG1', 'PROG2']
        """
        # Build variable value map
        variable_values = {}
        lines = source_code.split('\n')
        current_condition = None
        
        # Pattern for MOVE statements: MOVE 'LITERAL' TO VARIABLE
        # Line 344 - NEW CODE
        # Supports: VARIABLE, VARIABLE(N), VARIABLE.FIELD, VARIABLE(1:8), VARIABLE(N).FIELD
        move_pattern = re.compile(
            r"MOVE\s+['\"]?([A-Z0-9\-]+)['\"]?\s+TO\s+"
            r"([A-Z0-9\-]+(?:\([^)]*\))?(?:\.[A-Z0-9\-]+)?(?:\([^)]*\))?)",
            re.IGNORECASE
        )
        
        logger.debug("Analyzing MOVE statements for variable resolution")
        
        for line_num, line in enumerate(lines, 1):
            clean_line = line[6:72] if len(line) > 6 else line
            line_upper = clean_line.upper().strip()
            
            # Track conditional context (for better debugging)
            if line_upper.startswith('IF '):
                current_condition = line.strip()
            elif line_upper.startswith(('END-IF', 'ELSE')):
                current_condition = None
            elif line_upper.endswith('.') and current_condition:
                current_condition = None
            
            # Find MOVE statements
            match = move_pattern.search(clean_line)
            if match:
                value = match.group(1).strip("'\"")
                variable = match.group(2)
                
                if variable not in variable_values:
                    variable_values[variable] = []
                
                variable_values[variable].append({
                    'value': value,
                    'line': line_num,
                    'condition': current_condition,
                    'source_line': line.strip()
                })
                
                logger.debug(f"Found MOVE: {value} → {variable} at line {line_num}")
        
        # Resolve each dynamic call
        resolved_count = 0
        unresolved_count = 0
        
        for call in calls:
            if call.get('is_dynamic') and call.get('variable'):
                variable = call['variable']
                
                # Direct variable match
                if variable in variable_values:
                    call['possible_targets'] = [v['value'] for v in variable_values[variable]]
                    call['resolution_details'] = variable_values[variable]
                    resolved_count += 1
                    logger.info(f"✓ Resolved {variable} → {call['possible_targets']}")
                    continue
                
                # Check for group variables (e.g., TRANX contains HOLD-TRANX)
                # The variable might be a group item with sub-fields
                found_group = False
                for var_name, values in variable_values.items():
                    if var_name in variable or variable in var_name:
                        # Found a related variable (possibly sub-field)
                        call['possible_targets'] = [v['value'] for v in values]
                        call['resolution_details'] = values
                        call['resolved_via_group'] = var_name
                        resolved_count += 1
                        found_group = True
                        logger.info(f"✓ Resolved {variable} via group {var_name} → {call['possible_targets']}")
                        break
                
                if not found_group:
                    unresolved_count += 1
                    logger.warning(f"✗ Could not resolve variable: {variable} at line {call['line']}")
        
        dynamic_call_count = len([c for c in calls if c.get('is_dynamic')])
        logger.info(f"Dynamic call resolution: {resolved_count}/{dynamic_call_count} resolved, {unresolved_count} unresolved")
        
        return calls
    
    # ============================================================================
    # Helper Methods
    # ============================================================================
    
    def _is_quoted_literal(self, value: str) -> bool:
        """Check if a value is a quoted string literal"""
        stripped = value.strip()
        return (stripped.startswith(("'", '"')) and stripped.endswith(("'", '"')))
    
    def _log_call_summary(self, calls: List[Dict]):
        """Log summary of detected calls"""
        summary = {
            'STATIC_CALL': 0,
            'DYNAMIC_CALL': 0,
            'CICS_LINK': 0,
            'CICS_LINK_DYNAMIC': 0,
            'CICS_XCTL': 0,
            'CICS_XCTL_DYNAMIC': 0
        }
        
        for call in calls:
            mechanism = call.get('call_mechanism', 'UNKNOWN')
            summary[mechanism] = summary.get(mechanism, 0) + 1
        
        logger.info("Call Type Summary:")
        for call_type, count in summary.items():
            if count > 0:
                logger.info(f"  {call_type}: {count}")
    
    # ============================================================================
    # DB2 and Other Extractions (unchanged from original)
    # ============================================================================
    
    def extract_db2_operations(self, source_code: str) -> List[Dict[str, Any]]:
        """Extract DB2 SQL operations"""
        operations = []
        pattern = re.compile(
            r'EXEC\s+SQL\s+(SELECT|INSERT|UPDATE|DELETE).*?FROM\s+(\w+)',
            re.IGNORECASE | re.DOTALL
        )
        
        for match in pattern.finditer(source_code):
            operations.append({
                'type': match.group(1).upper(),
                'table': match.group(2),
                'statement': match.group(0)
            })
        
        return operations
    
    def extract_cics_commands(self, source_code: str) -> List[Dict[str, Any]]:
        """Extract CICS commands with resource names (files, queues)"""
        commands = []
        lines = source_code.split('\n')
        
        in_cics = False
        cics_buffer = []
        cics_start_line = 0
        
        for i, line in enumerate(lines, 1):
            line_upper = line.upper().strip()
            
            if 'EXEC CICS' in line_upper:
                if in_cics:
                    # Process previous CICS statement
                    commands.extend(self._parse_cics_statement(
                        ' '.join(cics_buffer), cics_start_line
                    ))
                
                in_cics = True
                cics_buffer = [line]
                cics_start_line = i
            
            elif in_cics:
                cics_buffer.append(line)
                
                if 'END-EXEC' in line_upper:
                    # Process complete CICS statement
                    full_statement = ' '.join(cics_buffer)
                    commands.extend(self._parse_cics_statement(full_statement, cics_start_line))
                    
                    in_cics = False
                    cics_buffer = []
        
        return commands

    def _parse_cics_statement(self, statement: str, line_num: int) -> List[Dict[str, Any]]:
        """Parse a single CICS statement to extract command and resource"""
        commands = []
        
        # Extract CICS command (READ, WRITE, DELETE, etc.)
        cmd_match = re.search(r'EXEC\s+CICS\s+(\w+)', statement, re.IGNORECASE)
        if not cmd_match:
            return commands
        
        command = cmd_match.group(1).upper()
        
        # Extract resource name (DATASET, FILE, or QUEUE)
        resource_match = re.search(
            r"(?:DATASET|FILE|QUEUE)\s*\(\s*['\"]?([A-Z0-9\-_]+)['\"]?\s*\)",
            statement,
            re.IGNORECASE
        )
        
        resource = resource_match.group(1) if resource_match else None
        
        commands.append({
            'command': command,
            'resource': resource,  # ← NEW: Actual file/queue name
            'resource_type': self._detect_resource_type(command, resource),
            'line': line_num,
            'source_line': statement.strip()
        })
        
        return commands

    def _detect_resource_type(self, command: str, resource: str) -> str:
        """Determine if resource is DATASET, FILE, or QUEUE"""
        if not resource:
            return 'UNKNOWN'
        
        # Queue names often end with -Q or contain QUEUE
        if resource.endswith('-Q') or 'QUEUE' in resource.upper():
            return 'QUEUE'
        
        # Files typically have logical names
        if 'FILE' in resource.upper() or 'DATASET' in resource.upper():
            return 'FILE'
        
        # Default: classify by command type
        if command in ['PUT', 'GET', 'RETRIEVE']:
            return 'QUEUE'
        else:
            return 'FILE'
        
    def extract_mq_operations(self, source_code: str) -> List[Dict[str, Any]]:
        """Extract MQ operations"""
        operations = []
        pattern = re.compile(
            r'(MQOPEN|MQGET|MQPUT|MQCLOSE)\s*\(',
            re.IGNORECASE
        )
        
        for match in pattern.finditer(source_code):
            operations.append({
                'operation': match.group(1).upper(),
                'statement': match.group(0)
            })
        
        return operations
    
    def extract_dynamic_calls_advanced(self, source_code: str) -> List[Dict[str, Any]]:
        """
        Compatibility wrapper for batch_parser.py
        This method now calls the enhanced extract_calls() which handles everything
        """
        # Call the enhanced method that handles all call types
        all_calls = self.extract_calls(source_code)
        
        # Filter to only return dynamic calls for backward compatibility
        dynamic_calls = [
            call for call in all_calls 
            if call.get('is_dynamic', False)
        ]
        
        logger.info(f"extract_dynamic_calls_advanced: Found {len(dynamic_calls)} dynamic calls")
        return dynamic_calls

# ============================================================================
# DYNAMIC CALL RESOLVER
# ============================================================================

class DynamicCallResolver:
    """
    Advanced resolver for dynamic CALL statements in COBOL.
    Analyzes data structures and conditional logic to find all possible targets.
    """
    
    def __init__(self):
        self.call_patterns = []
    
    def analyze_program(self, source_code: str) -> Dict[str, List[str]]:
        """
        Analyze entire program for dynamic calls.
        Returns dict mapping variables to possible program names.
        """
        results = {}
        
        # Find all dynamic CALL statements
        dynamic_calls = self._find_dynamic_calls(source_code)
        
        for call_var in dynamic_calls:
            # Find all possible values for this variable
            possible_values = self._resolve_variable_values(source_code, call_var)
            if possible_values:
                results[call_var] = possible_values
        
        return results
    
    def _find_dynamic_calls(self, source_code: str) -> List[str]:
        """Find all dynamic CALL statements"""
        dynamic_calls = []
        
        # Pattern: CALL variable-name
        pattern = re.compile(r'CALL\s+([A-Z][A-Z0-9-]*)\s+USING', re.IGNORECASE)
        
        for match in pattern.finditer(source_code):
            var_name = match.group(1)
            # Check it's not a literal
            if not var_name.startswith("'") and not var_name.startswith('"'):
                dynamic_calls.append(var_name)
        
        return list(set(dynamic_calls))
    
    def _resolve_variable_values(self, source_code: str, variable: str) -> List[str]:
        """
        Resolve all possible values for a variable.
        Handles:
        - MOVE statements
        - VALUE clauses in data structures
        - Conditional assignments
        """
        possible_values = []
        
        # Method 1: MOVE 'LITERAL' TO variable
        move_pattern = re.compile(
            rf"MOVE\s+['\"]([A-Z0-9]+)['\"]\s+TO\s+{variable}",
            re.IGNORECASE
        )
        for match in move_pattern.finditer(source_code):
            possible_values.append(match.group(1))
        
        # Method 2: VALUE clause in data structure
        # Pattern: 05 variable PIC X(8) VALUE 'PROGRAM'.
        value_pattern = re.compile(
            rf"\d+\s+{variable}\s+PIC\s+X\(\d+\)\s+VALUE\s+['\"]([A-Z0-9]+)['\"]",
            re.IGNORECASE
        )
        for match in value_pattern.finditer(source_code):
            possible_values.append(match.group(1))
        
        # Method 3: Group-level VALUE with FILLER
        # Pattern:
        # 01 PROGRAM-TABLE.
        #    05 FILLER PIC X(8) VALUE 'PROG1'.
        #    05 FILLER PIC X(8) VALUE 'PROG2'.
        # ...
        # MOVE PROGRAM-TABLE(INDEX) TO variable
        
        # Find if this variable is part of a table/group
        group_pattern = self._find_group_values(source_code, variable)
        possible_values.extend(group_pattern)
        
        # Method 4: STRING/UNSTRING operations
        string_pattern = re.compile(
            rf"STRING\s+['\"]([A-Z0-9]+)['\"]\s+.*?INTO\s+{variable}",
            re.IGNORECASE | re.DOTALL
        )
        for match in string_pattern.finditer(source_code):
            possible_values.append(match.group(1))
        
        return list(set(possible_values))
    
    def _find_group_values(self, source_code: str, variable: str) -> List[str]:
        """
        Find values from group-level structures.
        Example:
        01 PROGRAM-GROUP.
           05 FILLER VALUE 'TMS'.
           05 PROG-NAME PIC X(5).
        """
        values = []
        
        # Find the group this variable belongs to
        # Look for pattern like: nn variable-name PIC ...
        var_pattern = re.compile(
            rf"(\d+)\s+{variable}\s+PIC",
            re.IGNORECASE
        )
        
        match = var_pattern.search(source_code)
        if not match:
            return values
        
        level = match.group(1)
        
        # Find the parent group (01 level)
        # Work backwards to find 01 level
        lines = source_code[:match.start()].split('\n')
        group_name = None
        
        for line in reversed(lines):
            group_match = re.match(r'\s*01\s+([A-Z][A-Z0-9-]*)', line, re.IGNORECASE)
            if group_match:
                group_name = group_match.group(1)
                break
        
        if not group_name:
            return values
        
        # Now find all FILLER values in this group
        group_pattern = re.compile(
            rf"01\s+{group_name}.*?(?=01\s|\Z)",
            re.IGNORECASE | re.DOTALL
        )
        
        group_match = group_pattern.search(source_code)
        if group_match:
            group_text = group_match.group(0)
            
            # Find all FILLER VALUE entries
            filler_pattern = re.compile(
                r"\d+\s+FILLER.*?VALUE\s+['\"]([A-Z0-9]+)['\"]",
                re.IGNORECASE
            )
            
            for filler_match in filler_pattern.finditer(group_text):
                values.append(filler_match.group(1))
        
        return values


# Update the COBOLParser class to use DynamicCallResolver
# Add this method to COBOLParser class:

   
    
# ============================================================================
# JCL PARSER
# ============================================================================

class JCLParser:
    """Parse JCL (Job Control Language)"""
    
    def parse_jcl(self, source_code: str, filename: str) -> List[CodeChunk]:
        """Parse JCL into structured chunks"""
        chunks = []
        lines = source_code.split('\n')
        
        job_name = None
        current_step = None
        step_start = 0
        
        for i, line in enumerate(lines):
            if line.startswith('//*'):
                continue
            
            if line.startswith('//') and ' JOB ' in line:
                job_match = re.match(r'//(\w+)\s+JOB', line)
                if job_match:
                    job_name = job_match.group(1)
            
            if line.startswith('//') and ' EXEC ' in line:
                if current_step:
                    chunks.append(CodeChunk(
                        id=f"{job_name}::{current_step}",
                        source_file=filename,
                        content='\n'.join(lines[step_start:i]),
                        chunk_type='jcl_step',
                        line_start=step_start,
                        line_end=i,
                        metadata={'job_name': job_name, 'step': current_step}
                    ))
                
                step_match = re.match(r'//(\w+)\s+EXEC', line)
                if step_match:
                    current_step = step_match.group(1)
                    step_start = i
        
        return chunks
    
    def extract_programs(self, source_code: str) -> List[str]:
        """Extract program names from JCL EXEC statements"""
        programs = []
        
        pgm_pattern = re.compile(r'EXEC\s+(?:PGM=|PROC=)(\w+)', re.IGNORECASE)
        
        for match in pgm_pattern.finditer(source_code):
            programs.append(match.group(1))
        
        return programs


# ============================================================================
# DOCUMENT PARSER
# ============================================================================

class DocumentParser:
    """Parse various document formats (PDF, Word, Markdown, Text, HTML)"""
    
    def __init__(self):
        self.chunk_size = 1000  # characters per chunk
        self.chunk_overlap = 200
    
    def parse_pdf(self, filepath: str) -> List[CodeChunk]:
        """Parse PDF document"""
        try:
            import PyPDF2
            chunks = []
            
            with open(filepath, 'rb') as f:
                pdf_reader = PyPDF2.PdfReader(f)
                full_text = ""
                
                for page_num, page in enumerate(pdf_reader.pages):
                    full_text += f"\n--- Page {page_num + 1} ---\n"
                    full_text += page.extract_text()
            
            # Split into chunks
            chunks = self._split_into_chunks(full_text, filepath, 'pdf')
            logger.info(f"Parsed PDF: {filepath} -> {len(chunks)} chunks")
            return chunks
            
        except Exception as e:
            logger.error(f"Failed to parse PDF {filepath}: {e}")
            return []
    
    def parse_word(self, filepath: str) -> List[CodeChunk]:
        """Parse Word document"""
        try:
            import docx
            chunks = []
            
            doc = docx.Document(filepath)
            full_text = ""
            
            for para in doc.paragraphs:
                full_text += para.text + "\n"
            
            chunks = self._split_into_chunks(full_text, filepath, 'docx')
            logger.info(f"Parsed Word: {filepath} -> {len(chunks)} chunks")
            return chunks
            
        except Exception as e:
            logger.error(f"Failed to parse Word {filepath}: {e}")
            return []
    
    def parse_markdown(self, filepath: str) -> List[CodeChunk]:
        """Parse Markdown document"""
        try:
            import markdown
            from bs4 import BeautifulSoup
            
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                md_text = f.read()
            
            # Convert to HTML then extract text
            html = markdown.markdown(md_text)
            soup = BeautifulSoup(html, 'html.parser')
            text = soup.get_text()
            
            chunks = self._split_into_chunks(text, filepath, 'markdown')
            logger.info(f"Parsed Markdown: {filepath} -> {len(chunks)} chunks")
            return chunks
            
        except Exception as e:
            logger.error(f"Failed to parse Markdown {filepath}: {e}")
            return []
    
    def parse_text(self, filepath: str) -> List[CodeChunk]:
        """Parse plain text document"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
            
            chunks = self._split_into_chunks(text, filepath, 'text')
            logger.info(f"Parsed Text: {filepath} -> {len(chunks)} chunks")
            return chunks
            
        except Exception as e:
            logger.error(f"Failed to parse Text {filepath}: {e}")
            return []
    
    def parse_html(self, filepath: str) -> List[CodeChunk]:
        """Parse HTML document"""
        try:
            from bs4 import BeautifulSoup
            
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                html = f.read()
            
            soup = BeautifulSoup(html, 'html.parser')
            text = soup.get_text()
            
            chunks = self._split_into_chunks(text, filepath, 'html')
            logger.info(f"Parsed HTML: {filepath} -> {len(chunks)} chunks")
            return chunks
            
        except Exception as e:
            logger.error(f"Failed to parse HTML {filepath}: {e}")
            return []
    
    def _split_into_chunks(self, text: str, filepath: str, doc_type: str) -> List[CodeChunk]:
        """Split text into overlapping chunks"""
        chunks = []
        text = text.strip()
        
        if not text:
            return chunks
        
        start = 0
        chunk_id = 0
        
        while start < len(text):
            end = start + self.chunk_size
            
            # Try to break at sentence boundary
            if end < len(text):
                sentence_end = text.rfind('.', start, end)
                if sentence_end > start:
                    end = sentence_end + 1
            
            chunk_text = text[start:end].strip()
            
            if chunk_text:
                chunks.append(CodeChunk(
                    id=f"{Path(filepath).stem}::chunk{chunk_id}",
                    source_file=filepath,
                    content=chunk_text,
                    chunk_type=f'document_{doc_type}',
                    line_start=0,
                    line_end=0,
                    metadata={
                        'doc_type': doc_type,
                        'chunk_index': chunk_id,
                        'char_start': start,
                        'char_end': end
                    }
                ))
                chunk_id += 1
            
            start = end - self.chunk_overlap
        
        return chunks


# ============================================================================
# GRAPH BUILDER
# ============================================================================

class ProgramGraphBuilder:
    """Build NetworkX graph of program relationships"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
    
    def add_program(self, program_id: str, filename: str, metadata: Dict = None):
        """Add a program node to the graph"""
        self.graph.add_node(
            f"prog:{program_id}",
            node_type='program',
            name=program_id,
            source_file=filename,
            metadata=metadata or {}
        )
    
    # Around line 892 in cobol_rag_agent.py
    def add_call(self, source: str, target: str, call_mechanism: str = 'STATIC_CALL'):
       """Add call with mechanism type"""
       source_id = f"prog:{source}"
       target_id = f"prog:{target}"
       
       if source_id not in self.graph:
           self.add_program(source, source)
       if target_id not in self.graph:
           self.add_program(target, target)
       
       self.graph.add_edge(
           source_id, 
           target_id, 
           type='calls',
           call_mechanism=call_mechanism  # NEW: store the mechanism
       )
    
    def add_db2_table(self, program_id: str, table_name: str, operation: str):
        """Add DB2 table access"""
        table_node = f"table:{table_name}"
        if not self.graph.has_node(table_node):
            self.graph.add_node(
                table_node,
                node_type='db2_table',
                name=table_name
            )
        
        self.graph.add_edge(
            f"prog:{program_id}",
            table_node,
            edge_type='db2_access',
            operation=operation
        )
    
    def add_mq_queue(self, program_id: str, operation: str):
        """Add MQ operation"""
        mq_node = f"mq:{operation}"
        if not self.graph.has_node(mq_node):
            self.graph.add_node(
                mq_node,
                node_type='mq_operation',
                name=operation
            )
        
        self.graph.add_edge(
            f"prog:{program_id}",
            mq_node,
            edge_type='mq_operation'
        )
    
    def add_cics_command(self, program_id: str, command: str):
        """Add CICS command"""
        cics_node = f"cics:{command}"
        if not self.graph.has_node(cics_node):
            self.graph.add_node(
                cics_node,
                node_type='cics_command',
                name=command
            )
        
        self.graph.add_edge(
            f"prog:{program_id}",
            cics_node,
            edge_type='cics_command'
        )
    
    def get_neighbors(self, node_id: str, depth: int = 1) -> Dict[str, Any]:
        """Get neighbors of a node up to specified depth"""
        if not self.graph.has_node(node_id):
            return {'error': f'Node {node_id} not found'}
        
        neighbors = {
            'node': node_id,
            'depth': depth,
            'incoming': [],
            'outgoing': []
        }
        
        for successor in nx.descendants(self.graph, node_id):
            try:
                path_length = nx.shortest_path_length(self.graph, node_id, successor)
                if path_length <= depth:
                    edge_data = self.graph.get_edge_data(node_id, successor) or {}
                    neighbors['outgoing'].append({
                        'node': successor,
                        'distance': path_length,
                        'node_data': dict(self.graph.nodes[successor]),
                        'edge_type': edge_data.get('edge_type', 'unknown')
                    })
            except:
                pass
        
        for predecessor in nx.ancestors(self.graph, node_id):
            try:
                path_length = nx.shortest_path_length(self.graph, predecessor, node_id)
                if path_length <= depth:
                    edge_data = self.graph.get_edge_data(predecessor, node_id) or {}
                    neighbors['incoming'].append({
                        'node': predecessor,
                        'distance': path_length,
                        'node_data': dict(self.graph.nodes[predecessor]),
                        'edge_type': edge_data.get('edge_type', 'unknown')
                    })
            except:
                pass
        
        return neighbors
    
    def save_graph(self, filepath: str):
        """Save graph to file using pickle"""
        with open(filepath, 'wb') as f:
            pickle.dump(self.graph, f)
    
    def load_graph(self, filepath: str):
        """Load graph from file using pickle"""
        with open(filepath, 'rb') as f:
            self.graph = pickle.load(f)


# ============================================================================
# VECTOR INDEX BUILDER
# ============================================================================

class VectorIndexBuilder:
    """Build FAISS vector index for semantic search"""
    
    def __init__(self, model_name: str = 'all-MiniLM-L6-v2'):
        self.model = SentenceTransformer(model_name)
        self.dimension = self.model.get_sentence_embedding_dimension()
        self.index = faiss.IndexFlatL2(self.dimension)
        self.chunks: List[CodeChunk] = []
    
    def add_chunks(self, chunks: List[CodeChunk]):
        """Add code chunks to the index"""
        if not chunks:
            return
        
        texts = [f"{chunk.chunk_type}: {chunk.content}" for chunk in chunks]
        embeddings = self.model.encode(texts, show_progress_bar=True)
        
        self.index.add(np.array(embeddings).astype('float32'))
        self.chunks.extend(chunks)
        
        logger.info(f"Added {len(chunks)} chunks to index. Total: {len(self.chunks)}")
    
    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Search for similar code chunks"""
        query_embedding = self.model.encode([query])
        
        distances, indices = self.index.search(
            np.array(query_embedding).astype('float32'), 
            top_k
        )
        
        results = []
        for i, (dist, idx) in enumerate(zip(distances[0], indices[0])):
            if idx < len(self.chunks):
                chunk = self.chunks[idx]
                results.append({
                    'rank': i + 1,
                    'score': float(dist),
                    'chunk': asdict(chunk)
                })
        
        return results
    
    def save_index(self, index_path: str, chunks_path: str):
        """Save index and chunks to disk"""
        faiss.write_index(self.index, index_path)
        
        with open(chunks_path, 'w') as f:
            json.dump([asdict(chunk) for chunk in self.chunks], f, indent=2)
        
        logger.info(f"Saved index to {index_path} and chunks to {chunks_path}")
    
    def load_index(self, index_path: str, chunks_path: str):
        """Load index and chunks from disk"""
        self.index = faiss.read_index(index_path)
        
        with open(chunks_path, 'r') as f:
            chunk_dicts = json.load(f)
            self.chunks = [CodeChunk(**c) for c in chunk_dicts]
        
        logger.info(f"Loaded {len(self.chunks)} chunks from {chunks_path}")


# ============================================================================
# FLOW DIAGRAM GENERATOR
# ============================================================================

# ============================================================================
# ENHANCED FLOW DIAGRAM GENERATOR
# ============================================================================

"""
EnhancedFlowDiagramGenerator - Complete Flow Visualization
===========================================================
Generates comprehensive Mermaid diagrams showing:
- Program call chains (static, dynamic, CICS)
- Input/Output files
- Database operations
- MQ operations
- Full execution flow
"""



"""
EnhancedFlowDiagramGenerator - Complete Flow Visualization
===========================================================
Generates comprehensive Mermaid diagrams showing:
- Program call chains (static, dynamic, CICS)
- Input/Output files
- Database operations
- MQ operations
- Full execution flow
"""


"""
EnhancedFlowDiagramGenerator - Complete Flow Visualization
===========================================================
Generates comprehensive Mermaid diagrams showing:
- Program call chains (static, dynamic, CICS)
- Input/Output files
- Database operations
- MQ operations
- Full execution flow
"""



class EnhancedFlowDiagramGenerator:
    """
    Enhanced flow diagram generator that shows complete program execution flow
    including called programs, input files, output files, and database operations.
    """
    
    def __init__(self, graph_builder):
        """
        Initialize with a ProgramGraphBuilder instance or NetworkX graph
        
        Handles different input types:
        - ProgramGraphBuilder: extracts the .graph attribute
        - NetworkX Graph: uses directly
        - Dict or other: attempts to use as-is
        """
        import networkx as nx
        
        # Check if it's a NetworkX graph (must check this FIRST)
        if isinstance(graph_builder, (nx.Graph, nx.DiGraph, nx.MultiGraph, nx.MultiDiGraph)):
            # It's already a NetworkX graph - use it directly
            self.graph_builder = None
            self.graph = graph_builder
            logger.debug("Initialized with NetworkX graph directly")
        
        # Check if it has a .graph attribute (ProgramGraphBuilder)
        elif hasattr(graph_builder, 'graph'):
            # Extract the actual NetworkX graph
            self.graph_builder = graph_builder
            self.graph = graph_builder.graph
            logger.debug(f"Initialized with ProgramGraphBuilder, extracted graph type: {type(self.graph)}")
        
        # Fallback: treat as unknown type
        else:
            logger.warning(f"Unknown graph type: {type(graph_builder)}, attempting to use as-is")
            self.graph_builder = graph_builder
            self.graph = getattr(graph_builder, 'graph', graph_builder)
        
        # Verify we have a valid graph
        if not hasattr(self.graph, 'has_node'):
            raise TypeError(
                f"Invalid graph type: {type(self.graph)}. "
                f"Expected NetworkX graph but got {type(self.graph).__name__}. "
                f"Make sure you're passing either a ProgramGraphBuilder or NetworkX graph."
            )
        
        self.colors = {
            'program': '#4A90E2',
            'called_program': '#5BA3F5',
            'input_file': '#50C878',
            'output_file': '#FF6B6B',
            'db2_table': '#9B59B6',
            'mq_queue': '#FFA500',
            'cics': '#E74C3C'
        }
    
    def generate_flow(self, program_name: str, max_depth: int = 3) -> Dict[str, Any]:
        """
        Generate flow diagram for a program (main entry point).
        Alias for generate_complete_flow() for backward compatibility.
        
        Args:
            program_name: Name of the program to analyze
            max_depth: Maximum depth for call chain traversal (default: 3)
        
        Returns:
            Dictionary with flow information and Mermaid diagram
        """
        return self.generate_complete_flow(program_name, max_depth)
    
    def generate_complete_flow(self, program_name: str, max_depth: int = 3) -> Dict[str, Any]:
        """
        Generate complete flow diagram for a program including:
        - All called programs (with recursion up to max_depth)
        - All input files
        - All output files
        - All database operations
        - All MQ operations
        
        Returns:
            {
                'mermaid_diagram': str,
                'programs_called': [str],
                'input_files': [str],
                'output_files': [str],
                'databases': [dict],
                'mq_queues': [str],
                'execution_flow': [dict]
            }
        """
        logger.info(f"Generating complete flow for {program_name} (max depth: {max_depth})")
        
        if not self.graph.has_node(program_name):
            logger.warning(f"Program {program_name} not found in graph")
            return self._empty_result()
        
        # Collect all information
        result = {
            'program': program_name,
            'programs_called': [],
            'input_files': [],
            'output_files': [],
            'databases': [],
            'mq_queues': [],
            'execution_flow': []
        }
        
        # Traverse the call graph
        visited_programs = set()
        self._traverse_calls(program_name, result, visited_programs, depth=0, max_depth=max_depth)
        
        # Generate Mermaid diagram
        result['mermaid_diagram'] = self._generate_mermaid_with_files(program_name, result, max_depth)
        
        logger.info(f"Flow generated: {len(result['programs_called'])} programs, "
                   f"{len(result['input_files'])} inputs, {len(result['output_files'])} outputs")
        
        return result
    
    def _traverse_calls(self, program: str, result: Dict, visited: Set[str], depth: int, max_depth: int):
        """
        Recursively traverse program calls and collect all information
        """
        if depth > max_depth or program in visited:
            return
        
        visited.add(program)
        
        if not self.graph.has_node(program):
            return
        
        node_data = self.graph.nodes[program]
        
        # Create execution flow entry
        flow_entry = {
            'name': program,
            'type': node_data.get('type', 'program'),
            'depth': depth,
            'calls': [],
            'inputs': [],
            'outputs': [],
            'databases': []
        }
        
        # Collect calls from this program
        for successor in self.graph.successors(program):
            edge_data = self.graph.edges[program, successor]
            edge_type = edge_data.get('type', 'unknown')
            
            successor_node_data = self.graph.nodes[successor]
            successor_type = successor_node_data.get('type', 'program')
            
            if successor_type == 'program':
                # It's a program call
                call_info = {
                    'program': successor,
                    'call_type': edge_type,
                    'depth': depth + 1
                }
                flow_entry['calls'].append(call_info)
                
                if successor not in result['programs_called']:
                    result['programs_called'].append(successor)
                
                # Recursively traverse called program
                self._traverse_calls(successor, result, visited, depth + 1, max_depth)
            
            elif successor_type == 'file':
                # It's a file operation
                file_info = {
                    'name': successor,
                    'operation': edge_data.get('operation', 'unknown')
                }
                
                # Determine if input or output based on operation
                operation = edge_data.get('operation', '').upper()
                if 'READ' in operation or 'INPUT' in operation or 'OPEN INPUT' in operation:
                    if successor not in result['input_files']:
                        result['input_files'].append(successor)
                    flow_entry['inputs'].append(file_info['name'])
                elif 'WRITE' in operation or 'OUTPUT' in operation or 'OPEN OUTPUT' in operation:
                    if successor not in result['output_files']:
                        result['output_files'].append(successor)
                    flow_entry['outputs'].append(file_info['name'])
                else:
                    # Default: treat as both input and output
                    if successor not in result['input_files']:
                        result['input_files'].append(successor)
                    flow_entry['inputs'].append(file_info['name'])
            
            elif successor_type == 'table':
                # Database table
                table_info = {
                    'table': successor,
                    'operation': edge_data.get('operation', 'unknown')
                }
                flow_entry['databases'].append(table_info)
                
                if table_info not in result['databases']:
                    result['databases'].append(table_info)
            
            elif successor_type == 'mq_queue':
                # MQ queue
                if successor not in result['mq_queues']:
                    result['mq_queues'].append(successor)
        
        result['execution_flow'].append(flow_entry)
    
    def _generate_mermaid_with_files(self, root_program: str, flow_data: Dict, max_depth: int) -> str:
        """
        Generate Mermaid diagram with programs, files, and databases
        """
        lines = [
            "graph TB",
            "    %% Styling",
            "    classDef programStyle fill:#4A90E2,stroke:#2E5C8A,stroke-width:3px,color:#fff",
            "    classDef calledProgramStyle fill:#5BA3F5,stroke:#3A7BC8,stroke-width:2px,color:#fff",
            "    classDef inputFileStyle fill:#50C878,stroke:#2D7A4A,stroke-width:2px,color:#fff",
            "    classDef outputFileStyle fill:#FF6B6B,stroke:#CC5555,stroke-width:2px,color:#fff",
            "    classDef databaseStyle fill:#50C878,stroke:#2D7A4A,stroke-width:2px,color:#fff",
            "    classDef mqStyle fill:#FFA500,stroke:#CC8400,stroke-width:2px,color:#fff",
            "",
            "    %% Main program"
        ]
        
        # Clean IDs for Mermaid
        def clean_id(name: str) -> str:
            return name.replace('-', '_').replace('.', '_').replace('/', '_').replace(' ', '_')
        
        root_id = clean_id(root_program)
        lines.append(f"    {root_id}[\"{root_program}<br/><b>MAIN PROGRAM</b>\"]")
        lines.append(f"    class {root_id} programStyle")
        lines.append("")
        
        # Track what we've added to avoid duplicates
        added_nodes = {root_id}
        added_edges = set()
        
        # Add input files
        if flow_data['input_files']:
            lines.append("    %% Input Files")
            for file in flow_data['input_files']:
                file_id = clean_id(f"in_{file}")
                if file_id not in added_nodes:
                    lines.append(f"    {file_id}[\"📥 {file}<br/><small>INPUT</small>\"]")
                    lines.append(f"    class {file_id} inputFileStyle")
                    added_nodes.add(file_id)
                
                edge = (file_id, root_id)
                if edge not in added_edges:
                    lines.append(f"    {file_id} -->|reads| {root_id}")
                    added_edges.add(edge)
            lines.append("")
        
        # Add output files
        if flow_data['output_files']:
            lines.append("    %% Output Files")
            for file in flow_data['output_files']:
                file_id = clean_id(f"out_{file}")
                if file_id not in added_nodes:
                    lines.append(f"    {file_id}[\"📤 {file}<br/><small>OUTPUT</small>\"]")
                    lines.append(f"    class {file_id} outputFileStyle")
                    added_nodes.add(file_id)
                
                edge = (root_id, file_id)
                if edge not in added_edges:
                    lines.append(f"    {root_id} -->|writes| {file_id}")
                    added_edges.add(edge)
            lines.append("")
        
        # Add database operations
        if flow_data['databases']:
            lines.append("    %% Database Tables")
            for db_info in flow_data['databases']:
                table = db_info['table']
                operation = db_info.get('operation', 'ACCESS')
                table_id = clean_id(f"db_{table}")
                
                if table_id not in added_nodes:
                    lines.append(f"    {table_id}[(\"💾 {table}<br/><small>DATABASE</small>\")]")
                    lines.append(f"    class {table_id} databaseStyle")
                    added_nodes.add(table_id)
                
                edge = (root_id, table_id)
                if edge not in added_edges:
                    lines.append(f"    {root_id} -->|{operation}| {table_id}")
                    added_edges.add(edge)
            lines.append("")
        
        # Add MQ queues
        if flow_data['mq_queues']:
            lines.append("    %% MQ Queues")
            for queue in flow_data['mq_queues']:
                queue_id = clean_id(f"mq_{queue}")
                if queue_id not in added_nodes:
                    lines.append(f"    {queue_id}[\"📨 {queue}<br/><small>MQ QUEUE</small>\"]")
                    lines.append(f"    class {queue_id} mqStyle")
                    added_nodes.add(queue_id)
                
                edge = (root_id, queue_id)
                if edge not in added_edges:
                    lines.append(f"    {root_id} -->|uses| {queue_id}")
                    added_edges.add(edge)
            lines.append("")
        
        # Add called programs with their I/O
        if flow_data['programs_called']:
            lines.append("    %% Called Programs")
            
            for flow_entry in flow_data['execution_flow']:
                if flow_entry['name'] == root_program:
                    continue  # Skip root, already added
                
                prog_id = clean_id(flow_entry['name'])
                
                if prog_id not in added_nodes:
                    depth_indicator = "▶" * min(flow_entry['depth'], 3)
                    lines.append(f"    {prog_id}[\"{depth_indicator} {flow_entry['name']}<br/><small>CALLED PROGRAM</small>\"]")
                    lines.append(f"    class {prog_id} calledProgramStyle")
                    added_nodes.add(prog_id)
                
                # Find which program calls this one
                for parent_flow in flow_data['execution_flow']:
                    for call_info in parent_flow['calls']:
                        if call_info['program'] == flow_entry['name']:
                            parent_id = clean_id(parent_flow['name'])
                            call_type = call_info.get('call_type', 'CALL')
                            edge = (parent_id, prog_id)
                            
                            if edge not in added_edges:
                                lines.append(f"    {parent_id} -->|{call_type}| {prog_id}")
                                added_edges.add(edge)
                
                # Add I/O for called programs
                for inp in flow_entry['inputs']:
                    inp_id = clean_id(f"in_{inp}_{prog_id}")
                    if inp_id not in added_nodes:
                        lines.append(f"    {inp_id}[\"📥 {inp}\"]")
                        lines.append(f"    class {inp_id} inputFileStyle")
                        added_nodes.add(inp_id)
                    
                    edge = (inp_id, prog_id)
                    if edge not in added_edges:
                        lines.append(f"    {inp_id} -.->|reads| {prog_id}")
                        added_edges.add(edge)
                
                for out in flow_entry['outputs']:
                    out_id = clean_id(f"out_{out}_{prog_id}")
                    if out_id not in added_nodes:
                        lines.append(f"    {out_id}[\"📤 {out}\"]")
                        lines.append(f"    class {out_id} outputFileStyle")
                        added_nodes.add(out_id)
                    
                    edge = (prog_id, out_id)
                    if edge not in added_edges:
                        lines.append(f"    {prog_id} -.->|writes| {out_id}")
                        added_edges.add(edge)
        
        return '\n'.join(lines)
    
    def _empty_result(self) -> Dict[str, Any]:
        """Return empty result structure"""
        return {
            'mermaid_diagram': 'graph TB\n    A[Program Not Found]',
            'programs_called': [],
            'input_files': [],
            'output_files': [],
            'databases': [],
            'mq_queues': [],
            'execution_flow': []
        }
    
    def generate_simple_flow(self, program_name: str) -> str:
        """
        Generate a simple Mermaid diagram for a single program.
        Shows only direct neighbors (calls, files, tables).
        """
        if not self.graph.has_node(program_name):
            return "graph TB\n    A[Program Not Found]"
        
        lines = [
            "graph TB",
            "    classDef programStyle fill:#4A90E2,stroke:#2E5C8A,stroke-width:2px,color:#fff",
            "    classDef fileStyle fill:#50C878,stroke:#2D7A4A,stroke-width:2px,color:#fff",
            "    classDef tableStyle fill:#9B59B6,stroke:#6C3483,stroke-width:2px,color:#fff",
            ""
        ]
        
        def clean_id(name: str) -> str:
            return name.replace('-', '_').replace('.', '_').replace('/', '_')
        
        root_id = clean_id(program_name)
        lines.append(f"    {root_id}[\"{program_name}\"]")
        lines.append(f"    class {root_id} programStyle")
        
        # Add all successors
        for successor in self.graph.successors(program_name):
            succ_id = clean_id(successor)
            node_data = self.graph.nodes[successor]
            node_type = node_data.get('type', 'program')
            edge_data = self.graph.edges[program_name, successor]
            
            if node_type == 'file':
                lines.append(f"    {succ_id}[\"{successor}\"]")
                lines.append(f"    class {succ_id} fileStyle")
                lines.append(f"    {root_id} --> {succ_id}")
            elif node_type == 'table':
                lines.append(f"    {succ_id}[(\"{successor}\")]")
                lines.append(f"    class {succ_id} tableStyle")
                operation = edge_data.get('operation', 'ACCESS')
                lines.append(f"    {root_id} -->|{operation}| {succ_id}")
            else:
                lines.append(f"    {succ_id}[\"{successor}\"]")
                lines.append(f"    class {succ_id} programStyle")
                call_type = edge_data.get('type', 'CALL')
                lines.append(f"    {root_id} -->|{call_type}| {succ_id}")
        
        return '\n'.join(lines)
        
class ProgramChainAnalyzer:
    """Analyze complete program call chains with file/data flow"""
    
    def __init__(self, graph: nx.DiGraph, code_index: 'VectorIndexBuilder'):
        self.graph = graph
        self.code_index = code_index
    
    def analyze_program_chain(self, start_program: str, max_depth: int = 5) -> Dict[str, Any]:
        """
        Analyze complete program chain starting from a program.
        Returns full flow with inputs, outputs, and intermediate steps.
        """
        start_node = f"prog:{start_program}"
        
        if not self.graph.has_node(start_node):
            return {'error': f'Program {start_program} not found'}
        
        chain = {
            'start_program': start_program,
            'execution_flow': [],
            'files': {'input': [], 'output': [], 'intermediate': []},
            'databases': [],
            'mq_queues': [],
            'programs_called': []
        }
        
        # Traverse the call graph
        visited = set()
        self._traverse_chain(start_node, chain, visited, 0, max_depth)
        
        return chain
    
    def _traverse_chain(self, node: str, chain: Dict, visited: set, depth: int, max_depth: int):
        """Recursively traverse program chain"""
        if depth > max_depth or node in visited:
            return
        
        visited.add(node)
        node_data = self.graph.nodes.get(node, {})
        node_type = node_data.get('node_type', 'unknown')
        node_name = node_data.get('name', node)
        
        step = {
            'depth': depth,
            'type': node_type,
            'name': node_name,
            'inputs': [],
            'outputs': [],
            'calls': []
        }
        
        # Analyze successors
        for successor in self.graph.successors(node):
            succ_data = self.graph.nodes.get(successor, {})
            succ_type = succ_data.get('node_type', '')
            succ_name = succ_data.get('name', successor)
            edge_data = self.graph.get_edge_data(node, successor)
            
            if succ_type == 'program':
                step['calls'].append({
                    'program': succ_name,
                    'call_type': edge_data.get('call_type', 'static') if edge_data else 'unknown',
                    'call_mechanism': edge_data.get('call_type', 'static') if edge_data else 'unknown'
                })
                chain['programs_called'].append(succ_name)
                
                # Recursively analyze called program
                self._traverse_chain(successor, chain, visited, depth + 1, max_depth)
                
            elif succ_type == 'db2_table':
                operation = edge_data.get('operation', 'ACCESS') if edge_data else 'ACCESS'
                db_info = {'table': succ_name, 'operation': operation}
                
                if operation in ['SELECT', 'READ']:
                    step['inputs'].append(db_info)
                else:
                    step['outputs'].append(db_info)
                
                if succ_name not in [d['table'] for d in chain['databases']]:
                    chain['databases'].append(db_info)
                    
            elif succ_type == 'mq_operation':
                mq_info = {'operation': succ_name}
                
                if 'GET' in succ_name.upper() or 'READ' in succ_name.upper():
                    step['inputs'].append(mq_info)
                else:
                    step['outputs'].append(mq_info)
                
                if succ_name not in chain['mq_queues']:
                    chain['mq_queues'].append(succ_name)
        
        chain['execution_flow'].append(step)
    
    def generate_chain_diagram(self, chain: Dict) -> str:
        """Generate Mermaid diagram for entire chain"""
        lines = ["graph TB"]
        
        # Group by depth
        depth_groups = {}
        for step in chain['execution_flow']:
            depth = step['depth']
            if depth not in depth_groups:
                depth_groups[depth] = []
            depth_groups[depth].append(step)
        
        # Generate nodes by level
        for depth in sorted(depth_groups.keys()):
            lines.append(f"  subgraph Level_{depth}")
            for step in depth_groups[depth]:
                node_id = step['name'].replace('-', '_').replace(':', '_')
                lines.append(f"    {node_id}[{step['name']}]")
            lines.append("  end")
        
        # Generate edges
        for step in chain['execution_flow']:
            source_id = step['name'].replace('-', '_').replace(':', '_')
            
            # Inputs
            for inp in step['inputs']:
                inp_id = str(inp).replace('-', '_').replace(':', '_').replace(' ', '_')
                lines.append(f"  {inp_id} --> {source_id}")
            
            # Outputs
            for out in step['outputs']:
                out_id = str(out).replace('-', '_').replace(':', '_').replace(' ', '_')
                lines.append(f"  {source_id} --> {out_id}")
            
            # Calls
            for call in step['calls']:
                target_id = call['program'].replace('-', '_').replace(':', '_')
                call_type = call['call_type']
                lines.append(f"  {source_id} -->|CALL ({call_type})| {target_id}")
        
        return '\n'.join(lines)

# ============================================================================
# MCP SERVER
# ============================================================================

class MCPServer:
    """MCP (Model Context Protocol) Server for COBOL RAG"""
    
    def __init__(self, code_index: VectorIndexBuilder, doc_index: VectorIndexBuilder, 
                 graph: ProgramGraphBuilder):
        self.code_index = code_index
        self.doc_index = doc_index
        self.graph = graph
        self.diagram_gen = EnhancedFlowDiagramGenerator(graph.graph)
    
    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle JSON-RPC request"""
        method = request.get('method')
        params = request.get('params', {})
        request_id = request.get('id')
        
        try:
            if method == 'search_code':
                result = self._search_code(params)
            elif method == 'search_docs':
                result = self._search_docs(params)
            elif method == 'graph_neighbors':
                result = self._graph_neighbors(params)
            elif method == 'flow_mermaid':
                result = self._flow_mermaid(params)
            elif method == 'resolve_dynamic_call':
                result = self._resolve_dynamic_call(params)
            elif method == 'combined_search':
                result = self._combined_search(params)
            elif method == 'full_program_chain':
                result = self._full_program_chain(params)
            else:
                return {
                    'jsonrpc': '2.0',
                    'id': request_id,
                    'error': {'code': -32601, 'message': f'Method not found: {method}'}
                }
            
            return {
                'jsonrpc': '2.0',
                'id': request_id,
                'result': result
            }
        
        except Exception as e:
            logger.error(f"Error handling request: {e}", exc_info=True)
            return {
                'jsonrpc': '2.0',
                'id': request_id,
                'error': {'code': -32603, 'message': str(e)}
            }
    
    def _search_code(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Search code index"""
        query = params.get('query', '')
        top_k = params.get('top_k', 5)
        
        results = self.code_index.search(query, top_k)
        
        return {
            'query': query,
            'top_k': top_k,
            'results': results
        }
    
    def _search_docs(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Search documentation index"""
        query = params.get('query', '')
        top_k = params.get('top_k', 5)
        
        results = self.doc_index.search(query, top_k)
        
        return {
            'query': query,
            'top_k': top_k,
            'results': results
        }
    
    def _graph_neighbors(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get graph neighbors"""
        node = params.get('node', '')
        depth = params.get('depth', 1)
        
        neighbors = self.graph.get_neighbors(node, depth)
        
        return neighbors
    
    def _flow_mermaid(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Mermaid flow diagram"""
        node = params.get('node', '')
        depth = params.get('depth', 2)
        
        diagram = self.diagram_gen.generate_flow(node, depth)
        
        return {
            'node': node,
            'depth': depth,
            'mermaid_diagram': diagram.get('mermaid_diagram', ''),
            'nodes': diagram.get('programs_called', []),
            'edges': diagram.get('execution_flow', [])
        }
    
    def _resolve_dynamic_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve dynamic CALL using heuristics"""
        variable = params.get('variable', '')
        context = params.get('context', '')
        
        possible_targets = []
        move_pattern = re.compile(
            rf"MOVE\s+['\"](\w+)['\"]\s+TO\s+{variable}",
            re.IGNORECASE
        )
        
        for match in move_pattern.finditer(context):
            possible_targets.append(match.group(1))
        
        return {
            'variable': variable,
            'possible_targets': possible_targets,
            'confidence': 'medium' if possible_targets else 'low'
        }
    
    def _combined_search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Combined search across code, docs, and graph"""
        query = params.get('query', '')
        top_k = params.get('top_k', 5)
        
        code_results = self.code_index.search(query, top_k)
        doc_results = self.doc_index.search(query, top_k)
        
        graph_context = []
        for result in code_results[:3]:
            chunk = result['chunk']
            program_id = chunk['metadata'].get('program_id')
            if program_id:
                node_id = f"prog:{program_id}"
                neighbors = self.graph.get_neighbors(node_id, depth=1)
                graph_context.append(neighbors)
        
        return {
            'query': query,
            'code_results': code_results,
            'doc_results': doc_results,
            'graph_context': graph_context
        }
    
    # In MCPServer class, add this method:

    def _full_program_chain(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze full program execution chain"""
        program = params.get('program', '')
        max_depth = params.get('max_depth', 5)
        
        analyzer = ProgramChainAnalyzer(self.graph.graph, self.code_index)
        chain = analyzer.analyze_program_chain(program, max_depth)
        
        if 'error' not in chain:
            # Generate diagram
            diagram = analyzer.generate_chain_diagram(chain)
            chain['mermaid_diagram'] = diagram
        
        return chain
    
    def run(self):
        """Run MCP server on stdin/stdout"""
        logger.info("MCP Server started. Listening on stdin...")
        
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            
            try:
                request = json.loads(line)
                response = self.handle_request(request)
                print(json.dumps(response), flush=True)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON: {e}")
                error_response = {
                    'jsonrpc': '2.0',
                    'id': None,
                    'error': {'code': -32700, 'message': 'Parse error'}
                }
                print(json.dumps(error_response), flush=True)


# ============================================================================
# MAIN INDEXER
# ============================================================================

class COBOLIndexer:
    """Main indexer that orchestrates parsing and index building"""
    
    def __init__(self, output_dir: str = './cobol_index'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.cobol_parser = COBOLParser()
        self.jcl_parser = JCLParser()
        self.doc_parser = DocumentParser()
        #self.flow_generator = EnhancedFlowDiagramGenerator(self.db_manager)
        self.code_index = VectorIndexBuilder()
        self.doc_index = VectorIndexBuilder()
        self.graph = ProgramGraphBuilder()
    
    def index_directory(self, source_dir: str):
        """Index all COBOL/JCL files in a directory"""
        source_path = Path(source_dir)
        
        logger.info(f"Indexing directory: {source_dir}")
        
        cobol_files = list(source_path.rglob('*.cbl')) + list(source_path.rglob('*.cob'))
        jcl_files = list(source_path.rglob('*.jcl'))
        copybook_files = list(source_path.rglob('*.cpy'))
        
        logger.info(f"Found {len(cobol_files)} COBOL files, {len(jcl_files)} JCL files, {len(copybook_files)} copybooks")
        
        all_chunks = []
        for filepath in cobol_files:
            logger.info(f"Processing: {filepath}")
            with open(filepath, 'r', encoding='latin-1', errors='ignore') as f:
                source_code = f.read()
            
            chunks = self.cobol_parser.parse_cobol(source_code, str(filepath))
            all_chunks.extend(chunks)
            
            program_id = self._extract_program_id_from_chunks(chunks)
            self.graph.add_program(program_id, str(filepath))
            calls = self.cobol_parser.extract_calls(source_code)
            logger.info(f"Processing {len(calls)} calls from {program_id}")

            for call in calls:
                target = call.get('target')
                
                # Get call type/mechanism - handle both old and new format
                call_mechanism = call.get('call_mechanism', call.get('type', 'static'))
                
                # Convert call_mechanism to call_type format expected by graph
                call_type_map = {
                    'STATIC_CALL': 'static',
                    'DYNAMIC_CALL': 'dynamic',
                    'CICS_LINK': 'cics_link',
                    'CICS_LINK_DYNAMIC': 'cics_link_dynamic',
                    'CICS_XCTL': 'cics_xctl',
                    'CICS_XCTL_DYNAMIC': 'cics_xctl_dynamic',
                    # Legacy format support
                    'static': 'static',
                    'dynamic': 'dynamic',
                    'cics_link': 'cics_link',
                    'cics_xctl': 'cics_xctl'
                }
                
                # Get the simplified call type
                simple_call_type = call_type_map.get(call_mechanism, 'static')
                
                # Add primary call
                if target:
                    logger.info(f"  → Adding call: {program_id} -> {target} ({simple_call_type})")
                    self.graph.add_call(program_id, target, simple_call_type)
                
                # For dynamic calls with resolved targets, add each resolved target
                if call.get('is_dynamic') and call.get('possible_targets'):
                    logger.info(f"  → Dynamic call resolved to {len(call['possible_targets'])} targets")
                    for resolved_target in call['possible_targets']:
                        logger.info(f"    → {program_id} -> {resolved_target} ({simple_call_type})")
                        self.graph.add_call(program_id, resolved_target, simple_call_type)
            
            db2_ops = self.cobol_parser.extract_db2_operations(source_code)
            for op in db2_ops:
                if op['table']:
                    self.graph.add_db2_table(program_id, op['table'], op['type'])
            
            cics_cmds = self.cobol_parser.extract_cics_commands(source_code)
            for cmd in cics_cmds:
                self.graph.add_cics_command(program_id, cmd['command'])
            
            mq_ops = self.cobol_parser.extract_mq_operations(source_code)
            for op in mq_ops:
                self.graph.add_mq_queue(program_id, op['operation'])
            
        
        for filepath in jcl_files:
            logger.info(f"Processing JCL: {filepath}")
            with open(filepath, 'r', encoding='latin-1', errors='ignore') as f:
                source_code = f.read()
            
            chunks = self.jcl_parser.parse_jcl(source_code, str(filepath))
            all_chunks.extend(chunks)
        
        self.code_index.add_chunks(all_chunks)
        
        logger.info("Indexing complete!")
    
    def _extract_program_id_from_chunks(self, chunks: List[CodeChunk]) -> str:
        """Extract program ID from chunks"""
        for chunk in chunks:
            if 'program_id' in chunk.metadata:
                return chunk.metadata['program_id']
        return "UNKNOWN"
    
    def save_all(self):
        """Save all indexes to disk"""
        self.code_index.save_index(
            str(self.output_dir / 'code_index.faiss'),
            str(self.output_dir / 'code_chunks.json')
        )
        
        self.doc_index.save_index(
            str(self.output_dir / 'doc_index.faiss'),
            str(self.output_dir / 'doc_chunks.json')
        )
        
        self.graph.save_graph(str(self.output_dir / 'program_graph.gpickle'))
        
        logger.info(f"All indexes saved to {self.output_dir}")
    
    def load_all(self):
        """Load all indexes from disk"""
        code_index_path = self.output_dir / 'code_index.faiss'
        code_chunks_path = self.output_dir / 'code_chunks.json'
        
        if not code_index_path.exists() or not code_chunks_path.exists():
            raise FileNotFoundError(
                f"Code index not found in {self.output_dir}. "
                "Run batch_parser.py first to create indexes."
            )
        
        self.code_index.load_index(
            str(code_index_path),
            str(code_chunks_path)
        )
        logger.info(f"✓ Loaded code index with {len(self.code_index.chunks)} chunks")
        
        doc_index_path = self.output_dir / 'doc_index.faiss'
        doc_chunks_path = self.output_dir / 'doc_chunks.json'
        
        if doc_index_path.exists() and doc_chunks_path.exists():
            try:
                self.doc_index.load_index(
                    str(doc_index_path),
                    str(doc_chunks_path)
                )
                logger.info(f"✓ Loaded doc index with {len(self.doc_index.chunks)} chunks")
            except Exception as e:
                logger.warning(f"Could not load doc index: {e}")
        else:
            logger.info("No doc index found (this is optional)")
        
        graph_path = self.output_dir / 'program_graph.gpickle'
        
        if not graph_path.exists():
            raise FileNotFoundError(
                f"Program graph not found in {self.output_dir}. "
                "Run batch_parser.py first to create indexes."
            )
        
        self.graph.load_graph(str(graph_path))
        logger.info(f"✓ Loaded program graph with {len(self.graph.graph.nodes)} nodes")
        
        logger.info("All indexes loaded successfully!")


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='COBOL RAG MCP Agent')
    parser.add_argument('command', choices=['index', 'serve', 'query'],
                       help='Command to execute')
    parser.add_argument('--source-dir', help='Source directory to index')
    parser.add_argument('--index-dir', default='./cobol_index',
                       help='Index directory')
    parser.add_argument('--query', help='Query string for search')
    parser.add_argument('--method', default='search_code',
                       help='MCP method to call')
    
    args = parser.parse_args()
    
    if args.command == 'index':
        if not args.source_dir:
            print("Error: --source-dir required for indexing")
            sys.exit(1)
        
        indexer = COBOLIndexer(args.index_dir)
        indexer.index_directory(args.source_dir)
        indexer.save_all()
        
    elif args.command == 'serve':
        indexer = COBOLIndexer(args.index_dir)
        indexer.load_all()
        
        server = MCPServer(indexer.code_index, indexer.doc_index, indexer.graph)
        server.run()
        
    elif args.command == 'query':
        if not args.query:
            print("Error: --query required")
            sys.exit(1)
        
        indexer = COBOLIndexer(args.index_dir)
        indexer.load_all()
        
        server = MCPServer(indexer.code_index, indexer.doc_index, indexer.graph)
        
        request = {
            'jsonrpc': '2.0',
            'id': 1,
            'method': args.method,
            'params': {'query': args.query, 'top_k': 5}
        }
        
        response = server.handle_request(request)
        print(json.dumps(response, indent=2))


if __name__ == '__main__':
    main()