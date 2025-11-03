"""
COBOL RAG Agent Patches - UNIFIED v1.0.5
=========================================
Combines ALL fixes:
- v1.0.3: Dynamic call resolution, CICS parsing, tree-sitter
- v1.0.4: CICS file nodes, combined_search safety, flow colors
- NEW: Ensures all patches work together

USAGE:
    import cobol_rag_patches_unified
    # Auto-applies all patches
"""

import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


# ============================================================================
# PATCH 1: Tree-sitter Detection (from v1.0.3 + v1.0.4)
# ============================================================================

def patch_treesitter_languages():
    """Enhanced tree-sitter detection with multiple fallback methods"""
    from cobol_rag_agent import COBOLParser
    
    def fixed_init_parser(self):
        """Initialize Tree-Sitter parser for COBOL using multiple methods"""
        try:
            # Method 1: tree_sitter_languages (easiest, modern)
            try:
                from tree_sitter_languages import get_language, get_parser
                self.parser = get_parser('cobol')
                logger.info("✓ Tree-Sitter COBOL parser initialized via tree_sitter_languages")
                return
            except ImportError:
                logger.debug("tree_sitter_languages not installed")
            except Exception as e:
                logger.debug(f"tree_sitter_languages failed: {e}")
            
            # Method 2: tree_sitter_cobol (new API)
            try:
                from tree_sitter import Parser
                import tree_sitter_cobol
                
                COBOL_LANGUAGE = tree_sitter_cobol.language()
                self.parser = Parser()
                self.parser.set_language(COBOL_LANGUAGE)
                logger.info("✓ Tree-Sitter COBOL parser initialized via tree_sitter_cobol")
                return
            except ImportError:
                logger.debug("tree_sitter_cobol not installed")
            except Exception as e:
                logger.debug(f"tree_sitter_cobol failed: {e}")
            
            # Method 3: Old API (for backward compatibility)
            try:
                from tree_sitter import Language, Parser
                
                COBOL_LANGUAGE = Language('build/cobol.so', 'cobol')
                self.parser = Parser()
                self.parser.set_language(COBOL_LANGUAGE)
                logger.info("✓ Tree-Sitter COBOL parser initialized via old API")
                return
            except Exception as e:
                logger.debug(f"Old API failed: {e}")
            
            # All methods failed
            raise Exception("No tree-sitter COBOL installation found")
            
        except Exception as e:
            logger.warning(f"Tree-sitter COBOL not available: {e}")
            logger.info("Using heuristic parser (fully functional)")
            logger.info("To install: pip install tree-sitter-languages")
            self.parser = None
    
    # Apply patch
    COBOLParser._init_parser = fixed_init_parser
    logger.info("✓ Patched COBOLParser._init_parser (tree-sitter detection)")


# ============================================================================
# PATCH 2: Dynamic Call Resolution (CRITICAL - from v1.0.3)
# ============================================================================

def patch_dynamic_call_resolution():
    """
    CRITICAL: Patch for dynamic CALL resolution with:
    - Group-level VALUE clauses
    - Subscripted variables
    - Reference modifications
    """
    from cobol_rag_agent import COBOLParser
    
    def enhanced_resolve_dynamic_call_variables(self, calls: List[Dict], source_code: str) -> List[Dict]:
        """
        Enhanced resolver that handles group variables with VALUE clauses.
        
        Example COBOL:
            01 WA-CONSTANTS.
               05 WA-TMSBTSI1 PIC X(08) VALUE 'TMSBTSI1'.
               05 WA-TMSBTSI3 PIC X(08) VALUE 'TMSBTSI3'.
            ...
            MOVE WA-TMSBTSI1 TO WS-PROGRAM-NAME
            CALL WS-PROGRAM-NAME
        
        Result: WS-PROGRAM-NAME resolves to ['TMSBTSI1']
        """
        # Build comprehensive variable value map
        variable_values = {}
        lines = source_code.split('\n')
        current_condition = None
        current_group = None
        
        # Enhanced patterns
        # Pattern 1: Direct MOVE with literals
        move_literal_pattern = re.compile(
            r"MOVE\s+['\"]([A-Z0-9\-]+)['\"]\s+TO\s+"
            r"([A-Z0-9\-]+(?:\([^)]*\))?(?:\.[A-Z0-9\-]+)?(?:\([^)]*\))?)",
            re.IGNORECASE
        )
        
        # Pattern 2: MOVE from one variable to another
        move_var_pattern = re.compile(
            r"MOVE\s+([A-Z0-9\-]+(?:\([^)]*\))?(?:\.[A-Z0-9\-]+)?(?:\([^)]*\))?)\s+TO\s+"
            r"([A-Z0-9\-]+(?:\([^)]*\))?(?:\.[A-Z0-9\-]+)?(?:\([^)]*\))?)",
            re.IGNORECASE
        )
        
        # Pattern 3: Variable definitions with VALUE clause
        value_def_pattern = re.compile(
            r"^\s*(\d+)\s+([A-Z0-9\-]+)\s+(?:PIC\s+[^\s]+\s+)?VALUE\s+['\"]([A-Z0-9\-]+)['\"]",
            re.IGNORECASE
        )
        
        # Pattern 4: Group level detection
        group_pattern = re.compile(r"^\s*01\s+([A-Z0-9\-]+)", re.IGNORECASE)
        
        logger.debug("=" * 70)
        logger.debug("ENHANCED DYNAMIC CALL RESOLUTION")
        logger.debug("=" * 70)
        
        # First pass: Build variable definitions map
        for line_num, line in enumerate(lines, 1):
            clean_line = line[6:72] if len(line) > 6 else line
            line_upper = clean_line.upper().strip()
            
            # Track group boundaries
            group_match = group_pattern.match(clean_line)
            if group_match:
                current_group = group_match.group(1)
                logger.debug(f"Line {line_num}: Entering group {current_group}")
                continue
            
            # Check for VALUE definitions
            value_match = value_def_pattern.match(clean_line)
            if value_match:
                level = value_match.group(1)
                variable = value_match.group(2)
                value = value_match.group(3)
                
                # Store the value
                if variable not in variable_values:
                    variable_values[variable] = []
                
                variable_values[variable].append({
                    'value': value,
                    'line': line_num,
                    'source_line': line.strip(),
                    'group': current_group,
                    'definition_type': 'VALUE_CLAUSE'
                })
                
                logger.debug(f"Line {line_num}: Found VALUE definition: {variable} = '{value}' (group: {current_group})")
                continue
            
            # Track conditional context
            if line_upper.startswith('IF '):
                current_condition = line.strip()
            elif line_upper.startswith(('END-IF', 'ELSE')):
                current_condition = None
            elif line_upper.endswith('.') and current_condition:
                current_condition = None
            
            # Pattern 1: MOVE literal to variable
            literal_match = move_literal_pattern.search(clean_line)
            if literal_match:
                value = literal_match.group(1)
                variable = literal_match.group(2)
                base_var = re.sub(r'\([^)]*\)', '', variable)
                base_var = re.sub(r'\.[A-Z0-9\-]+$', '', base_var)
                
                if base_var not in variable_values:
                    variable_values[base_var] = []
                
                variable_values[base_var].append({
                    'value': value,
                    'line': line_num,
                    'condition': current_condition,
                    'source_line': line.strip(),
                    'definition_type': 'MOVE_LITERAL'
                })
                
                logger.debug(f"Line {line_num}: Found MOVE literal: '{value}' → {base_var}")
            
            # Pattern 2: MOVE variable to variable
            var_match = move_var_pattern.search(clean_line)
            if var_match and not literal_match:
                source_var = var_match.group(1)
                target_var = var_match.group(2)
                
                base_source = re.sub(r'\([^)]*\)', '', source_var)
                base_target = re.sub(r'\([^)]*\)', '', target_var)
                
                # Propagate values
                if base_source in variable_values:
                    if base_target not in variable_values:
                        variable_values[base_target] = []
                    
                    for val_info in variable_values[base_source]:
                        variable_values[base_target].append({
                            'value': val_info['value'],
                            'line': line_num,
                            'source_line': line.strip(),
                            'derived_from': base_source,
                            'definition_type': 'MOVE_VARIABLE'
                        })
                    
                    logger.debug(f"Line {line_num}: Propagated values from {base_source} → {base_target}")
        
        logger.debug("=" * 70)
        logger.debug(f"Variable values map: {len(variable_values)} variables")
        for var, vals in variable_values.items():
            logger.debug(f"  {var}: {[v['value'] for v in vals]}")
        logger.debug("=" * 70)
        
        # Second pass: Resolve each dynamic call
        resolved_count = 0
        unresolved_count = 0
        
        for call in calls:
            if not call.get('is_dynamic') or not call.get('variable'):
                continue
            
            variable = call['variable']
            base_var = re.sub(r'\([^)]*\)', '', variable)
            
            logger.debug(f"\nResolving dynamic call: {variable} (base: {base_var})")
            
            # Direct match
            if base_var in variable_values:
                call['possible_targets'] = list(set([v['value'] for v in variable_values[base_var]]))
                call['resolution_details'] = variable_values[base_var]
                resolved_count += 1
                logger.info(f"✓ Resolved {variable} → {call['possible_targets']}")
                continue
            
            # Fuzzy match
            found_match = False
            for var_name, values in variable_values.items():
                if var_name in base_var or base_var in var_name:
                    call['possible_targets'] = list(set([v['value'] for v in values]))
                    call['resolution_details'] = values
                    call['resolved_via_group'] = var_name
                    resolved_count += 1
                    found_match = True
                    logger.info(f"✓ Resolved {variable} via fuzzy match {var_name} → {call['possible_targets']}")
                    break
            
            if not found_match:
                unresolved_count += 1
                logger.warning(f"✗ Could not resolve variable: {variable} at line {call['line']}")
        
        dynamic_call_count = len([c for c in calls if c.get('is_dynamic')])
        logger.info("=" * 70)
        logger.info(f"Dynamic call resolution complete:")
        logger.info(f"  Total dynamic calls: {dynamic_call_count}")
        logger.info(f"  Resolved: {resolved_count}")
        logger.info(f"  Unresolved: {unresolved_count}")
        logger.info("=" * 70)
        
        return calls
    
    # Apply patch
    COBOLParser._resolve_dynamic_call_variables = enhanced_resolve_dynamic_call_variables
    logger.info("✓ Patched COBOLParser._resolve_dynamic_call_variables (DYNAMIC CALLS)")


# ============================================================================
# PATCH 3: CICS File Extraction (from v1.0.3)
# ============================================================================

def patch_cics_file_extraction():
    """Extract actual file/dataset names from CICS commands"""
    from cobol_rag_agent import COBOLParser
    
    def enhanced_extract_cics_commands(self, source_code: str) -> List[Dict[str, Any]]:
        """
        Extract CICS commands with actual file/dataset names and I/O classification.
        """
        commands = []
        lines = source_code.split('\n')
        
        in_cics = False
        cics_buffer = []
        cics_start_line = 0
        
        # I/O operation classification
        input_operations = {'READ', 'READNEXT', 'READPREV', 'STARTBR'}
        output_operations = {'WRITE', 'REWRITE', 'DELETE'}
        control_operations = {'ENDBR', 'UNLOCK', 'HANDLE'}
        
        for i, line in enumerate(lines, 1):
            line_upper = line.upper().strip()
            
            if 'EXEC CICS' in line_upper:
                if in_cics:
                    commands.extend(self._parse_cics_io_statement(
                        ' '.join(cics_buffer), 
                        cics_start_line,
                        input_operations,
                        output_operations,
                        control_operations
                    ))
                
                in_cics = True
                cics_buffer = [line]
                cics_start_line = i
            
            elif in_cics:
                cics_buffer.append(line)
                
                if 'END-EXEC' in line_upper:
                    full_statement = ' '.join(cics_buffer)
                    commands.extend(self._parse_cics_io_statement(
                        full_statement, 
                        cics_start_line,
                        input_operations,
                        output_operations,
                        control_operations
                    ))
                    
                    in_cics = False
                    cics_buffer = []
        
        logger.debug(f"Extracted {len(commands)} CICS I/O commands")
        return commands
    
    def parse_cics_io_statement(self, statement: str, line_num: int,
                                input_ops: set, output_ops: set, control_ops: set) -> List[Dict[str, Any]]:
        """Parse a single CICS statement"""
        commands = []
        
        cmd_match = re.search(r'EXEC\s+CICS\s+(\w+)', statement, re.IGNORECASE)
        if not cmd_match:
            return commands
        
        command = cmd_match.group(1).upper()
        
        if command in control_ops:
            logger.debug(f"Skipping control operation: {command}")
            return commands
        
        # Extract resource name
        resource_patterns = [
            (r"DATASET\s*\(\s*['\"]?([A-Z0-9\-_]+)['\"]?\s*\)", 'DATASET'),
            (r"FILE\s*\(\s*['\"]?([A-Z0-9\-_]+)['\"]?\s*\)", 'FILE'),
            (r"QUEUE\s*\(\s*['\"]?([A-Z0-9\-_]+)['\"]?\s*\)", 'QUEUE')
        ]
        
        resource = None
        resource_type = None
        
        for pattern, res_type in resource_patterns:
            match = re.search(pattern, statement, re.IGNORECASE)
            if match:
                resource = match.group(1)
                resource_type = res_type
                break
        
        if not resource:
            logger.debug(f"No resource found in CICS {command}")
            return commands
        
        # Determine I/O direction
        io_direction = 'UNKNOWN'
        if command in input_ops:
            io_direction = 'INPUT'
        elif command in output_ops:
            io_direction = 'OUTPUT'
        
        if io_direction == 'UNKNOWN':
            logger.debug(f"Unrecognized I/O operation: {command}")
            return commands
        
        commands.append({
            'command': command,
            'resource': resource,
            'resource_type': resource_type,
            'io_direction': io_direction,
            'line': line_num,
            'source_line': statement.strip()
        })
        
        logger.debug(f"Extracted CICS I/O: {command} {resource} ({io_direction})")
        
        return commands
    
    # Apply patches
    COBOLParser.extract_cics_commands = enhanced_extract_cics_commands
    COBOLParser._parse_cics_io_statement = parse_cics_io_statement
    logger.info("✓ Patched COBOLParser.extract_cics_commands (CICS parsing)")


# ============================================================================
# PATCH 4: CICS File Graph Nodes (CRITICAL FIX from v1.0.4)
# ============================================================================

def patch_graph_builder_cics():
    """Create proper file nodes in graph for CICS operations"""
    from cobol_rag_agent import ProgramGraphBuilder
    
    def enhanced_add_cics_command(self, program_id: str, command_info):
        """
        Enhanced CICS handler that creates proper file nodes.
        
        Handles 3 formats:
        1. New dict with 'resource' key (v1.0.3+)
        2. Old dict with 'command' and 'statement'
        3. Legacy string format (skip)
        """
        # Skip string format
        if isinstance(command_info, str):
            logger.debug(f"Skipping string CICS command: {command_info}")
            return
        
        if not isinstance(command_info, dict):
            logger.warning(f"Invalid command_info type: {type(command_info)}")
            return
        
        resource = None
        resource_type = None
        io_direction = None
        command = None
        
        # NEW FORMAT: Has 'resource' key
        if 'resource' in command_info:
            resource = command_info.get('resource')
            resource_type = command_info.get('resource_type', 'FILE')
            io_direction = command_info.get('io_direction', 'INPUT')
            command = command_info.get('command', 'UNKNOWN')
            logger.debug(f"Using NEW format: {command} {resource} ({io_direction})")
        
        # OLD FORMAT: Parse statement
        elif 'command' in command_info:
            command = command_info.get('command', '').upper()
            statement = command_info.get('statement', '')
            
            if not statement:
                logger.debug(f"Old format with no statement: {command}")
                return
            
            logger.debug(f"Parsing OLD format: {command}")
            
            # Extract resource
            resource_patterns = [
                (r"DATASET\s*\(\s*['\"]?([A-Z0-9\-_]+)['\"]?\s*\)", 'DATASET'),
                (r"FILE\s*\(\s*['\"]?([A-Z0-9\-_]+)['\"]?\s*\)", 'FILE'),
                (r"QUEUE\s*\(\s*['\"]?([A-Z0-9\-_]+)['\"]?\s*\)", 'QUEUE')
            ]
            
            for pattern, rtype in resource_patterns:
                match = re.search(pattern, statement, re.IGNORECASE)
                if match:
                    resource = match.group(1)
                    resource_type = rtype
                    logger.info(f"✓ EXTRACTED from old format: {resource_type}={resource}")
                    break
            
            if not resource:
                logger.debug(f"No resource in: {statement[:100]}")
                return
            
            # Determine I/O direction
            input_ops = {'READ', 'READNEXT', 'READPREV', 'STARTBR'}
            output_ops = {'WRITE', 'REWRITE', 'DELETE'}
            
            if command in input_ops:
                io_direction = 'INPUT'
            elif command in output_ops:
                io_direction = 'OUTPUT'
            else:
                logger.debug(f"Unknown I/O type for {command}")
                return
            
            logger.info(f"✓ Classified as {io_direction}: {command} {resource}")
        
        else:
            logger.warning(f"Unknown dict format: {command_info}")
            return
        
        # Validate
        if not resource:
            return
        
        # Create proper file nodes
        prog_node = f"prog:{program_id}"
        
        if io_direction == 'INPUT':
            # INPUT: file -> program
            file_node = f"cics_input:{resource}"
            
            if not self.graph.has_node(file_node):
                self.graph.add_node(
                    file_node,
                    node_type='cics_input_file',
                    name=resource,
                    resource_type=resource_type,
                    cics_operation=command
                )
                logger.info(f"✓ Created INPUT file node: {file_node}")
            
            self.graph.add_edge(
                file_node,
                prog_node,
                edge_type='cics_read',
                operation=command
            )
            
        else:  # OUTPUT
            # OUTPUT: program -> file
            file_node = f"cics_output:{resource}"
            
            if not self.graph.has_node(file_node):
                self.graph.add_node(
                    file_node,
                    node_type='cics_output_file',
                    name=resource,
                    resource_type=resource_type,
                    cics_operation=command
                )
                logger.info(f"✓ Created OUTPUT file node: {file_node}")
            
            self.graph.add_edge(
                prog_node,
                file_node,
                edge_type='cics_write',
                operation=command
            )
        
        logger.info(f"✓ Added CICS {io_direction} file: {resource} ({command})")
    
    # Apply patch
    ProgramGraphBuilder.add_cics_command = enhanced_add_cics_command
    logger.info("✓ Patched ProgramGraphBuilder.add_cics_command (FILE NODES)")


# ============================================================================
# PATCH 5: Flow Diagram Colors (from v1.0.4)
# ============================================================================

def patch_flow_diagram_colors():
    """Fix flow diagram colors to match node types"""
    from cobol_rag_agent import EnhancedFlowDiagramGenerator
    
    def enhanced_generate_mermaid_with_files(self, root_program: str, flow_data: Dict, max_depth: int) -> str:
        """Generate Mermaid with correct color classes"""
        lines = [
            "graph TB",
            "    %% Enhanced Styling",
            "    classDef programStyle fill:#4A90E2,stroke:#2E5C8A,stroke-width:3px,color:#fff",
            "    classDef calledProgramStyle fill:#5BA3F5,stroke:#3A7BC8,stroke-width:2px,color:#fff",
            "    classDef inputFileStyle fill:#90EE90,stroke:#228B22,stroke-width:2px,color:#000",
            "    classDef outputFileStyle fill:#FFB6C1,stroke:#DC143C,stroke-width:2px,color:#000",
            "    classDef databaseStyle fill:#90EE90,stroke:#228B22,stroke-width:2px,color:#000",
            "    classDef mqStyle fill:#FFA500,stroke:#CC8400,stroke-width:2px,color:#fff",
            "",
            "    %% Main program"
        ]
        
        def clean_id(name: str) -> str:
            return name.replace('-', '_').replace('.', '_').replace('/', '_').replace(' ', '_').replace(':', '_')
        
        def get_node_class(node_id: str) -> str:
            """Get Mermaid class based on node type in graph"""
            if not self.graph.has_node(node_id):
                return 'programStyle'
            
            node_data = self.graph.nodes[node_id]
            node_type = node_data.get('node_type', 'program')
            
            type_to_class = {
                'program': 'programStyle',
                'cics_input_file': 'inputFileStyle',
                'cics_output_file': 'outputFileStyle',
                'db2_table': 'databaseStyle',
                'mq_operation': 'mqStyle',
                'mq_queue': 'mqStyle'
            }
            
            return type_to_class.get(node_type, 'programStyle')
        
        root_id = clean_id(root_program)
        lines.append(f"    {root_id}[\"🔷 {root_program}<br/><b>MAIN PROGRAM</b>\"]")
        lines.append(f"    class {root_id} programStyle")
        lines.append("")
        
        added_nodes = {root_id}
        added_edges = set()
        
        # Add input files at top
        if flow_data.get('input_files'):
            lines.append("    %% Input Files (Top)")
            for file in flow_data['input_files']:
                file_id = clean_id(f"cics_input:{file}")
                
                if file_id not in added_nodes:
                    lines.append(f"    {file_id}[\"📥 {file}<br/><small>INPUT FILE</small>\"]")
                    node_class = get_node_class(f"cics_input:{file}")
                    lines.append(f"    class {file_id} {node_class}")
                    added_nodes.add(file_id)
                
                edge = (file_id, root_id)
                if edge not in added_edges:
                    lines.append(f"    {file_id} -->|reads| {root_id}")
                    added_edges.add(edge)
            lines.append("")
        
        # Add database operations
        if flow_data.get('databases'):
            lines.append("    %% Database Tables")
            for db_info in flow_data['databases']:
                table = db_info['table']
                operation = db_info.get('operation', 'ACCESS')
                table_id = clean_id(f"table:{table}")
                
                if table_id not in added_nodes:
                    lines.append(f"    {table_id}[(\"🗄️ {table}<br/><small>{operation}</small>\")]")
                    node_class = get_node_class(f"table:{table}")
                    lines.append(f"    class {table_id} {node_class}")
                    added_nodes.add(table_id)
                
                edge = (root_id, table_id)
                if edge not in added_edges:
                    lines.append(f"    {root_id} -.->|{operation}| {table_id}")
                    added_edges.add(edge)
            lines.append("")
        
        # Add called programs
        if flow_data.get('programs_called'):
            lines.append("    %% Called Programs")
            for flow_entry in flow_data['execution_flow']:
                if flow_entry['name'] == root_program:
                    continue
                
                prog_id = clean_id(flow_entry['name'])
                
                if prog_id not in added_nodes:
                    depth_indicator = "▶" * min(flow_entry['depth'], 3)
                    lines.append(f"    {prog_id}[\"{depth_indicator} {flow_entry['name']}<br/><small>CALLED</small>\"]")
                    lines.append(f"    class {prog_id} calledProgramStyle")
                    added_nodes.add(prog_id)
                
                for parent_flow in flow_data['execution_flow']:
                    for call_info in parent_flow['calls']:
                        if call_info['program'] == flow_entry['name']:
                            parent_id = clean_id(parent_flow['name'])
                            call_type = call_info.get('call_type', 'CALL')
                            edge = (parent_id, prog_id)
                            
                            if edge not in added_edges:
                                lines.append(f"    {parent_id} ==>|{call_type}| {prog_id}")
                                added_edges.add(edge)
            lines.append("")
        
        # Add output files at bottom
        if flow_data.get('output_files'):
            lines.append("    %% Output Files (Bottom)")
            for file in flow_data['output_files']:
                file_id = clean_id(f"cics_output:{file}")
                
                if file_id not in added_nodes:
                    lines.append(f"    {file_id}[\"📤 {file}<br/><small>OUTPUT FILE</small>\"]")
                    node_class = get_node_class(f"cics_output:{file}")
                    lines.append(f"    class {file_id} {node_class}")
                    added_nodes.add(file_id)
                
                edge = (root_id, file_id)
                if edge not in added_edges:
                    lines.append(f"    {root_id} -->|writes| {file_id}")
                    added_edges.add(edge)
            lines.append("")
        
        # Add MQ queues
        if flow_data.get('mq_queues'):
            lines.append("    %% MQ Queues")
            for queue in flow_data['mq_queues']:
                queue_id = clean_id(f"mq:{queue}")
                
                if queue_id not in added_nodes:
                    lines.append(f"    {queue_id}[\"📨 {queue}<br/><small>MQ QUEUE</small>\"]")
                    node_class = get_node_class(f"mq:{queue}")
                    lines.append(f"    class {queue_id} {node_class}")
                    added_nodes.add(queue_id)
                
                edge = (root_id, queue_id)
                if edge not in added_edges:
                    lines.append(f"    {root_id} -.->|uses| {queue_id}")
                    added_edges.add(edge)
            lines.append("")
        
        return '\n'.join(lines)
    
    # Apply patch
    EnhancedFlowDiagramGenerator._generate_mermaid_with_files = enhanced_generate_mermaid_with_files
    logger.info("✓ Patched EnhancedFlowDiagramGenerator (COLORS)")


# ============================================================================
# PATCH 6: Combined Search Safety (from v1.0.4)
# ============================================================================

def patch_combined_search():
    """Fix combined_search to prevent index errors"""
    from cobol_rag_agent import MCPServer
    
    def safe_combined_search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Safe combined search with bounds checking"""
        query = params.get('query', '')
        top_k = params.get('top_k', 5)
        
        logger.info(f"Combined search: '{query}' (top_k={top_k})")
        
        code_results = self.code_index.search(query, top_k)
        doc_results = self.doc_index.search(query, top_k)
        
        logger.info(f"Code results: {len(code_results)}, Doc results: {len(doc_results)}")
        
        graph_context = []
        
        for i, result in enumerate(code_results[:3]):
            try:
                chunk = result.get('chunk')
                if not chunk:
                    logger.warning(f"Result {i} has no chunk")
                    continue
                
                metadata = chunk.get('metadata', {})
                program_id = metadata.get('program_id')
                
                if not program_id:
                    logger.debug(f"Result {i} has no program_id")
                    continue
                
                node_id = f"prog:{program_id}"
                
                if not self.graph.graph.has_node(node_id):
                    logger.debug(f"Node {node_id} not in graph")
                    continue
                
                neighbors = self.graph.get_neighbors(node_id, depth=1)
                
                if neighbors and 'error' not in neighbors:
                    graph_context.append({
                        'program': program_id,
                        'neighbors': neighbors
                    })
                    logger.debug(f"Added graph context for {program_id}")
                
            except Exception as e:
                logger.warning(f"Error processing result {i}: {e}")
                continue
        
        logger.info(f"Graph context collected: {len(graph_context)} programs")
        
        return {
            'query': query,
            'code_results': code_results,
            'doc_results': doc_results,
            'graph_context': graph_context
        }
    
    # Apply patch
    MCPServer._combined_search = safe_combined_search
    logger.info("✓ Patched MCPServer._combined_search (SAFETY)")


# ============================================================================
# PATCH 7: COBOLIndexer to use enhanced methods
# ============================================================================

def patch_cobol_indexer():
    """Ensure COBOLIndexer uses all enhanced methods"""
    from cobol_rag_agent import COBOLIndexer
    from pathlib import Path
    
    original_index_directory = COBOLIndexer.index_directory
    
    def enhanced_index_directory(self, source_dir: str):
        """Enhanced indexing with all fixes"""
        source_path = Path(source_dir)
        
        logger.info(f"Indexing directory: {source_dir}")
        
        cobol_files = list(source_path.rglob('*.cbl')) + list(source_path.rglob('*.cob'))
        jcl_files = list(source_path.rglob('*.jcl'))
        copybook_files = list(source_path.rglob('*.cpy'))
        
        logger.info(f"Found {len(cobol_files)} COBOL, {len(jcl_files)} JCL, {len(copybook_files)} copybooks")
        
        all_chunks = []
        for filepath in cobol_files:
            logger.info(f"Processing: {filepath}")
            with open(filepath, 'r', encoding='latin-1', errors='ignore') as f:
                source_code = f.read()
            
            chunks = self.cobol_parser.parse_cobol(source_code, str(filepath))
            all_chunks.extend(chunks)
            
            program_id = self._extract_program_id_from_chunks(chunks)
            self.graph.add_program(program_id, str(filepath))
            
            # Extract calls with dynamic resolution
            calls = self.cobol_parser.extract_calls(source_code)
            logger.info(f"Processing {len(calls)} calls from {program_id}")
            
            for call in calls:
                target = call.get('target')
                call_mechanism = call.get('call_mechanism', call.get('type', 'static'))
                
                call_type_map = {
                    'STATIC_CALL': 'static',
                    'DYNAMIC_CALL': 'dynamic',
                    'CICS_LINK': 'cics_link',
                    'CICS_LINK_DYNAMIC': 'cics_link_dynamic',
                    'CICS_XCTL': 'cics_xctl',
                    'CICS_XCTL_DYNAMIC': 'cics_xctl_dynamic',
                    'static': 'static',
                    'dynamic': 'dynamic',
                    'cics_link': 'cics_link',
                    'cics_xctl': 'cics_xctl'
                }
                
                simple_call_type = call_type_map.get(call_mechanism, 'static')
                
                if target:
                    logger.info(f"  → Adding call: {program_id} -> {target} ({simple_call_type})")
                    self.graph.add_call(program_id, target, simple_call_type)
                
                # Dynamic call resolution
                if call.get('is_dynamic') and call.get('possible_targets'):
                    logger.info(f"  → Dynamic call resolved to {len(call['possible_targets'])} targets")
                    for resolved_target in call['possible_targets']:
                        logger.info(f"    → {program_id} -> {resolved_target} ({simple_call_type})")
                        self.graph.add_call(program_id, resolved_target, simple_call_type)
            
            # Extract DB2 operations
            db2_ops = self.cobol_parser.extract_db2_operations(source_code)
            for op in db2_ops:
                if op['table']:
                    self.graph.add_db2_table(program_id, op['table'], op['type'])
            
            # Extract CICS commands (now creates file nodes)
            cics_cmds = self.cobol_parser.extract_cics_commands(source_code)
            for cmd in cics_cmds:
                self.graph.add_cics_command(program_id, cmd)
            
            # Extract MQ operations
            mq_ops = self.cobol_parser.extract_mq_operations(source_code)
            for op in mq_ops:
                self.graph.add_mq_queue(program_id, op['operation'])
        
        # Process JCL files
        for filepath in jcl_files:
            logger.info(f"Processing JCL: {filepath}")
            with open(filepath, 'r', encoding='latin-1', errors='ignore') as f:
                source_code = f.read()
            
            chunks = self.jcl_parser.parse_jcl(source_code, str(filepath))
            all_chunks.extend(chunks)
        
        self.code_index.add_chunks(all_chunks)
        
        logger.info("Indexing complete!")
    
    # Apply patch
    COBOLIndexer.index_directory = enhanced_index_directory
    logger.info("✓ Patched COBOLIndexer.index_directory (COMPLETE)")


# ============================================================================
# MASTER PATCH APPLICATION
# ============================================================================

def apply_all_patches():
    """Apply all patches in correct order"""
    logger.info("=" * 70)
    logger.info("APPLYING UNIFIED COBOL RAG PATCHES v1.0.5")
    logger.info("=" * 70)
    
    try:
        # Core parsing fixes
        patch_treesitter_languages()
        patch_dynamic_call_resolution()  # CRITICAL for dynamic calls
        patch_cics_file_extraction()
        
        # Graph building fixes
        patch_graph_builder_cics()  # CRITICAL for file nodes
        
        # Visualization fixes
        patch_flow_diagram_colors()
        
        # Safety fixes
        patch_combined_search()
        
        # Integration fixes
        patch_cobol_indexer()
        
        logger.info("=" * 70)
        logger.info("✓ ALL UNIFIED PATCHES APPLIED SUCCESSFULLY")
        logger.info("Features enabled:")
        logger.info("  ✓ Dynamic call resolution (with VALUE clauses)")
        logger.info("  ✓ CICS file extraction (INPUT/OUTPUT classification)")
        logger.info("  ✓ CICS file graph nodes (proper file nodes created)")
        logger.info("  ✓ Flow diagram colors (green/blue/red/orange)")
        logger.info("  ✓ combined_search safety (no crashes)")
        logger.info("  ✓ Tree-sitter detection (multiple methods)")
        logger.info("=" * 70)
        
    except Exception as e:
        logger.error(f"Failed to apply patches: {e}", exc_info=True)
        raise


# Auto-apply when imported
apply_all_patches()