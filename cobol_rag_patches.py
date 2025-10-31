"""
COBOL RAG Agent Patches - Dynamic Call Resolution & CICS File Extraction
=========================================================================
This module patches cobol_rag_agent.py to fix:
1. Dynamic call resolution for group variables with subscripts
2. CICS command extraction to show actual file names instead of command types
3. Enhanced flow diagram with proper I/O classification

USAGE:
    import cobol_rag_patches  # Auto-applies all patches
"""

import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def patch_dynamic_call_resolution():
    """
    Patch COBOLParser._resolve_dynamic_call_variables to handle:
    - Group-level VALUE clauses (01 WA-CONSTANTS with 05 WA-VAR VALUE 'PROG')
    - Subscripted variables (MOVE WA-VAR(INDEX) TO CALL-VAR)
    - Reference modifications (MOVE WA-VAR(1:8) TO CALL-VAR)
    """
    from cobol_rag_agent import COBOLParser
    
    def enhanced_resolve_dynamic_call_variables(self, calls: List[Dict], source_code: str) -> List[Dict]:
        """
        Enhanced resolver that handles group variables with VALUE clauses.
        
        Example COBOL structure:
            01 WA-CONSTANTS.
               05 WA-TMSBTSI1 PIC X(08) VALUE 'TMSBTSI1'.
               05 WA-TMSBTSI3 PIC X(08) VALUE 'TMSBTSI3'.
            ...
            MOVE WA-TMSBTSI1 TO WS-PROGRAM-NAME
            CALL WS-PROGRAM-NAME
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
        
        # Pattern 2: MOVE from one variable to another (for subscripted access)
        move_var_pattern = re.compile(
            r"MOVE\s+([A-Z0-9\-]+(?:\([^)]*\))?(?:\.[A-Z0-9\-]+)?(?:\([^)]*\))?)\s+TO\s+"
            r"([A-Z0-9\-]+(?:\([^)]*\))?(?:\.[A-Z0-9\-]+)?(?:\([^)]*\))?)",
            re.IGNORECASE
        )
        
        # Pattern 3: Variable definitions with VALUE clause
        # This is critical for catching group-level constants
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
                # Extract base variable name (remove subscripts and ref mods)
                variable = literal_match.group(2)
                base_var = re.sub(r'\([^)]*\)', '', variable)  # Remove subscripts
                base_var = re.sub(r'\.[A-Z0-9\-]+$', '', base_var)  # Remove field qualifiers
                
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
            
            # Pattern 2: MOVE variable to variable (for tracing)
            var_match = move_var_pattern.search(clean_line)
            if var_match and not literal_match:  # Don't double-process
                source_var = var_match.group(1)
                target_var = var_match.group(2)
                
                # Extract base names
                base_source = re.sub(r'\([^)]*\)', '', source_var)
                base_target = re.sub(r'\([^)]*\)', '', target_var)
                
                # If source variable has known values, propagate them
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
        logger.debug(f"Variable values map built: {len(variable_values)} variables found")
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
            base_var = re.sub(r'\([^)]*\)', '', variable)  # Remove subscripts
            
            logger.debug(f"\nResolving dynamic call: {variable} (base: {base_var})")
            
            # Direct match
            if base_var in variable_values:
                call['possible_targets'] = list(set([v['value'] for v in variable_values[base_var]]))
                call['resolution_details'] = variable_values[base_var]
                resolved_count += 1
                logger.info(f"✓ Resolved {variable} → {call['possible_targets']}")
                continue
            
            # Fuzzy match: check if variable is part of a group
            found_match = False
            for var_name, values in variable_values.items():
                # Check for partial matches (e.g., BUSINESS might match BUSINESS-FUNC)
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
    logger.info("✓ Patched COBOLParser._resolve_dynamic_call_variables")


def patch_cics_file_extraction():
    """
    Patch COBOLParser to extract actual file/dataset names from CICS commands
    and determine if they're input or output based on operation type.
    """
    from cobol_rag_agent import COBOLParser
    
    def enhanced_extract_cics_commands(self, source_code: str) -> List[Dict[str, Any]]:
        """
        Extract CICS commands with actual file/dataset names and I/O classification.
        
        Operations classified as:
        - INPUT: READ, READNEXT, READPREV, STARTBR
        - OUTPUT: WRITE, REWRITE, DELETE
        - BOTH: (no classification - treat as input)
        
        Extracts from:
        - DATASET(...) for file operations
        - FILE(...) for file operations
        - QUEUE(...) for queue operations
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
                    # Process previous CICS statement
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
                    # Process complete CICS statement
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
        """Parse a single CICS statement to extract I/O operations"""
        commands = []
        
        # Extract CICS command
        cmd_match = re.search(r'EXEC\s+CICS\s+(\w+)', statement, re.IGNORECASE)
        if not cmd_match:
            return commands
        
        command = cmd_match.group(1).upper()
        
        # Skip control operations (ENDBR, UNLOCK, etc.)
        if command in control_ops:
            logger.debug(f"Skipping control operation: {command}")
            return commands
        
        # Extract resource name from DATASET, FILE, or QUEUE
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
            # No explicit resource found
            logger.debug(f"No resource found in CICS {command}")
            return commands
        
        # Determine I/O direction
        io_direction = 'UNKNOWN'
        if command in input_ops:
            io_direction = 'INPUT'
        elif command in output_ops:
            io_direction = 'OUTPUT'
        
        # Skip if not a recognized I/O operation
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
    logger.info("✓ Patched COBOLParser.extract_cics_commands")


def patch_graph_builder_cics():
    """
    Patch ProgramGraphBuilder to properly handle CICS file nodes as I/O
    """
    from cobol_rag_agent import ProgramGraphBuilder
    
    def enhanced_add_cics_command(self, program_id: str, command_info: Dict[str, Any]):
        """
        Add CICS file as input or output node based on operation type.
        
        Args:
            command_info: Dict with keys:
                - command: CICS command (READ, WRITE, etc.)
                - resource: File/dataset name
                - resource_type: DATASET, FILE, or QUEUE
                - io_direction: INPUT or OUTPUT
        """
        resource = command_info.get('resource')
        resource_type = command_info.get('resource_type', 'FILE')
        io_direction = command_info.get('io_direction', 'INPUT')
        command = command_info.get('command', 'UNKNOWN')
        
        if not resource:
            return
        
        # Create file node ID
        if io_direction == 'INPUT':
            file_node = f"cics_input:{resource}"
            node_type = 'cics_input_file'
        else:
            file_node = f"cics_output:{resource}"
            node_type = 'cics_output_file'
        
        # Add file node if it doesn't exist
        if not self.graph.has_node(file_node):
            self.graph.add_node(
                file_node,
                node_type=node_type,
                name=resource,
                resource_type=resource_type,
                cics_operation=command
            )
        
        # Add edge: input -> program or program -> output
        prog_node = f"prog:{program_id}"
        
        if io_direction == 'INPUT':
            # Input file -> Program
            self.graph.add_edge(
                file_node,
                prog_node,
                edge_type='cics_read',
                operation=command
            )
        else:
            # Program -> Output file
            self.graph.add_edge(
                prog_node,
                file_node,
                edge_type='cics_write',
                operation=command
            )
        
        logger.debug(f"Added CICS {io_direction} file: {resource} ({command})")
    
    # Apply patch
    ProgramGraphBuilder.add_cics_command = enhanced_add_cics_command
    logger.info("✓ Patched ProgramGraphBuilder.add_cics_command")


def patch_flow_diagram_colors():
    """
    Patch EnhancedFlowDiagramGenerator to use proper colors:
    - Green for DB2 tables
    - Light green for input files
    - Red for output files
    - Blue for programs
    """
    from cobol_rag_agent import EnhancedFlowDiagramGenerator
    
    def enhanced_generate_mermaid_with_files(self, root_program: str, flow_data: Dict, max_depth: int) -> str:
        """
        Generate Mermaid diagram with proper styling:
        - Inputs at top (green)
        - Processing in middle (blue)
        - Databases with DB symbol (green)
        - Outputs at bottom (red)
        """
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
                file_id = clean_id(f"in_{file}")
                if file_id not in added_nodes:
                    lines.append(f"    {file_id}[\"📥 {file}<br/><small>INPUT FILE</small>\"]")
                    lines.append(f"    class {file_id} inputFileStyle")
                    added_nodes.add(file_id)
                
                edge = (file_id, root_id)
                if edge not in added_edges:
                    lines.append(f"    {file_id} -->|reads| {root_id}")
                    added_edges.add(edge)
            lines.append("")
        
        # Add database operations with DB symbol
        if flow_data.get('databases'):
            lines.append("    %% Database Tables")
            for db_info in flow_data['databases']:
                table = db_info['table']
                operation = db_info.get('operation', 'ACCESS')
                table_id = clean_id(f"db_{table}")
                
                if table_id not in added_nodes:
                    # Use database symbol
                    lines.append(f"    {table_id}[(\"🗄️ {table}<br/><small>{operation}</small>\")]")
                    lines.append(f"    class {table_id} databaseStyle")
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
                
                # Find caller
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
                file_id = clean_id(f"out_{file}")
                if file_id not in added_nodes:
                    lines.append(f"    {file_id}[\"📤 {file}<br/><small>OUTPUT FILE</small>\"]")
                    lines.append(f"    class {file_id} outputFileStyle")
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
                queue_id = clean_id(f"mq_{queue}")
                if queue_id not in added_nodes:
                    lines.append(f"    {queue_id}[\"📨 {queue}<br/><small>MQ QUEUE</small>\"]")
                    lines.append(f"    class {queue_id} mqStyle")
                    added_nodes.add(queue_id)
                
                edge = (root_id, queue_id)
                if edge not in added_edges:
                    lines.append(f"    {root_id} -.->|uses| {queue_id}")
                    added_edges.add(edge)
            lines.append("")
        
        return '\n'.join(lines)
    
    # Apply patch
    EnhancedFlowDiagramGenerator._generate_mermaid_with_files = enhanced_generate_mermaid_with_files
    logger.info("✓ Patched EnhancedFlowDiagramGenerator._generate_mermaid_with_files")


def patch_cobol_indexer():
    """
    Patch COBOLIndexer to use enhanced CICS command info
    """
    from cobol_rag_agent import COBOLIndexer
    
    # Store original method
    original_index_directory = COBOLIndexer.index_directory
    
    def enhanced_index_directory(self, source_dir: str):
        """Enhanced indexing that properly handles CICS I/O"""
        from pathlib import Path
        
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
            
            # Extract calls
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
            
            # Extract CICS commands (now returns enhanced dict)
            cics_cmds = self.cobol_parser.extract_cics_commands(source_code)
            for cmd in cics_cmds:
                # Use enhanced add_cics_command that handles I/O direction
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
    logger.info("✓ Patched COBOLIndexer.index_directory")


# Auto-apply all patches when module is imported
def apply_all_patches():
    """Apply all patches automatically"""
    logger.info("=" * 70)
    logger.info("APPLYING COBOL RAG AGENT PATCHES")
    logger.info("=" * 70)
    
    try:
        patch_dynamic_call_resolution()
        patch_cics_file_extraction()
        patch_graph_builder_cics()
        patch_flow_diagram_colors()
        patch_cobol_indexer()
        
        logger.info("=" * 70)
        logger.info("✓ ALL PATCHES APPLIED SUCCESSFULLY")
        logger.info("=" * 70)
        
    except Exception as e:
        logger.error(f"Failed to apply patches: {e}", exc_info=True)
        raise


# Apply patches when module is imported
apply_all_patches()