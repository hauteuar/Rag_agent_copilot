"""
COBOL RAG Agent Patches v1.0.4 - COMPREHENSIVE FIX
===================================================
Fixes ALL 4 reported issues:
1. CICS file extraction for search_code/full_program_chain
2. combined_search index out of bounds error
3. tree-sitter COBOL installation detection
4. Flow HTML color coding (all nodes showing blue instead of proper colors)

USAGE:
    import cobol_rag_patches_v104 as patches
    patches.apply_all_patches()
"""

import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


# ============================================================================
# FIX 1: CICS File Extraction (for search_code/full_program_chain)
# ============================================================================

def patch_cics_file_nodes():
    """
    Fix CICS file extraction to properly create input/output file nodes.
    This ensures files appear in search results and program chains.
    """
    from cobol_rag_agent import ProgramGraphBuilder
    
    def enhanced_add_cics_command(self, program_id: str, command_info: Dict):
        """
        Enhanced CICS handler that creates proper file nodes.
        
        Handles 3 formats:
        1. New dict with 'resource' key
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
        
        # Format detection and parsing
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
        
        # OLD FORMAT: Has 'command' but no 'resource' - parse statement
        elif 'command' in command_info:
            command = command_info.get('command', '').upper()
            statement = command_info.get('statement', '')
            
            if not statement:
                logger.debug(f"Old format with no statement: {command}")
                return
            
            logger.debug(f"Parsing OLD format: {command}")
            
            # Extract resource from DATASET/FILE/QUEUE
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
                logger.debug(f"No resource found in: {statement[:100]}")
                return
            
            # Determine I/O direction
            input_ops = {'READ', 'READNEXT', 'READPREV', 'STARTBR'}
            output_ops = {'WRITE', 'REWRITE', 'DELETE'}
            
            if command in input_ops:
                io_direction = 'INPUT'
            elif command in output_ops:
                io_direction = 'OUTPUT'
            else:
                logger.debug(f"Unknown I/O type for {command}, skipping")
                return
            
            logger.info(f"✓ Classified as {io_direction}: {command} {resource}")
        
        else:
            logger.warning(f"Unknown dict format: {command_info}")
            return
        
        # Validate we have required info
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
            
            # Edge: file -> program
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
            
            # Edge: program -> file
            self.graph.add_edge(
                prog_node,
                file_node,
                edge_type='cics_write',
                operation=command
            )
        
        logger.info(f"✓ Added CICS {io_direction} file: {resource} ({command})")
    
    # Apply patch
    ProgramGraphBuilder.add_cics_command = enhanced_add_cics_command
    logger.info("✓ Patched ProgramGraphBuilder.add_cics_command (CICS files now appear in results)")


# ============================================================================
# FIX 2: combined_search Index Out of Bounds
# ============================================================================

def patch_combined_search():
    """
    Fix combined_search to handle empty results and prevent index errors.
    """
    from cobol_rag_agent import MCPServer
    
    def safe_combined_search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Safe combined search with bounds checking"""
        query = params.get('query', '')
        top_k = params.get('top_k', 5)
        
        logger.info(f"Combined search: '{query}' (top_k={top_k})")
        
        # Search code and docs
        code_results = self.code_index.search(query, top_k)
        doc_results = self.doc_index.search(query, top_k)
        
        logger.info(f"Code results: {len(code_results)}, Doc results: {len(doc_results)}")
        
        # Collect graph context safely
        graph_context = []
        
        # Only process results that exist
        for i, result in enumerate(code_results[:3]):  # Limit to top 3
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
                
                # Check if node exists before getting neighbors
                if not self.graph.graph.has_node(node_id):
                    logger.debug(f"Node {node_id} not in graph")
                    continue
                
                neighbors = self.graph.get_neighbors(node_id, depth=1)
                
                # Add to context if neighbors found
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
    logger.info("✓ Patched MCPServer._combined_search (fixed index errors)")


# ============================================================================
# FIX 3: Tree-sitter COBOL Installation Detection
# ============================================================================

def patch_treesitter_detection():
    """
    Enhanced tree-sitter detection that tries multiple methods and provides
    clear feedback about what's available.
    """
    from cobol_rag_agent import COBOLParser
    
    def enhanced_init_parser(self):
        """Try multiple tree-sitter installation methods"""
        try:
            # Method 1: tree_sitter_languages (easiest)
            try:
                from tree_sitter_languages import get_parser
                self.parser = get_parser('cobol')
                logger.info("✓ Tree-Sitter: Using tree_sitter_languages")
                return
            except ImportError:
                logger.debug("tree_sitter_languages not installed")
            except Exception as e:
                logger.debug(f"tree_sitter_languages failed: {e}")
            
            # Method 2: tree_sitter_cobol (new API)
            try:
                from tree_sitter import Parser
                import tree_sitter_cobol
                
                self.parser = Parser()
                self.parser.set_language(tree_sitter_cobol.language())
                logger.info("✓ Tree-Sitter: Using tree_sitter_cobol")
                return
            except ImportError:
                logger.debug("tree_sitter_cobol not installed")
            except Exception as e:
                logger.debug(f"tree_sitter_cobol failed: {e}")
            
            # Method 3: Old API with .so file
            try:
                from tree_sitter import Language, Parser
                
                COBOL_LANGUAGE = Language('build/cobol.so', 'cobol')
                self.parser = Parser()
                self.parser.set_language(COBOL_LANGUAGE)
                logger.info("✓ Tree-Sitter: Using legacy .so file")
                return
            except Exception as e:
                logger.debug(f"Legacy API failed: {e}")
            
            # All methods failed - use heuristic parser
            raise Exception("No tree-sitter installation found")
            
        except Exception as e:
            logger.warning("Tree-sitter COBOL not available - using heuristic parser")
            logger.info("To install tree-sitter: pip install tree-sitter-languages")
            self.parser = None
    
    # Apply patch
    COBOLParser._init_parser = enhanced_init_parser
    logger.info("✓ Patched COBOLParser._init_parser (better tree-sitter detection)")


# ============================================================================
# FIX 4: Flow HTML Color Coding
# ============================================================================

def patch_flow_html_colors():
    """
    Fix flow HTML generation to use correct Mermaid class names.
    The issue is that node types in the graph don't match Mermaid class names.
    """
    from cobol_rag_agent import EnhancedFlowDiagramGenerator
    
    def fixed_generate_mermaid(self, root_program: str, flow_data: Dict, max_depth: int) -> str:
        """
        Generate Mermaid with CORRECT class assignments based on node_type.
        
        Node types from graph:
        - 'program' -> programStyle (blue)
        - 'cics_input_file' -> inputFileStyle (green)
        - 'cics_output_file' -> outputFileStyle (red)
        - 'db2_table' -> databaseStyle (green)
        - 'mq_operation' -> mqStyle (orange)
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
            """Clean name for Mermaid ID"""
            return name.replace('-', '_').replace('.', '_').replace('/', '_').replace(' ', '_').replace(':', '_')
        
        # Track added nodes and edges
        added_nodes = set()
        added_edges = set()
        
        # Add root program
        root_id = clean_id(root_program)
        lines.append(f"    {root_id}[\"🔷 {root_program}<br/><b>MAIN PROGRAM</b>\"]")
        lines.append(f"    class {root_id} programStyle")
        added_nodes.add(root_id)
        lines.append("")
        
        # Helper to determine class based on node type
        def get_node_class(node_id: str) -> str:
            """Get Mermaid class based on node type in graph"""
            if not self.graph.has_node(node_id):
                return 'programStyle'
            
            node_data = self.graph.nodes[node_id]
            node_type = node_data.get('node_type', 'program')
            
            # Map node types to classes
            type_to_class = {
                'program': 'programStyle',
                'cics_input_file': 'inputFileStyle',
                'cics_output_file': 'outputFileStyle',
                'db2_table': 'databaseStyle',
                'mq_operation': 'mqStyle',
                'mq_queue': 'mqStyle'
            }
            
            return type_to_class.get(node_type, 'programStyle')
        
        # Add input files at top
        if flow_data.get('input_files'):
            lines.append("    %% Input Files (Top)")
            for file in flow_data['input_files']:
                file_id = clean_id(f"cics_input:{file}")
                
                if file_id not in added_nodes:
                    lines.append(f"    {file_id}[\"📥 {file}<br/><small>INPUT FILE</small>\"]")
                    
                    # Get correct class from graph
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
                    # Database symbol
                    lines.append(f"    {table_id}[(\"🗄️ {table}<br/><small>{operation}</small>\")]")
                    
                    # Get correct class
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
                file_id = clean_id(f"cics_output:{file}")
                
                if file_id not in added_nodes:
                    lines.append(f"    {file_id}[\"📤 {file}<br/><small>OUTPUT FILE</small>\"]")
                    
                    # Get correct class
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
                    
                    # Get correct class
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
    EnhancedFlowDiagramGenerator._generate_mermaid_with_files = fixed_generate_mermaid
    logger.info("✓ Patched EnhancedFlowDiagramGenerator (colors now work correctly)")


# ============================================================================
# FIX 4B: ProgramChainAnalyzer for full_program_chain
# ============================================================================

def patch_chain_analyzer():
    """
    Fix ProgramChainAnalyzer to properly collect CICS files for full_program_chain.
    """
    from cobol_rag_agent import ProgramChainAnalyzer
    
    def enhanced_traverse_chain(self, node: str, chain: Dict, visited: set, depth: int, max_depth: int):
        """Enhanced chain traversal that properly handles CICS files"""
        if depth > max_depth or node in visited:
            return
        
        visited.add(node)
        
        if not self.graph.has_node(node):
            return
        
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
            
            # PROGRAMS
            if succ_type == 'program':
                step['calls'].append({
                    'program': succ_name,
                    'call_type': edge_data.get('type', 'static') if edge_data else 'static'
                })
                chain['programs_called'].append(succ_name)
                
                # Recursively analyze
                self._traverse_chain(successor, chain, visited, depth + 1, max_depth)
            
            # CICS OUTPUT FILES
            elif succ_type == 'cics_output_file':
                file_info = {
                    'name': succ_name,
                    'operation': edge_data.get('operation', 'WRITE') if edge_data else 'WRITE',
                    'type': 'CICS_OUTPUT'
                }
                step['outputs'].append(file_info)
                
                if succ_name not in chain['files'].get('output', []):
                    chain['files']['output'].append(succ_name)
            
            # DB2 TABLES
            elif succ_type == 'db2_table':
                operation = edge_data.get('operation', 'ACCESS') if edge_data else 'ACCESS'
                db_info = {'table': succ_name, 'operation': operation}
                
                if operation in ['SELECT', 'READ']:
                    step['inputs'].append(db_info)
                else:
                    step['outputs'].append(db_info)
                
                if succ_name not in [d['table'] for d in chain['databases']]:
                    chain['databases'].append(db_info)
            
            # MQ OPERATIONS
            elif succ_type in ['mq_operation', 'mq_queue']:
                mq_info = {'operation': succ_name}
                
                if 'GET' in succ_name.upper() or 'READ' in succ_name.upper():
                    step['inputs'].append(mq_info)
                else:
                    step['outputs'].append(mq_info)
                
                if succ_name not in chain['mq_queues']:
                    chain['mq_queues'].append(succ_name)
        
        # Analyze predecessors for CICS INPUT FILES
        for predecessor in self.graph.predecessors(node):
            pred_data = self.graph.nodes.get(predecessor, {})
            pred_type = pred_data.get('node_type', '')
            pred_name = pred_data.get('name', predecessor)
            edge_data = self.graph.get_edge_data(predecessor, node)
            
            # CICS INPUT FILES
            if pred_type == 'cics_input_file':
                file_info = {
                    'name': pred_name,
                    'operation': edge_data.get('operation', 'READ') if edge_data else 'READ',
                    'type': 'CICS_INPUT'
                }
                step['inputs'].append(file_info)
                
                if pred_name not in chain['files'].get('input', []):
                    chain['files']['input'].append(pred_name)
        
        chain['execution_flow'].append(step)
    
    # Apply patch
    ProgramChainAnalyzer._traverse_chain = enhanced_traverse_chain
    logger.info("✓ Patched ProgramChainAnalyzer._traverse_chain (CICS files now appear)")


# ============================================================================
# MASTER PATCH APPLICATION
# ============================================================================

def apply_all_patches():
    """Apply all v1.0.4 patches"""
    logger.info("=" * 70)
    logger.info("APPLYING COBOL RAG AGENT PATCHES v1.0.4")
    logger.info("=" * 70)
    
    try:
        # Apply all fixes
        patch_cics_file_nodes()
        patch_combined_search()
        patch_treesitter_detection()
        patch_flow_html_colors()
        patch_chain_analyzer()
        
        logger.info("=" * 70)
        logger.info("✓ ALL v1.0.4 PATCHES APPLIED SUCCESSFULLY")
        logger.info("Fixes:")
        logger.info("  1. ✓ CICS files now appear in search_code/full_program_chain")
        logger.info("  2. ✓ combined_search no longer crashes with index errors")
        logger.info("  3. ✓ Tree-sitter detection improved with clear messages")
        logger.info("  4. ✓ Flow HTML colors now work correctly (green/blue/red/orange)")
        logger.info("=" * 70)
        
    except Exception as e:
        logger.error(f"Failed to apply patches: {e}", exc_info=True)
        raise


# Auto-apply when imported
if __name__ != '__main__':
    apply_all_patches()


if __name__ == '__main__':
    # Allow manual application
    apply_all_patches()
    print("✓ All patches applied successfully!")