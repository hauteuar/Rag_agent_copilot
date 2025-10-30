"""
cobol_rag_patches.py - Runtime Patches for COBOL RAG Agent
===========================================================
This module provides runtime patches to add file I/O tracking and
complete flow diagram generation.

USAGE:
    # At the top of your script, before other imports:
    import cobol_rag_patches
    cobol_rag_patches.apply_patches()
    
    # Then import and use normally:
    from cobol_rag_agent import COBOLIndexer, MCPServer
"""

import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def patch_program_graph_builder():
    """Add file tracking methods to ProgramGraphBuilder"""
    from cobol_rag_agent import ProgramGraphBuilder
    
    def add_file(self, program: str, filename: str, operation: str = 'ACCESS', file_type: str = 'file'):
        """Add a file node and link it to a program"""
        file_node = f"{filename}"
        
        if not self.graph.has_node(file_node):
            self.graph.add_node(
                file_node,
                type='file',
                file_type=file_type,
                name=filename
            )
            logger.debug(f"Added file node: {file_node}")
        
        if not self.graph.has_edge(program, file_node):
            self.graph.add_edge(
                program,
                file_node,
                type='file_access',
                operation=operation
            )
            logger.debug(f"Added file access: {program} -> {file_node} ({operation})")
    
    def add_input_file(self, program: str, filename: str):
        """Add an input file relationship"""
        self.add_file(program, filename, operation='INPUT')
    
    def add_output_file(self, program: str, filename: str):
        """Add an output file relationship"""
        self.add_file(program, filename, operation='OUTPUT')
    
    # Apply patches
    ProgramGraphBuilder.add_file = add_file
    ProgramGraphBuilder.add_input_file = add_input_file
    ProgramGraphBuilder.add_output_file = add_output_file
    
    logger.info("✓ Patched ProgramGraphBuilder with file tracking methods")


def patch_cobol_parser():
    """Add file operation extraction to COBOLParser"""
    from cobol_rag_agent import COBOLParser
    
    def extract_file_operations(self, source_code: str) -> List[Dict[str, Any]]:
        """Extract all file operations from COBOL code"""
        file_ops = []
        lines = source_code.split('\n')
        
        # Pattern 1: SELECT statements
        select_pattern = re.compile(
            r'SELECT\s+([A-Z0-9\-]+)\s+ASSIGN\s+(?:TO\s+)?([A-Z0-9\-]+)',
            re.IGNORECASE
        )
        
        # Pattern 2: OPEN statements
        open_pattern = re.compile(
            r'OPEN\s+(INPUT|OUTPUT|I-O|EXTEND)\s+([A-Z0-9\-\s]+)',
            re.IGNORECASE
        )
        
        # Pattern 3: READ statements
        read_pattern = re.compile(
            r'READ\s+([A-Z0-9\-]+)',
            re.IGNORECASE
        )
        
        # Pattern 4: WRITE statements
        write_pattern = re.compile(
            r'WRITE\s+([A-Z0-9\-]+)',
            re.IGNORECASE
        )
        
        # Track SELECT statements
        file_to_dd = {}
        
        for line_num, line in enumerate(lines, 1):
            if len(line) > 6:
                code_line = line[6:72] if len(line) > 72 else line[6:]
            else:
                code_line = line
            
            # SELECT
            select_match = select_pattern.search(code_line)
            if select_match:
                file_name = select_match.group(1)
                dd_name = select_match.group(2)
                file_to_dd[file_name] = dd_name
                
                file_ops.append({
                    'file_name': file_name,
                    'dd_name': dd_name,
                    'operation': 'DECLARE',
                    'line_number': line_num
                })
            
            # OPEN
            open_match = open_pattern.search(code_line)
            if open_match:
                operation = open_match.group(1).upper()
                file_list = open_match.group(2).strip()
                
                for file_name in file_list.split():
                    file_name = file_name.strip()
                    if file_name:
                        dd_name = file_to_dd.get(file_name, file_name)
                        
                        file_ops.append({
                            'file_name': file_name,
                            'dd_name': dd_name,
                            'operation': operation,
                            'line_number': line_num
                        })
            
            # READ
            read_match = read_pattern.search(code_line)
            if read_match:
                file_name = read_match.group(1)
                dd_name = file_to_dd.get(file_name, file_name)
                
                file_ops.append({
                    'file_name': file_name,
                    'dd_name': dd_name,
                    'operation': 'READ',
                    'line_number': line_num
                })
            
            # WRITE
            write_match = write_pattern.search(code_line)
            if write_match:
                file_name = write_match.group(1)
                dd_name = file_to_dd.get(file_name, file_name)
                
                file_ops.append({
                    'file_name': file_name,
                    'dd_name': dd_name,
                    'operation': 'WRITE',
                    'line_number': line_num
                })
        
        logger.debug(f"Found {len(file_ops)} file operations")
        return file_ops
    
    # Apply patch
    COBOLParser.extract_file_operations = extract_file_operations
    
    logger.info("✓ Patched COBOLParser with file operation extraction")


def patch_cobol_indexer():
    """Enhance COBOLIndexer to process file operations"""
    from cobol_rag_agent import COBOLIndexer
    
    # Store original method
    original_index_directory = COBOLIndexer.index_directory
    
    def enhanced_index_directory(self, source_dir: str):
        """Enhanced indexing with file I/O tracking"""
        # Call original method
        original_index_directory(self, source_dir)
        
        # Now add file operations (this happens after initial indexing)
        logger.info("Adding file I/O relationships...")
        
        # Re-process COBOL files to add file operations
        from pathlib import Path
        cobol_files = list(Path(source_dir).rglob('*.cbl')) + \
                     list(Path(source_dir).rglob('*.cob')) + \
                     list(Path(source_dir).rglob('*.cobol'))
        
        file_count = 0
        for filepath in cobol_files:
            try:
                with open(filepath, 'r', encoding='latin-1', errors='ignore') as f:
                    source_code = f.read()
                
                # Extract program ID
                program_id = "UNKNOWN"
                prog_match = re.search(r'PROGRAM-ID\.\s+(\S+)', source_code, re.IGNORECASE)
                if prog_match:
                    program_id = prog_match.group(1).strip('.')
                
                if not self.graph.graph.has_node(program_id):
                    continue
                
                # Extract and add file operations
                file_ops = self.cobol_parser.extract_file_operations(source_code)
                for file_op in file_ops:
                    operation = file_op['operation']
                    dd_name = file_op['dd_name']
                    
                    if operation in ['INPUT', 'READ']:
                        self.graph.add_input_file(program_id, dd_name)
                    elif operation in ['OUTPUT', 'WRITE', 'EXTEND']:
                        self.graph.add_output_file(program_id, dd_name)
                    elif operation in ['I-O']:
                        self.graph.add_input_file(program_id, dd_name)
                        self.graph.add_output_file(program_id, dd_name)
                
                if file_ops:
                    file_count += len(file_ops)
                    logger.debug(f"  {program_id}: added {len(file_ops)} file operations")
            
            except Exception as e:
                logger.error(f"Error processing file operations for {filepath}: {e}")
        
        logger.info(f"✓ Added {file_count} file I/O relationships")
    
    # Apply patch
    COBOLIndexer.index_directory = enhanced_index_directory
    
    logger.info("✓ Patched COBOLIndexer with enhanced file processing")


def patch_mcp_server():
    """Enhance MCPServer with better flow diagram generation"""
    from cobol_rag_agent import MCPServer
    
    def enhanced_flow_mermaid(self, program: str, max_depth: int = 3) -> Dict[str, Any]:
        """Generate comprehensive flow diagram"""
        try:
            from enhanced_flow_diagram_generator import EnhancedFlowDiagramGenerator
            
            generator = EnhancedFlowDiagramGenerator(self.graph)
            # Use generate_flow() which is the main entry point
            result = generator.generate_flow(program, max_depth)
            
            return result
        
        except ImportError:
            logger.error("EnhancedFlowDiagramGenerator not found!")
            # Fallback to basic generation
            return {
                'mermaid_diagram': self._generate_basic_mermaid(program),
                'programs_called': [],
                'input_files': [],
                'output_files': [],
                'databases': [],
                'mq_queues': [],
                'execution_flow': []
            }
    
    def _generate_basic_mermaid(self, program: str) -> str:
        """Fallback basic mermaid generation"""
        if not self.graph.graph.has_node(program):
            return "graph TB\n    A[Program Not Found]"
        
        lines = ["graph TB"]
        lines.append(f"    {program}[\"{program}\"]")
        
        for successor in self.graph.graph.successors(program):
            lines.append(f"    {successor}[\"{successor}\"]")
            lines.append(f"    {program} --> {successor}")
        
        return '\n'.join(lines)
    
    # Apply patches
    MCPServer.flow_mermaid = enhanced_flow_mermaid
    MCPServer._generate_basic_mermaid = _generate_basic_mermaid
    
    logger.info("✓ Patched MCPServer with enhanced flow generation")


def apply_patches():
    """Apply all patches to the COBOL RAG Agent"""
    logger.info("=" * 70)
    logger.info("Applying COBOL RAG Agent Patches...")
    logger.info("=" * 70)
    
    try:
        patch_program_graph_builder()
        patch_cobol_parser()
        patch_cobol_indexer()
        patch_mcp_server()
        
        logger.info("=" * 70)
        logger.info("✓ All patches applied successfully!")
        logger.info("=" * 70)
        logger.info("")
        logger.info("Enhanced features now available:")
        logger.info("  • File I/O tracking (input/output files)")
        logger.info("  • Complete call chain visualization")
        logger.info("  • Enhanced flow diagrams with all relationships")
        logger.info("")
        
        return True
    
    except Exception as e:
        logger.error(f"Failed to apply patches: {e}")
        logger.error("Make sure cobol_rag_agent.py is in the same directory")
        return False


# Auto-apply patches when module is imported
if __name__ != '__main__':
    apply_patches()