"""
COBOL RAG MCP Agent - Complete Implementation
==============================================
A comprehensive system for parsing COBOL/JCL code, building semantic indexes,
creating program call graphs, and serving queries via MCP protocol.

Installation Requirements:
pip install tree-sitter tree-sitter-cobol sentence-transformers faiss-cpu networkx numpy
"""

import os
import json
import sys
import re
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

# Tree-sitter imports
try:
    from tree_sitter import Language, Parser
except ImportError:
    print("Please install: pip install tree-sitter")
    sys.exit(1)

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
    chunk_type: str  # 'program', 'paragraph', 'section', 'copybook'
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
    """Parse COBOL source code using Tree-Sitter"""
    
    def __init__(self):
        self.parser = None
        self._init_parser()
    
    def _init_parser(self):
        """Initialize Tree-Sitter parser for COBOL"""
        try:
            # Note: You need to build the COBOL grammar first
            # git clone https://github.com/tree-sitter/tree-sitter-cobol
            # python build_cobol.py (see helper below)
            COBOL_LANGUAGE = Language('build/cobol.so', 'cobol')
            self.parser = Parser()
            self.parser.set_language(COBOL_LANGUAGE)
            logger.info("COBOL parser initialized successfully")
        except Exception as e:
            logger.warning(f"Tree-sitter COBOL not available: {e}")
            logger.info("Falling back to heuristic parser")
            self.parser = None
    
    def parse_cobol(self, source_code: str, filename: str) -> List[CodeChunk]:
        """Parse COBOL source code into structured chunks"""
        if self.parser:
            return self._parse_with_treesitter(source_code, filename)
        else:
            return self._parse_with_heuristics(source_code, filename)
    
    def _parse_with_treesitter(self, source_code: str, filename: str) -> List[CodeChunk]:
        """Parse using Tree-Sitter"""
        chunks = []
        tree = self.parser.parse(bytes(source_code, "utf8"))
        root_node = tree.root_node
        
        # Extract program identification
        program_id = self._extract_program_id(root_node, source_code)
        
        # Extract divisions, sections, paragraphs
        chunks.extend(self._extract_divisions(root_node, source_code, filename, program_id))
        chunks.extend(self._extract_paragraphs(root_node, source_code, filename, program_id))
        
        return chunks
    
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
            
            # Detect divisions
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
        
        # Extract paragraphs from PROCEDURE DIVISION
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
    
    def extract_calls(self, source_code: str) -> List[Dict[str, Any]]:
        """Extract CALL statements (static and dynamic)"""
        calls = []
        lines = source_code.split('\n')
        
        # Static calls: CALL 'PROGNAME'
        static_pattern = re.compile(r"CALL\s+['\"](\w+)['\"]", re.IGNORECASE)
        
        # Dynamic calls: CALL WS-PROG-NAME
        dynamic_pattern = re.compile(r"CALL\s+(\w+-\w+)", re.IGNORECASE)
        
        for i, line in enumerate(lines):
            clean_line = line[6:72] if len(line) > 6 else line
            
            # Static calls
            for match in static_pattern.finditer(clean_line):
                calls.append({
                    'type': 'static',
                    'target': match.group(1),
                    'line': i + 1,
                    'source_line': line.strip()
                })
            
            # Dynamic calls
            for match in dynamic_pattern.finditer(clean_line):
                calls.append({
                    'type': 'dynamic',
                    'variable': match.group(1),
                    'line': i + 1,
                    'source_line': line.strip()
                })
        
        return calls
    
    def extract_db2_operations(self, source_code: str) -> List[Dict[str, Any]]:
        """Extract DB2 SQL operations"""
        operations = []
        
        # EXEC SQL ... END-EXEC
        sql_pattern = re.compile(
            r'EXEC\s+SQL(.*?)END-EXEC', 
            re.IGNORECASE | re.DOTALL
        )
        
        for match in sql_pattern.finditer(source_code):
            sql_text = match.group(1).strip()
            
            # Detect operation type
            op_type = 'UNKNOWN'
            table_name = None
            
            if 'SELECT' in sql_text.upper():
                op_type = 'SELECT'
                table_match = re.search(r'FROM\s+(\w+)', sql_text, re.IGNORECASE)
                if table_match:
                    table_name = table_match.group(1)
            elif 'INSERT' in sql_text.upper():
                op_type = 'INSERT'
                table_match = re.search(r'INTO\s+(\w+)', sql_text, re.IGNORECASE)
                if table_match:
                    table_name = table_match.group(1)
            elif 'UPDATE' in sql_text.upper():
                op_type = 'UPDATE'
                table_match = re.search(r'UPDATE\s+(\w+)', sql_text, re.IGNORECASE)
                if table_match:
                    table_name = table_match.group(1)
            elif 'DELETE' in sql_text.upper():
                op_type = 'DELETE'
                table_match = re.search(r'FROM\s+(\w+)', sql_text, re.IGNORECASE)
                if table_match:
                    table_name = table_match.group(1)
            
            operations.append({
                'type': op_type,
                'table': table_name,
                'sql': sql_text
            })
        
        return operations
    
    def extract_cics_commands(self, source_code: str) -> List[Dict[str, Any]]:
        """Extract CICS commands"""
        commands = []
        
        # EXEC CICS ... END-EXEC
        cics_pattern = re.compile(
            r'EXEC\s+CICS\s+(.*?)END-EXEC', 
            re.IGNORECASE | re.DOTALL
        )
        
        for match in cics_pattern.finditer(source_code):
            cics_text = match.group(1).strip()
            
            # Extract command type
            cmd_match = re.match(r'(\w+)', cics_text, re.IGNORECASE)
            cmd_type = cmd_match.group(1) if cmd_match else 'UNKNOWN'
            
            commands.append({
                'command': cmd_type,
                'full_text': cics_text
            })
        
        return commands
    
    def extract_mq_operations(self, source_code: str) -> List[Dict[str, Any]]:
        """Extract MQ operations"""
        operations = []
        
        # MQPUT, MQGET, MQOPEN, MQCLOSE
        mq_pattern = re.compile(
            r'CALL\s+[\'"]?(MQ(?:PUT|GET|OPEN|CLOSE|CONN|DISC))[\'"]?',
            re.IGNORECASE
        )
        
        for match in mq_pattern.finditer(source_code):
            operations.append({
                'operation': match.group(1),
                'context': match.group(0)
            })
        
        return operations
    
    def _extract_program_id(self, node, source_code: str) -> str:
        """Extract program ID from AST"""
        # Implementation depends on tree-sitter-cobol structure
        return "UNKNOWN"
    
    def _extract_divisions(self, node, source_code: str, filename: str, program_id: str) -> List[CodeChunk]:
        """Extract divisions from AST"""
        return []
    
    def _extract_paragraphs(self, node, source_code: str, filename: str, program_id: str) -> List[CodeChunk]:
        """Extract paragraphs from AST"""
        return []


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
            # Skip comments
            if line.startswith('//*'):
                continue
            
            # Job card
            if line.startswith('//') and ' JOB ' in line:
                job_match = re.match(r'//(\w+)\s+JOB', line)
                if job_match:
                    job_name = job_match.group(1)
            
            # Step card
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
        
        # EXEC PGM=PROGNAME
        pgm_pattern = re.compile(r'EXEC\s+(?:PGM=|PROC=)(\w+)', re.IGNORECASE)
        
        for match in pgm_pattern.finditer(source_code):
            programs.append(match.group(1))
        
        return programs


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
    
    def add_call(self, from_program: str, to_program: str, call_type: str = 'static'):
        """Add a call edge between programs"""
        self.graph.add_edge(
            f"prog:{from_program}",
            f"prog:{to_program}",
            edge_type='calls',
            call_type=call_type
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
        
        # Get successors (outgoing edges)
        for successor in nx.descendants(self.graph, node_id):
            path_length = nx.shortest_path_length(self.graph, node_id, successor)
            if path_length <= depth:
                edge_data = self.graph.get_edge_data(node_id, successor) or {}
                neighbors['outgoing'].append({
                    'node': successor,
                    'distance': path_length,
                    'node_data': dict(self.graph.nodes[successor]),
                    'edge_type': edge_data.get('edge_type', 'unknown')
                })
        
        # Get predecessors (incoming edges)
        for predecessor in nx.ancestors(self.graph, node_id):
            path_length = nx.shortest_path_length(self.graph, predecessor, node_id)
            if path_length <= depth:
                edge_data = self.graph.get_edge_data(predecessor, node_id) or {}
                neighbors['incoming'].append({
                    'node': predecessor,
                    'distance': path_length,
                    'node_data': dict(self.graph.nodes[predecessor]),
                    'edge_type': edge_data.get('edge_type', 'unknown')
                })
        
        return neighbors
    
    def save_graph(self, filepath: str):
        """Save graph to file"""
        nx.write_gpickle(self.graph, filepath)
    
    def load_graph(self, filepath: str):
        """Load graph from file"""
        self.graph = nx.read_gpickle(filepath)


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
        
        # Generate embeddings
        texts = [f"{chunk.chunk_type}: {chunk.content}" for chunk in chunks]
        embeddings = self.model.encode(texts, show_progress_bar=True)
        
        # Add to FAISS index
        self.index.add(np.array(embeddings).astype('float32'))
        
        # Store chunks
        self.chunks.extend(chunks)
        
        logger.info(f"Added {len(chunks)} chunks to index. Total: {len(self.chunks)}")
    
    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Search for similar code chunks"""
        # Encode query
        query_embedding = self.model.encode([query])
        
        # Search
        distances, indices = self.index.search(
            np.array(query_embedding).astype('float32'), 
            top_k
        )
        
        # Format results
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

class FlowDiagramGenerator:
    """Generate Mermaid flow diagrams from program graph"""
    
    def __init__(self, graph: nx.DiGraph):
        self.graph = graph
    
    def generate_flow(self, node_id: str, depth: int = 2) -> FlowDiagram:
        """Generate Mermaid flow diagram for a node"""
        if not self.graph.has_node(node_id):
            return FlowDiagram(
                mermaid_code=f"graph TD\n  ERROR[Node {node_id} not found]",
                nodes=[],
                edges=[]
            )
        
        # Collect nodes and edges within depth
        visited_nodes = set([node_id])
        edges_list = []
        
        self._traverse_graph(node_id, depth, visited_nodes, edges_list)
        
        # Generate Mermaid code
        mermaid_lines = ["graph TD"]
        
        # Add nodes with styling based on type
        for node in visited_nodes:
            node_data = self.graph.nodes[node]
            node_type = node_data.get('node_type', 'unknown')
            node_name = node_data.get('name', node)
            
            # Style based on type
            if node_type == 'program':
                style = f"{self._safe_id(node)}[{node_name}]"
                mermaid_lines.append(f"  {style}")
                mermaid_lines.append(f"  style {self._safe_id(node)} fill:#4A90E2,stroke:#2E5C8A,color:#fff")
            elif node_type == 'db2_table':
                style = f"{self._safe_id(node)}[({node_name})]"
                mermaid_lines.append(f"  {style}")
                mermaid_lines.append(f"  style {self._safe_id(node)} fill:#50C878,stroke:#2D7A4A,color:#fff")
            elif node_type == 'mq_operation':
                style = f"{self._safe_id(node)}{{{{MQ: {node_name}}}}}"
                mermaid_lines.append(f"  {style}")
                mermaid_lines.append(f"  style {self._safe_id(node)} fill:#FFA500,stroke:#CC8400,color:#fff")
            elif node_type == 'cics_command':
                style = f"{self._safe_id(node)}[/CICS: {node_name}/]"
                mermaid_lines.append(f"  {style}")
                mermaid_lines.append(f"  style {self._safe_id(node)} fill:#9B59B6,stroke:#6C3483,color:#fff")
            else:
                style = f"{self._safe_id(node)}[{node_name}]"
                mermaid_lines.append(f"  {style}")
        
        # Add edges with labels
        for source, target, label in edges_list:
            edge_str = f"  {self._safe_id(source)} -->|{label}| {self._safe_id(target)}"
            mermaid_lines.append(edge_str)
        
        mermaid_code = '\n'.join(mermaid_lines)
        
        return FlowDiagram(
            mermaid_code=mermaid_code,
            nodes=list(visited_nodes),
            edges=edges_list
        )
    
    def _traverse_graph(self, node_id: str, depth: int, visited: Set[str], edges: List[Tuple[str, str, str]]):
        """Recursively traverse graph to collect nodes and edges"""
        if depth == 0:
            return
        
        # Outgoing edges
        for successor in self.graph.successors(node_id):
            if successor not in visited:
                visited.add(successor)
                edge_data = self.graph.get_edge_data(node_id, successor)
                edge_label = edge_data.get('edge_type', 'link') if edge_data else 'link'
                edges.append((node_id, successor, edge_label))
                self._traverse_graph(successor, depth - 1, visited, edges)
        
        # Incoming edges (limited to depth 1 to avoid clutter)
        if depth == 2:
            for predecessor in self.graph.predecessors(node_id):
                if predecessor not in visited:
                    visited.add(predecessor)
                    edge_data = self.graph.get_edge_data(predecessor, node_id)
                    edge_label = edge_data.get('edge_type', 'link') if edge_data else 'link'
                    edges.append((predecessor, node_id, edge_label))
    
    def _safe_id(self, node_id: str) -> str:
        """Convert node ID to Mermaid-safe identifier"""
        return node_id.replace(':', '_').replace('-', '_').replace('.', '_')


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
        self.diagram_gen = FlowDiagramGenerator(graph.graph)
    
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
            'mermaid': diagram.mermaid_code,
            'nodes': diagram.nodes,
            'edges': diagram.edges
        }
    
    def _resolve_dynamic_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve dynamic CALL using heuristics"""
        variable = params.get('variable', '')
        context = params.get('context', '')
        
        # Simple heuristic: look for MOVE statements
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
        
        # Search code
        code_results = self.code_index.search(query, top_k)
        
        # Search docs
        doc_results = self.doc_index.search(query, top_k)
        
        # Extract relevant nodes and get graph context
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
        self.code_index = VectorIndexBuilder()
        self.doc_index = VectorIndexBuilder()
        self.graph = ProgramGraphBuilder()
    
    def index_directory(self, source_dir: str):
        """Index all COBOL/JCL files in a directory"""
        source_path = Path(source_dir)
        
        logger.info(f"Indexing directory: {source_dir}")
        
        # Find all source files
        cobol_files = list(source_path.rglob('*.cbl')) + list(source_path.rglob('*.cob'))
        jcl_files = list(source_path.rglob('*.jcl'))
        copybook_files = list(source_path.rglob('*.cpy'))
        
        logger.info(f"Found {len(cobol_files)} COBOL files, {len(jcl_files)} JCL files, {len(copybook_files)} copybooks")
        
        # Process COBOL files
        all_chunks = []
        for filepath in cobol_files:
            logger.info(f"Processing: {filepath}")
            with open(filepath, 'r', encoding='latin-1', errors='ignore') as f:
                source_code = f.read()
            
            # Parse and extract
            chunks = self.cobol_parser.parse_cobol(source_code, str(filepath))
            all_chunks.extend(chunks)
            
            # Extract program ID
            program_id = self._extract_program_id_from_chunks(chunks)
            self.graph.add_program(program_id, str(filepath))
            
            # Extract calls
            calls = self.cobol_parser.extract_calls(source_code)
            for call in calls:
                if call['type'] == 'static':
                    self.graph.add_call(program_id, call['target'], 'static')
            
            # Extract DB2 operations
            db2_ops = self.cobol_parser.extract_db2_operations(source_code)
            for op in db2_ops:
                if op['table']:
                    self.graph.add_db2_table(program_id, op['table'], op['type'])
            
            # Extract CICS commands
            cics_cmds = self.cobol_parser.extract_cics_commands(source_code)
            for cmd in cics_cmds:
                self.graph.add_cics_command(program_id, cmd['command'])
            
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
        
        # Add chunks to index
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
        # Save code index
        self.code_index.save_index(
            str(self.output_dir / 'code_index.faiss'),
            str(self.output_dir / 'code_chunks.json')
        )
        
        # Save doc index
        self.doc_index.save_index(
            str(self.output_dir / 'doc_index.faiss'),
            str(self.output_dir / 'doc_chunks.json')
        )
        
        # Save graph
        self.graph.save_graph(str(self.output_dir / 'program_graph.gpickle'))
        
        logger.info(f"All indexes saved to {self.output_dir}")
    
    def load_all(self):
        """Load all indexes from disk"""
        self.code_index.load_index(
            str(self.output_dir / 'code_index.faiss'),
            str(self.output_dir / 'code_chunks.json')
        )
        
        self.doc_index.load_index(
            str(self.output_dir / 'doc_index.faiss'),
            str(self.output_dir / 'doc_chunks.json')
        )
        
        self.graph.load_graph(str(self.output_dir / 'program_graph.gpickle'))
        
        logger.info(f"All indexes loaded from {self.output_dir}")


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


# ============================================================================
# HELPER: Build Tree-Sitter COBOL
# ============================================================================
"""
To build Tree-Sitter COBOL grammar:

1. Install dependencies:
   pip install tree-sitter

2. Clone COBOL grammar:
   git clone https://github.com/tree-sitter/tree-sitter-cobol

3. Create build_cobol.py:

from tree_sitter import Language
Language.build_library(
    'build/cobol.so',
    ['tree-sitter-cobol']
)

4. Run:
   python build_cobol.py

This will generate build/cobol.so that the parser uses.
"""