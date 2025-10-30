"""
batch_parser.py - Standalone COBOL Batch Parser with Document Support
======================================================================
Parses COBOL/JCL files AND documentation (PDF, Word, Markdown, HTML, Text)
to build comprehensive search indexes.

USAGE:
    python batch_parser.py --source /path/to/cobol --output ./index
    python batch_parser.py --source /path/to/cobol --output ./index --docs /path/to/docs
    python batch_parser.py --source /path/to/cobol --output ./index --incremental
    python batch_parser.py --watch /path/to/cobol --output ./index

REQUIREMENTS:
    pip install tree-sitter sentence-transformers faiss-cpu networkx PyPDF2 python-docx markdown beautifulsoup4
"""

import os
import sys
import time
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Set, Optional
import hashlib

# Import core components from cobol_rag_agent.py
try:
    from cobol_rag_agent import (
        COBOLParser, 
        JCLParser, 
        DocumentParser,
        VectorIndexBuilder, 
        ProgramGraphBuilder, 
        CodeChunk
    )
except ImportError:
    print("=" * 70)
    print("ERROR: Cannot import from cobol_rag_agent.py")
    print("=" * 70)
    print("Make sure cobol_rag_agent.py is in the same directory as this script.")
    print("")
    print("You need both files:")
    print("  1. cobol_rag_agent.py  (main library)")
    print("  2. batch_parser.py     (this file)")
    print("=" * 70)
    sys.exit(1)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('batch_parser.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class FileTracker:
    """
    Track processed files for incremental indexing.
    Stores file hashes to detect changes.
    """
    
    def __init__(self, tracker_file: str = '.file_tracker.json'):
        self.tracker_file = tracker_file
        self.processed_files: Dict[str, Dict] = {}
        self.load()
    
    def load(self):
        """Load tracking data from file"""
        if os.path.exists(self.tracker_file):
            try:
                with open(self.tracker_file, 'r') as f:
                    self.processed_files = json.load(f)
                logger.info(f"Loaded tracking data for {len(self.processed_files)} files")
            except Exception as e:
                logger.warning(f"Could not load tracker file: {e}")
                self.processed_files = {}
    
    def save(self):
        """Save tracking data to file"""
        try:
            with open(self.tracker_file, 'w') as f:
                json.dump(self.processed_files, f, indent=2)
            logger.debug(f"Saved tracking data for {len(self.processed_files)} files")
        except Exception as e:
            logger.error(f"Could not save tracker file: {e}")
    
    def get_file_hash(self, filepath: str) -> str:
        """Calculate MD5 hash of file"""
        try:
            with open(filepath, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception as e:
            logger.error(f"Could not hash file {filepath}: {e}")
            return ""
    
    def is_file_changed(self, filepath: str) -> bool:
        """Check if file has changed since last processing"""
        current_hash = self.get_file_hash(filepath)
        
        if filepath not in self.processed_files:
            return True  # New file
        
        stored_hash = self.processed_files[filepath].get('hash', '')
        return current_hash != stored_hash  # Changed if hash differs
    
    def mark_processed(self, filepath: str, stats: Dict = None):
        """Mark file as successfully processed"""
        self.processed_files[filepath] = {
            'hash': self.get_file_hash(filepath),
            'timestamp': datetime.now().isoformat(),
            'stats': stats or {}
        }

# ============================================================================
# ENHANCED JCL PARSER WITH FILE TRACKING
# ============================================================================

class EnhancedJCLParser:
    """Enhanced JCL parser that tracks file I/O"""
    
    def __init__(self):
        self.base_parser = JCLParser()
    
    def parse_jcl_with_files(self, source_code: str, filename: str) -> Dict[str, Any]:
        """
        Parse JCL and extract file I/O information.
        Returns: {
            'chunks': [CodeChunk],
            'programs': [str],
            'files': {'input': [], 'output': []},
            'datasets': []
        }
        """
        result = {
            'chunks': self.base_parser.parse_jcl(source_code, filename),
            'programs': self.base_parser.extract_programs(source_code),
            'files': {'input': [], 'output': []},
            'datasets': []
        }
        
        # Extract DD statements for file I/O
        dd_pattern = re.compile(
            r'//(\w+)\s+DD\s+(?:DSN=)?([^,\s]+)',
            re.IGNORECASE
        )
        
        for match in dd_pattern.finditer(source_code):
            ddname = match.group(1)
            dataset = match.group(2)
            
            # Determine if input or output based on DD name or DISP
            is_input = self._is_input_file(source_code, ddname, dataset)
            
            file_info = {
                'ddname': ddname,
                'dataset': dataset,
                'type': 'sequential'  # Could be enhanced to detect VSAM, etc.
            }
            
            if is_input:
                result['files']['input'].append(file_info)
            else:
                result['files']['output'].append(file_info)
            
            result['datasets'].append(dataset)
        
        return result
    
    def _is_input_file(self, source_code: str, ddname: str, dataset: str) -> bool:
        """
        Determine if a file is input or output.
        Checks DISP parameter and common naming conventions.
        """
        # Look for DISP parameter on this DD statement
        dd_line_pattern = re.compile(
            rf'//{ddname}\s+DD\s+.*?(?=//|\Z)',
            re.IGNORECASE | re.DOTALL
        )
        
        match = dd_line_pattern.search(source_code)
        if match:
            dd_statement = match.group(0)
            
            # Check DISP parameter
            if 'DISP=SHR' in dd_statement or 'DISP=(OLD' in dd_statement:
                return True
            elif 'DISP=(NEW' in dd_statement or 'DISP=(MOD' in dd_statement:
                return False
        
        # Fallback: check common naming conventions
        input_patterns = ['INPUT', 'INFILE', 'SYSIN', 'CARDIN']
        output_patterns = ['OUTPUT', 'OUTFILE', 'SYSOUT', 'CARDOUT', 'SYSPRINT']
        
        ddname_upper = ddname.upper()
        
        if any(pattern in ddname_upper for pattern in input_patterns):
            return True
        elif any(pattern in ddname_upper for pattern in output_patterns):
            return False
        
        # Default to input if unknown
        return True
# ============================================================================

class BatchParser:
    """
    Main batch parser for COBOL/JCL files and documentation.
    Scans directories, parses files, builds indexes.
    """
    
    def __init__(self, output_dir: str, incremental: bool = False):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.incremental = incremental
        self.file_tracker = FileTracker(str(self.output_dir / '.file_tracker.json'))
        
        # Initialize parsers
        logger.info("Initializing parsers...")
        self.cobol_parser = COBOLParser()
        self.jcl_parser = JCLParser()
        self.doc_parser = DocumentParser()
        
        # Initialize indexes
        logger.info("Initializing vector indexes...")
        self.code_index = VectorIndexBuilder()
        self.doc_index = VectorIndexBuilder()
        self.graph = ProgramGraphBuilder()
        
        # Statistics
        self.stats = {
            'total_files': 0,
            'processed_files': 0,
            'skipped_files': 0,
            'failed_files': 0,
            'total_chunks': 0,
            'programs_found': 0,
            'documents_processed': 0,
            'db2_tables': set(),
            'mq_operations': set(),
            'cics_commands': set(),
            'call_relationships': 0
        }
        
        # Load existing indexes if incremental mode
        if self.incremental:
            self._load_existing_indexes()
    
    def _load_existing_indexes(self):
        """Load existing indexes for incremental update"""
        try:
            code_index_path = self.output_dir / 'code_index.faiss'
            code_chunks_path = self.output_dir / 'code_chunks.json'
            
            if code_index_path.exists() and code_chunks_path.exists():
                self.code_index.load_index(str(code_index_path), str(code_chunks_path))
                logger.info(f"✓ Loaded existing code index with {len(self.code_index.chunks)} chunks")
            
            doc_index_path = self.output_dir / 'doc_index.faiss'
            doc_chunks_path = self.output_dir / 'doc_chunks.json'
            
            if doc_index_path.exists() and doc_chunks_path.exists():
                self.doc_index.load_index(str(doc_index_path), str(doc_chunks_path))
                logger.info(f"✓ Loaded existing doc index with {len(self.doc_index.chunks)} chunks")
            
            graph_path = self.output_dir / 'program_graph.gpickle'
            if graph_path.exists():
                self.graph.load_graph(str(graph_path))
                logger.info(f"✓ Loaded existing program graph")
        except Exception as e:
            logger.warning(f"Could not load existing indexes: {e}")
            logger.info("Starting with fresh indexes")
    
    def find_files(self, source_dir: str) -> Dict[str, List[Path]]:
        """
        Recursively find all COBOL/JCL files in directory.
        Returns dict with file types as keys.
        """
        source_path = Path(source_dir)
        
        if not source_path.exists():
            logger.error(f"Source directory does not exist: {source_dir}")
            return {'cobol': [], 'copybook': [], 'jcl': [], 'proc': []}
        
        logger.info(f"Scanning directory: {source_dir}")
        
        found_files = {
            'cobol': [],
            'copybook': [],
            'jcl': [],
            'proc': []
        }
        
        # COBOL programs
        for ext in ['*.cbl', '*.cob', '*.CBL', '*.COB']:
            found_files['cobol'].extend(source_path.rglob(ext))
        
        # Copybooks
        for ext in ['*.cpy', '*.CPY', '*.copy', '*.COPY']:
            found_files['copybook'].extend(source_path.rglob(ext))
        
        # JCL
        for ext in ['*.jcl', '*.JCL']:
            found_files['jcl'].extend(source_path.rglob(ext))
        
        # Procedures
        for ext in ['*.proc', '*.PROC', '*.prc', '*.PRC']:
            found_files['proc'].extend(source_path.rglob(ext))
        
        # Remove duplicates
        for file_type in found_files:
            found_files[file_type] = list(set(found_files[file_type]))
        
        return found_files
    
    def find_documents(self, docs_dir: str) -> Dict[str, List[Path]]:
        """
        Find all documentation files.
        Returns dict with document types as keys.
        """
        docs_path = Path(docs_dir)
        
        if not docs_path.exists():
            logger.warning(f"Documentation directory does not exist: {docs_dir}")
            return {'pdf': [], 'word': [], 'markdown': [], 'text': [], 'html': []}
        
        logger.info(f"Scanning documentation directory: {docs_dir}")
        
        found_docs = {
            'pdf': list(docs_path.rglob('*.pdf')) + list(docs_path.rglob('*.PDF')),
            'word': list(docs_path.rglob('*.doc')) + list(docs_path.rglob('*.docx')) + 
                    list(docs_path.rglob('*.DOC')) + list(docs_path.rglob('*.DOCX')),
            'markdown': list(docs_path.rglob('*.md')) + list(docs_path.rglob('*.MD')),
            'text': list(docs_path.rglob('*.txt')) + list(docs_path.rglob('*.TXT')),
            'html': list(docs_path.rglob('*.html')) + list(docs_path.rglob('*.htm')) +
                    list(docs_path.rglob('*.HTML')) + list(docs_path.rglob('*.HTM'))
        }
        
        # Remove duplicates
        for doc_type in found_docs:
            found_docs[doc_type] = list(set(found_docs[doc_type]))
        
        return found_docs
    
    def process_cobol_file(self, filepath: Path) -> bool:
        """
        Process a single COBOL file with enhanced dynamic call detection
        """
        try:
            logger.info(f"Processing: {filepath.name}")
            
            with open(filepath, 'r', encoding='latin-1', errors='ignore') as f:
                source_code = f.read()
            
            # Parse into chunks
            chunks = self.cobol_parser.parse_cobol(source_code, str(filepath))
            
            if not chunks:
                logger.warning(f"No chunks extracted from {filepath.name}")
                return False
            
            # Extract program ID
            program_id = self._extract_program_id(chunks, source_code)
            logger.debug(f"  Program ID: {program_id}")
            
            # Add program to graph
            self.graph.add_program(program_id, str(filepath))
            self.stats['programs_found'] += 1
            
            # Extract CALL statements (basic)
            calls = self.cobol_parser.extract_calls(source_code)
            logger.debug(f"  Found {len(calls)} basic CALL statements")
            
            # Extract dynamic calls (advanced)
            try:
                dynamic_calls = self.cobol_parser.extract_dynamic_calls_advanced(source_code)
                logger.debug(f"  Found {len(dynamic_calls)} dynamic call patterns")
                
                # Add dynamic calls to graph
                for var_name, possible_targets in dynamic_calls.items():
                    for target in possible_targets:
                        self.graph.add_call(program_id, target, 'dynamic')
                        self.stats['call_relationships'] += 1
                        logger.debug(f"    Dynamic call: {var_name} -> {target}")
            except Exception as e:
                logger.warning(f"  Could not resolve dynamic calls: {e}")
            
            # Add static calls
            for call in calls:
                if call['type'] == 'static':
                    self.graph.add_call(program_id, call['target'], 'static')
                    self.stats['call_relationships'] += 1
            
            # Extract DB2 operations
            db2_ops = self.cobol_parser.extract_db2_operations(source_code)
            logger.debug(f"  Found {len(db2_ops)} DB2 operations")
            for op in db2_ops:
                if op['table']:
                    self.graph.add_db2_table(program_id, op['table'], op['type'])
                    self.stats['db2_tables'].add(op['table'])
            
            # Extract CICS commands (only I/O related)
            cics_cmds = self.cobol_parser.extract_cics_commands(source_code)
            io_cics = [cmd for cmd in cics_cmds if cmd['command'].upper() in 
                       ['READ', 'WRITE', 'READNEXT', 'REWRITE', 'DELETE', 'STARTBR', 'ENDBR']]
            logger.debug(f"  Found {len(io_cics)} CICS I/O commands")
            for cmd in io_cics:
                self.graph.add_cics_command(program_id, cmd['command'])
                self.stats['cics_commands'].add(cmd['command'])
            
            # Extract MQ operations
            mq_ops = self.cobol_parser.extract_mq_operations(source_code)
            logger.debug(f"  Found {len(mq_ops)} MQ operations")
            for op in mq_ops:
                self.graph.add_mq_queue(program_id, op['operation'])
                self.stats['mq_operations'].add(op['operation'])
            
            # Add chunks to vector index
            self.code_index.add_chunks(chunks)
            self.stats['total_chunks'] += len(chunks)
            logger.debug(f"  Added {len(chunks)} chunks to index")
            
            # Mark as processed
            self.file_tracker.mark_processed(
                str(filepath),
                {
                    'program_id': program_id, 
                    'chunks': len(chunks),
                    'db2_ops': len(db2_ops),
                    'cics_cmds': len(io_cics),
                    'calls': len(calls),
                    'dynamic_calls': len(dynamic_calls) if 'dynamic_calls' in locals() else 0
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to process {filepath.name}: {e}", exc_info=True)
            return False
    
    def process_jcl_file(self, filepath: Path) -> bool:
        """Process a single JCL file with file I/O tracking"""
        try:
            logger.info(f"Processing JCL: {filepath.name}")
            
            with open(filepath, 'r', encoding='latin-1', errors='ignore') as f:
                source_code = f.read()
            
            # Use enhanced parser
            enhanced_parser = EnhancedJCLParser()
            jcl_data = enhanced_parser.parse_jcl_with_files(source_code, str(filepath))
            
            # Add chunks to index
            if jcl_data['chunks']:
                self.code_index.add_chunks(jcl_data['chunks'])
                self.stats['total_chunks'] += len(jcl_data['chunks'])
                logger.debug(f"  Added {len(jcl_data['chunks'])} JCL chunks")
            
            # Log file I/O
            logger.debug(f"  Found {len(jcl_data['programs'])} programs")
            logger.debug(f"  Input files: {len(jcl_data['files']['input'])}")
            logger.debug(f"  Output files: {len(jcl_data['files']['output'])}")
            
            # Add file nodes to graph if programs are found
            for program in jcl_data['programs']:
                prog_node = f"prog:{program}"
                
                # Add input files
                for inp_file in jcl_data['files']['input']:
                    file_node = f"file:input:{inp_file['ddname']}"
                    if not self.graph.graph.has_node(file_node):
                        self.graph.graph.add_node(
                            file_node,
                            node_type='input_file',
                            name=inp_file['ddname'],
                            dataset=inp_file['dataset']
                        )
                    # Input file -> Program
                    self.graph.graph.add_edge(file_node, prog_node, edge_type='input')
                
                # Add output files
                for out_file in jcl_data['files']['output']:
                    file_node = f"file:output:{out_file['ddname']}"
                    if not self.graph.graph.has_node(file_node):
                        self.graph.graph.add_node(
                            file_node,
                            node_type='output_file',
                            name=out_file['ddname'],
                            dataset=out_file['dataset']
                        )
                    # Program -> Output file
                    self.graph.graph.add_edge(prog_node, file_node, edge_type='output')
            
            self.file_tracker.mark_processed(
                str(filepath),
                {
                    'type': 'jcl', 
                    'chunks': len(jcl_data['chunks']), 
                    'programs': len(jcl_data['programs']),
                    'input_files': len(jcl_data['files']['input']),
                    'output_files': len(jcl_data['files']['output'])
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to process JCL {filepath.name}: {e}")
            return False
    
    def process_document(self, filepath: Path, doc_type: str) -> bool:
        """Process a documentation file"""
        try:
            logger.info(f"Processing {doc_type.upper()}: {filepath.name}")
            
            chunks = []
            
            if doc_type == 'pdf':
                chunks = self.doc_parser.parse_pdf(str(filepath))
            elif doc_type == 'word':
                chunks = self.doc_parser.parse_word(str(filepath))
            elif doc_type == 'markdown':
                chunks = self.doc_parser.parse_markdown(str(filepath))
            elif doc_type == 'text':
                chunks = self.doc_parser.parse_text(str(filepath))
            elif doc_type == 'html':
                chunks = self.doc_parser.parse_html(str(filepath))
            
            if chunks:
                self.doc_index.add_chunks(chunks)
                self.stats['total_chunks'] += len(chunks)
                self.stats['documents_processed'] += 1
                logger.debug(f"  Added {len(chunks)} documentation chunks")
            
            self.file_tracker.mark_processed(
                str(filepath),
                {'type': f'doc_{doc_type}', 'chunks': len(chunks)}
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to process document {filepath.name}: {e}")
            return False
    
    def _extract_program_id(self, chunks: List[CodeChunk], source_code: str) -> str:
        """Extract program ID from chunks or source code"""
        # Try chunks first
        for chunk in chunks:
            if 'program_id' in chunk.metadata:
                prog_id = chunk.metadata['program_id']
                if prog_id and prog_id != "UNKNOWN":
                    return prog_id
        
        # Fallback: search source code
        import re
        match = re.search(r'PROGRAM-ID\.\s+(\S+)', source_code, re.IGNORECASE)
        if match:
            return match.group(1).strip('.')
        
        return "UNKNOWN"
    
    def process_batch(self, source_dir: str, docs_dir: Optional[str] = None):
        """
        Main entry point: Process all files in batch
        """
        logger.info("=" * 70)
        logger.info("COBOL BATCH PARSER WITH DOCUMENT SUPPORT - STARTING")
        logger.info("=" * 70)
        logger.info(f"Source Directory: {source_dir}")
        if docs_dir:
            logger.info(f"Documentation Directory: {docs_dir}")
        logger.info(f"Output Directory: {self.output_dir}")
        logger.info(f"Mode: {'INCREMENTAL' if self.incremental else 'FULL'}")
        logger.info("")
        
        start_time = time.time()
        
        # Find all files
        logger.info("Scanning for source files...")
        files = self.find_files(source_dir)
        
        # Find documentation files
        docs = {'pdf': [], 'word': [], 'markdown': [], 'text': [], 'html': []}
        if docs_dir:
            logger.info("Scanning for documentation files...")
            docs = self.find_documents(docs_dir)
        
        self.stats['total_files'] = sum(len(f) for f in files.values()) + sum(len(d) for d in docs.values())
        
        logger.info("")
        logger.info("FOUND FILES:")
        logger.info(f"  COBOL Programs:    {len(files['cobol'])}")
        logger.info(f"  Copybooks:         {len(files['copybook'])}")
        logger.info(f"  JCL Files:         {len(files['jcl'])}")
        logger.info(f"  Procedures:        {len(files['proc'])}")
        logger.info(f"  PDF Documents:     {len(docs['pdf'])}")
        logger.info(f"  Word Documents:    {len(docs['word'])}")
        logger.info(f"  Markdown Files:    {len(docs['markdown'])}")
        logger.info(f"  Text Files:        {len(docs['text'])}")
        logger.info(f"  HTML Files:        {len(docs['html'])}")
        logger.info(f"  TOTAL:             {self.stats['total_files']}")
        logger.info("")
        
        if self.stats['total_files'] == 0:
            logger.warning("No files found! Check your source directory.")
            return
        
        # Process COBOL files
        logger.info("-" * 70)
        logger.info("PROCESSING COBOL PROGRAMS")
        logger.info("-" * 70)
        for i, filepath in enumerate(files['cobol'], 1):
            if self.incremental and not self.file_tracker.is_file_changed(str(filepath)):
                logger.debug(f"[{i}/{len(files['cobol'])}] Skipping unchanged: {filepath.name}")
                self.stats['skipped_files'] += 1
                continue
            
            logger.info(f"[{i}/{len(files['cobol'])}] Processing: {filepath.name}")
            
            if self.process_cobol_file(filepath):
                self.stats['processed_files'] += 1
            else:
                self.stats['failed_files'] += 1
            
            # Save periodically (every 50 files)
            if self.stats['processed_files'] % 50 == 0:
                logger.info(f"  → Saving intermediate state...")
                self._save_intermediate()
        
        # Process Copybooks
        logger.info("")
        logger.info("-" * 70)
        logger.info("PROCESSING COPYBOOKS")
        logger.info("-" * 70)
        for i, filepath in enumerate(files['copybook'], 1):
            if self.incremental and not self.file_tracker.is_file_changed(str(filepath)):
                logger.debug(f"[{i}/{len(files['copybook'])}] Skipping unchanged: {filepath.name}")
                self.stats['skipped_files'] += 1
                continue
            
            logger.info(f"[{i}/{len(files['copybook'])}] Processing: {filepath.name}")
            
            if self.process_cobol_file(filepath):
                self.stats['processed_files'] += 1
            else:
                self.stats['failed_files'] += 1
        
        # Process JCL files
        logger.info("")
        logger.info("-" * 70)
        logger.info("PROCESSING JCL FILES")
        logger.info("-" * 70)
        for i, filepath in enumerate(files['jcl'] + files['proc'], 1):
            if self.incremental and not self.file_tracker.is_file_changed(str(filepath)):
                logger.debug(f"[{i}] Skipping unchanged: {filepath.name}")
                self.stats['skipped_files'] += 1
                continue
            
            logger.info(f"[{i}] Processing: {filepath.name}")
            
            if self.process_jcl_file(filepath):
                self.stats['processed_files'] += 1
            else:
                self.stats['failed_files'] += 1
        
        # Process Documentation files
        if docs_dir:
            logger.info("")
            logger.info("-" * 70)
            logger.info("PROCESSING DOCUMENTATION FILES")
            logger.info("-" * 70)
            
            # Process PDFs
            for i, filepath in enumerate(docs['pdf'], 1):
                if self.incremental and not self.file_tracker.is_file_changed(str(filepath)):
                    self.stats['skipped_files'] += 1
                    continue
                
                logger.info(f"[PDF {i}/{len(docs['pdf'])}] Processing: {filepath.name}")
                
                if self.process_document(filepath, 'pdf'):
                    self.stats['processed_files'] += 1
                else:
                    self.stats['failed_files'] += 1
            
            # Process Word documents
            for i, filepath in enumerate(docs['word'], 1):
                if self.incremental and not self.file_tracker.is_file_changed(str(filepath)):
                    self.stats['skipped_files'] += 1
                    continue
                
                logger.info(f"[Word {i}/{len(docs['word'])}] Processing: {filepath.name}")
                
                if self.process_document(filepath, 'word'):
                    self.stats['processed_files'] += 1
                else:
                    self.stats['failed_files'] += 1
            
            # Process Markdown files
            for i, filepath in enumerate(docs['markdown'], 1):
                if self.incremental and not self.file_tracker.is_file_changed(str(filepath)):
                    self.stats['skipped_files'] += 1
                    continue
                
                logger.info(f"[Markdown {i}/{len(docs['markdown'])}] Processing: {filepath.name}")
                
                if self.process_document(filepath, 'markdown'):
                    self.stats['processed_files'] += 1
                else:
                    self.stats['failed_files'] += 1
            
            # Process Text files
            for i, filepath in enumerate(docs['text'], 1):
                if self.incremental and not self.file_tracker.is_file_changed(str(filepath)):
                    self.stats['skipped_files'] += 1
                    continue
                
                logger.info(f"[Text {i}/{len(docs['text'])}] Processing: {filepath.name}")
                
                if self.process_document(filepath, 'text'):
                    self.stats['processed_files'] += 1
                else:
                    self.stats['failed_files'] += 1
            
            # Process HTML files
            for i, filepath in enumerate(docs['html'], 1):
                if self.incremental and not self.file_tracker.is_file_changed(str(filepath)):
                    self.stats['skipped_files'] += 1
                    continue
                
                logger.info(f"[HTML {i}/{len(docs['html'])}] Processing: {filepath.name}")
                
                if self.process_document(filepath, 'html'):
                    self.stats['processed_files'] += 1
                else:
                    self.stats['failed_files'] += 1
        
        # Final save
        logger.info("")
        logger.info("-" * 70)
        logger.info("SAVING INDEXES")
        logger.info("-" * 70)
        self._save_all()
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Print summary
        self._print_summary(duration)
    
    def _save_intermediate(self):
        """Save intermediate state (file tracker only)"""
        self.file_tracker.save()
    
    def _save_all(self):
        """Save all indexes and metadata"""
        logger.info("Saving code index...")
        self.code_index.save_index(
            str(self.output_dir / 'code_index.faiss'),
            str(self.output_dir / 'code_chunks.json')
        )
        
        logger.info("Saving documentation index...")
        self.doc_index.save_index(
            str(self.output_dir / 'doc_index.faiss'),
            str(self.output_dir / 'doc_chunks.json')
        )
        
        logger.info("Saving program graph...")
        self.graph.save_graph(str(self.output_dir / 'program_graph.gpickle'))
        
        logger.info("Saving file tracker...")
        self.file_tracker.save()
        
        logger.info("Saving statistics...")
        stats_file = self.output_dir / 'index_stats.json'
        stats_to_save = self.stats.copy()
        stats_to_save['db2_tables'] = sorted(list(stats_to_save['db2_tables']))
        stats_to_save['mq_operations'] = sorted(list(stats_to_save['mq_operations']))
        stats_to_save['cics_commands'] = sorted(list(stats_to_save['cics_commands']))
        stats_to_save['timestamp'] = datetime.now().isoformat()
        
        with open(stats_file, 'w') as f:
            json.dump(stats_to_save, f, indent=2)
        
        logger.info(f"✓ All indexes saved to: {self.output_dir}")
    
    def _print_summary(self, duration: float):
        """Print final summary"""
        logger.info("")
        logger.info("=" * 70)
        logger.info("BATCH PARSING COMPLETED")
        logger.info("=" * 70)
        logger.info(f"Total Files Found:        {self.stats['total_files']}")
        logger.info(f"Files Processed:          {self.stats['processed_files']}")
        logger.info(f"Files Skipped:            {self.stats['skipped_files']}")
        logger.info(f"Files Failed:             {self.stats['failed_files']}")
        logger.info("")
        logger.info(f"Total Code Chunks:        {self.stats['total_chunks']}")
        logger.info(f"Programs Found:           {self.stats['programs_found']}")
        logger.info(f"Documents Processed:      {self.stats['documents_processed']}")
        logger.info(f"Call Relationships:       {self.stats['call_relationships']}")
        logger.info(f"DB2 Tables:               {len(self.stats['db2_tables'])}")
        logger.info(f"MQ Operations:            {len(self.stats['mq_operations'])}")
        logger.info(f"CICS Commands:            {len(self.stats['cics_commands'])}")
        logger.info("")
        logger.info(f"Processing Time:          {duration:.2f} seconds")
        if self.stats['processed_files'] > 0:
            logger.info(f"Files/Second:             {self.stats['processed_files']/duration:.2f}")
        logger.info("")
        logger.info(f"Output Directory:         {self.output_dir}")
        logger.info("")
        logger.info("Index Files Created:")
        for fname in ['code_index.faiss', 'code_chunks.json', 'doc_index.faiss', 'doc_chunks.json', 'program_graph.gpickle', 'index_stats.json']:
            fpath = self.output_dir / fname
            if fpath.exists():
                size_mb = fpath.stat().st_size / (1024 * 1024)
                logger.info(f"  • {fname:30s} {size_mb:>8.2f} MB")
        logger.info("=" * 70)


class FileWatcher:
    """
    Watch directory for new/changed files and auto-reindex.
    Useful for development environments.
    """
    
    def __init__(self, source_dir: str, output_dir: str, docs_dir: Optional[str] = None):
        self.source_dir = source_dir
        self.docs_dir = docs_dir
        self.parser = BatchParser(output_dir, incremental=True)
        self.last_check = datetime.now()
    
    def watch(self, interval: int = 60):
        """
        Watch for changes at specified interval (seconds).
        Press Ctrl+C to stop.
        """
        logger.info("=" * 70)
        logger.info("FILE WATCHER MODE")
        logger.info("=" * 70)
        logger.info(f"Watching: {self.source_dir}")
        if self.docs_dir:
            logger.info(f"Watching Docs: {self.docs_dir}")
        logger.info(f"Interval: {interval} seconds")
        logger.info("Press Ctrl+C to stop")
        logger.info("")
        
        try:
            while True:
                check_time = datetime.now()
                logger.info(f"[{check_time.strftime('%Y-%m-%d %H:%M:%S')}] Checking for changes...")
                
                # Find all files
                files = self.parser.find_files(self.source_dir)
                changed_files = []
                
                # Check source files
                for file_type, file_list in files.items():
                    for filepath in file_list:
                        if self.parser.file_tracker.is_file_changed(str(filepath)):
                            changed_files.append((file_type, filepath))
                
                # Check documentation files
                if self.docs_dir:
                    docs = self.parser.find_documents(self.docs_dir)
                    for doc_type, doc_list in docs.items():
                        for filepath in doc_list:
                            if self.parser.file_tracker.is_file_changed(str(filepath)):
                                changed_files.append((f'doc_{doc_type}', filepath))
                
                if changed_files:
                    logger.info(f"  → Found {len(changed_files)} changed files")
                    
                    # Process changed files
                    for file_type, filepath in changed_files:
                        if file_type in ['cobol', 'copybook']:
                            logger.info(f"  → Reprocessing: {filepath.name}")
                            self.parser.process_cobol_file(filepath)
                        elif file_type in ['jcl', 'proc']:
                            logger.info(f"  → Reprocessing: {filepath.name}")
                            self.parser.process_jcl_file(filepath)
                        elif file_type.startswith('doc_'):
                            doc_type = file_type.replace('doc_', '')
                            logger.info(f"  → Reprocessing: {filepath.name}")
                            self.parser.process_document(filepath, doc_type)
                    
                    # Save updates
                    logger.info("  → Saving updated indexes...")
                    self.parser._save_all()
                    logger.info("  ✓ Indexes updated")
                else:
                    logger.info("  ✓ No changes detected")
                
                logger.info("")
                self.last_check = check_time
                time.sleep(interval)
                
        except KeyboardInterrupt:
            logger.info("")
            logger.info("Stopping file watcher...")
            logger.info("Final save...")
            self.parser._save_all()
            logger.info("✓ File watcher stopped")


def main():
    """Main entry point with argument parsing"""
    
    parser = argparse.ArgumentParser(
        description='Batch Parser for COBOL/JCL Files and Documentation - Build Search Indexes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Parse COBOL code only
  python batch_parser.py --source /mainframe/cobol --output ./index
  
  # Parse COBOL code + documentation
  python batch_parser.py --source /mainframe/cobol --docs /mainframe/docs --output ./index
  
  # Incremental parse (only changed files)
  python batch_parser.py --source /mainframe/cobol --output ./index --incremental
  
  # Watch mode (auto-reindex when files change)
  python batch_parser.py --watch /mainframe/cobol --output ./index --interval 300

After indexing, use the MCP server:
  python mcp_server_rag.py
        """
    )
    
    parser.add_argument('--source', 
                       help='Source directory containing COBOL/JCL files')
    parser.add_argument('--docs',
                       help='Documentation directory (PDF, Word, Markdown, HTML, Text)')
    parser.add_argument('--output', 
                       required=True, 
                       help='Output directory for index files')
    parser.add_argument('--incremental', 
                       action='store_true',
                       help='Only process files that changed since last run')
    parser.add_argument('--watch', 
                       help='Watch directory for changes (specify directory path)')
    parser.add_argument('--interval', 
                       type=int, 
                       default=60,
                       help='Watch interval in seconds (default: 60)')
    
    args = parser.parse_args()
    
    # Watch mode
    if args.watch:
        if not os.path.isdir(args.watch):
            print(f"ERROR: Watch directory not found: {args.watch}")
            sys.exit(1)
        
        watcher = FileWatcher(args.watch, args.output, args.docs)
        watcher.watch(args.interval)
        return
    
    # Batch mode
    if not args.source:
        parser.error("--source is required for batch mode (or use --watch)")
    
    if not os.path.isdir(args.source):
        print(f"ERROR: Source directory not found: {args.source}")
        sys.exit(1)
    
    # Create and run batch parser
    batch_parser = BatchParser(args.output, args.incremental)
    batch_parser.process_batch(args.source, args.docs)
    
    logger.info("")
    logger.info("Next step: Start the MCP server with:")
    logger.info(f"  python mcp_server_rag.py")
    logger.info("")
    logger.info("Or configure in VS Code settings.json:")
    logger.info('  "INDEX_DIR": "' + args.output + '"')


if __name__ == '__main__':
    main()