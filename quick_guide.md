# Batch Parser - Quick Start Guide

## What You Need

You need **TWO files**:
1. ✅ `cobol_rag_agent.py` - Main library (scroll up to find it)
2. ✅ `batch_parser.py` - This batch parser (just generated above)

Put both files in the same folder.

---

## Installation

```bash
# Install dependencies
pip install tree-sitter sentence-transformers faiss-cpu networkx
```

---

## Usage

### 1. Basic Usage - Index a Folder

```bash
python batch_parser.py --source /path/to/cobol/files --output ./index
```

**What this does:**
- Scans `/path/to/cobol/files` for COBOL/JCL files
- Parses each file
- Extracts metadata (DB2, CICS, MQ, program calls)
- Builds indexes
- Saves everything to `./index/` folder

**Output files:**
```
./index/
├── code_index.faiss         # Vector search index
├── code_chunks.json         # All code chunks
├── program_graph.gpickle    # Program call graph
├── index_stats.json         # Statistics
└── .file_tracker.json       # File tracking (for incremental)
```

### 2. Incremental Mode - Only Changed Files

```bash
python batch_parser.py --source /path/to/cobol/files --output ./index --incremental
```

Only processes files that changed since last run. Much faster!

### 3. Watch Mode - Auto-Reindex

```bash
python batch_parser.py --watch /path/to/cobol/files --output ./index --interval 60
```

Automatically checks for changes every 60 seconds and reindexes.

---

## Complete Example

```bash
# Step 1: You have COBOL files in a folder
ls /mainframe/cobol/
# CUSTUPDT.cbl  VALIDATE.cbl  AUDITLOG.cbl  BILLING.jcl

# Step 2: Run the batch parser
python batch_parser.py --source /mainframe/cobol --output ./my_index

# Step 3: Wait for it to complete (you'll see progress)
# ============================================================
# BATCH PARSING COMPLETED
# ============================================================
# Total Files Found:      150
# Files Processed:        150
# Programs Found:         145
# DB2 Tables:             23
# ...

# Step 4: Index files are now created
ls ./my_index/
# code_index.faiss  code_chunks.json  program_graph.gpickle

# Step 5: Now use the MCP server with these indexes
python cobol_rag_agent.py serve --index-dir ./my_index
```

---

## What Gets Indexed?

The parser finds and indexes:

| File Type | Extensions | What's Extracted |
|-----------|-----------|------------------|
| COBOL Programs | .cbl, .cob, .CBL, .COB | Programs, paragraphs, sections, CALL statements, DB2 SQL, CICS commands, MQ operations |
| Copybooks | .cpy, .CPY, .copy | Data structures, common definitions |
| JCL | .jcl, .JCL | Job steps, EXEC statements, program references |
| Procedures | .proc, .prc, .PROC, .PRC | Procedure logic, program calls |

---

## Real Example Output

When you run it, you'll see:

```
======================================================================
COBOL BATCH PARSER - STARTING
======================================================================
Source Directory: /mainframe/cobol
Output Directory: ./index
Mode: FULL

Scanning for files...

Found 1543 COBOL programs
Found 234 Copybooks
Found 89 JCL files
Found 12 Procedures
Total: 1878 files

----------------------------------------------------------------------
PROCESSING COBOL PROGRAMS
----------------------------------------------------------------------
[1/1543] Processing: CUSTUPDT.cbl
  Program ID: CUSTUPDT
  Found 3 CALL statements
  Found 5 DB2 operations
  Found 2 CICS commands
  Added 12 chunks to index
[2/1543] Processing: VALIDATE.cbl
...

----------------------------------------------------------------------
SAVING INDEXES
----------------------------------------------------------------------
Saving code index...
Saving program graph...
Saving statistics...
✓ All indexes saved to: ./index

======================================================================
BATCH PARSING COMPLETED
======================================================================
Total Files Found:      1878
Files Processed:        1878
Files Skipped:          0
Files Failed:           0

Total Code Chunks:      15234
Programs Found:         1543
DB2 Tables:             245
MQ Operations:          89
CICS Commands:          456

Processing Time:        930.45 seconds
Files/Second:           2.02

Output Directory:       ./index

Index Files Created:
  • code_index.faiss                45.32 MB
  • code_chunks.json                89.12 MB
  • program_graph.gpickle           12.45 MB
  • index_stats.json                 0.23 MB
======================================================================

Next step: Start the MCP server with:
  python cobol_rag_agent.py serve --index-dir ./index
```

---

## Command Line Options

```bash
# Show help
python batch_parser.py --help

# Full parse
python batch_parser.py --source /cobol --output ./index

# Incremental (only changed files)
python batch_parser.py --source /cobol --output ./index --incremental

# Watch mode (auto-reindex)
python batch_parser.py --watch /cobol --output ./index --interval 300

# Different output location
python batch_parser.py --source /cobol --output /shared/indexes
```

---

## Typical Workflows

### Workflow 1: First-Time Setup
```bash
# Index everything
python batch_parser.py --source /mainframe/cobol --output ./prod_index

# Start MCP server
python cobol_rag_agent.py serve --index-dir ./prod_index
```

### Workflow 2: Daily Updates
```bash
# Add to crontab - runs every night at 2 AM
0 2 * * * cd /app && python batch_parser.py --source /mainframe/cobol --output ./prod_index --incremental
```

### Workflow 3: Development
```bash
# Terminal 1: Watch mode
python batch_parser.py --watch /dev/cobol --output ./dev_index --interval 30

# Terminal 2: MCP server
python cobol_rag_agent.py serve --index-dir ./dev_index

# Files auto-reindex when you save them!
```

---

## Troubleshooting

### Error: "Cannot import from cobol_rag_agent.py"
**Solution:** Make sure both files are in the same directory:
```bash
ls
# batch_parser.py
# cobol_rag_agent.py
```

### Error: "Source directory not found"
**Solution:** Check the path:
```bash
ls -la /mainframe/cobol
# or
ls -la ./cobol
```

### Error: "No files found"
**Solution:** Check file extensions. The parser looks for:
- .cbl, .cob (COBOL)
- .cpy (Copybooks)
- .jcl (JCL)
- .proc (Procedures)

### Parsing is slow
**Solution:** 
- Use `--incremental` mode for updates
- First run is always slower (building embeddings)
- ~2 files/second is normal

### Out of memory
**Solution:**
- Process files in batches (split directory)
- Use a machine with more RAM
- Reduce batch size in code

---

## Log Files

The parser creates a log file: `batch_parser.log`

```bash
# View logs
tail -f batch_parser.log

# Check for errors
grep ERROR batch_parser.log

# See what was processed
grep "Processing:" batch_parser.log
```

---

## Checking Results

After indexing, check the statistics:

```bash
# View stats
cat ./index/index_stats.json

# Pretty print with jq
cat ./index/index_stats.json | jq

# Example output:
{
  "total_files": 1878,
  "processed_files": 1878,
  "total_chunks": 15234,
  "programs_found": 1543,
  "db2_tables": ["CUSTOMER", "ACCOUNT", "TRANSACTION", ...],
  "mq_operations": ["MQPUT", "MQGET", ...],
  "cics_commands": ["READ", "WRITE", "SEND", ...]
}
```

---

## Next Steps

After running the batch parser:

1. **Verify the indexes were created:**
   ```bash
   ls -lh ./index/
   ```

2. **Start the MCP server:**
   ```bash
   python cobol_rag_agent.py serve --index-dir ./index
   ```

3. **Query your code:**
   ```bash
   echo '{"jsonrpc":"2.0","id":1,"method":"search_code","params":{"query":"DB2 SELECT","top_k":5}}' | python cobol_rag_agent.py serve --index-dir ./index
   ```

---

## Summary

**Three simple steps:**

```bash
# 1. Place COBOL files in a folder
/mainframe/cobol/
  ├── CUSTUPDT.cbl
  ├── VALIDATE.cbl
  └── ...

# 2. Run batch parser
python batch_parser.py --source /mainframe/cobol --output ./index

# 3. Use the indexes
python cobol_rag_agent.py serve --index-dir ./index
```

That's it! 🎉

