#!/bin/bash
# =================================================================
# run_parser.sh - Simple wrapper to run batch parser
# =================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         COBOL Batch Parser - Index Builder           ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: Python 3 is not installed${NC}"
    exit 1
fi

# Check if batch_parser.py exists
if [ ! -f "$SCRIPT_DIR/batch_parser.py" ]; then
    echo -e "${RED}ERROR: batch_parser.py not found${NC}"
    exit 1
fi

# Default values
SOURCE_DIR=""
OUTPUT_DIR="./index"
MODE="full"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --source)
            SOURCE_DIR="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --incremental)
            MODE="incremental"
            shift
            ;;
        --watch)
            MODE="watch"
            shift
            ;;
        --help)
            echo "Usage: ./run_parser.sh --source <dir> [--output <dir>] [--incremental|--watch]"
            echo ""
            echo "Options:"
            echo "  --source DIR       Source directory with COBOL/JCL files (required)"
            echo "  --output DIR       Output directory for indexes (default: ./index)"
            echo "  --incremental      Only process changed files"
            echo "  --watch           Watch for changes and auto-reindex"
            echo ""
            echo "Examples:"
            echo "  ./run_parser.sh --source /mainframe/cobol"
            echo "  ./run_parser.sh --source /mainframe/cobol --incremental"
            echo "  ./run_parser.sh --source /mainframe/cobol --watch"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Check if source is provided
if [ -z "$SOURCE_DIR" ]; then
    echo -e "${RED}ERROR: --source directory is required${NC}"
    echo "Usage: ./run_parser.sh --source <dir>"
    exit 1
fi

# Check if source directory exists
if [ ! -d "$SOURCE_DIR" ]; then
    echo -e "${RED}ERROR: Source directory not found: $SOURCE_DIR${NC}"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo -e "${YELLOW}Configuration:${NC}"
echo "  Source:  $SOURCE_DIR"
echo "  Output:  $OUTPUT_DIR"
echo "  Mode:    $MODE"
echo ""

# Run the parser
case $MODE in
    full)
        echo -e "${GREEN}Starting full parse...${NC}"
        python3 batch_parser.py --source "$SOURCE_DIR" --output "$OUTPUT_DIR"
        ;;
    incremental)
        echo -e "${GREEN}Starting incremental parse...${NC}"
        python3 batch_parser.py --source "$SOURCE_DIR" --output "$OUTPUT_DIR" --incremental
        ;;
    watch)
        echo -e "${GREEN}Starting watch mode...${NC}"
        python3 batch_parser.py --watch "$SOURCE_DIR" --output "$OUTPUT_DIR"
        ;;
esac

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ Parsing completed successfully!${NC}"
    echo ""
    echo "Index files created in: $OUTPUT_DIR"
    echo ""
    ls -lh "$OUTPUT_DIR"
else
    echo ""
    echo -e "${RED}✗ Parsing failed!${NC}"
    echo "Check batch_parser.log for details"
    exit 1
fi

# =================================================================
# quick_index.sh - Quick index script
# =================================================================

#!/bin/bash
# Simple one-liner to index a directory

if [ $# -eq 0 ]; then
    echo "Usage: ./quick_index.sh <cobol_directory>"
    echo "Example: ./quick_index.sh /mainframe/cobol"
    exit 1
fi

python3 batch_parser.py --source "$1" --output ./index
echo ""
echo "✓ Done! Index saved to ./index"
echo ""
echo "To serve with MCP:"
echo "  python cobol_rag_agent.py serve --index-dir ./index"

# =================================================================
# scheduled_reindex.sh - Cron job for scheduled reindexing
# =================================================================

#!/bin/bash
# Add to crontab for automatic reindexing
# Example: 0 2 * * * /path/to/scheduled_reindex.sh

LOG_FILE="/var/log/cobol_reindex.log"
SOURCE_DIR="/mainframe/cobol"
OUTPUT_DIR="/opt/cobol_index"

echo "========================================" >> "$LOG_FILE"
echo "Reindex started: $(date)" >> "$LOG_FILE"

python3 batch_parser.py \
    --source "$SOURCE_DIR" \
    --output "$OUTPUT_DIR" \
    --incremental >> "$LOG_FILE" 2>&1

if [ $? -eq 0 ]; then
    echo "Reindex completed successfully: $(date)" >> "$LOG_FILE"
else
    echo "Reindex failed: $(date)" >> "$LOG_FILE"
    # Send alert (optional)
    # mail -s "COBOL Reindex Failed" admin@example.com < "$LOG_FILE"
fi

# =================================================================
# Windows Batch File (run_parser.bat)
# =================================================================

@echo off
REM Windows batch script for running the parser

setlocal

set SOURCE_DIR=%1
set OUTPUT_DIR=%2

if "%SOURCE_DIR%"=="" (
    echo ERROR: Source directory required
    echo Usage: run_parser.bat C:\mainframe\cobol [output_dir]
    exit /b 1
)

if "%OUTPUT_DIR%"=="" (
    set OUTPUT_DIR=.\index
)

echo ============================================
echo COBOL Batch Parser
echo ============================================
echo Source: %SOURCE_DIR%
echo Output: %OUTPUT_DIR%
echo.

python batch_parser.py --source "%SOURCE_DIR%" --output "%OUTPUT_DIR%"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] Parsing completed!
    echo.
    echo Index files:
    dir "%OUTPUT_DIR%"
) else (
    echo.
    echo [ERROR] Parsing failed!
    echo Check batch_parser.log for details
    exit /b 1
)

# =================================================================
# MAKEFILE - Build automation
# =================================================================

.PHONY: index reindex watch serve clean help

# Default source and output directories
SOURCE_DIR ?= /mainframe/cobol
OUTPUT_DIR ?= ./index

help:
	@echo "COBOL Batch Parser - Make Commands"
	@echo ""
	@echo "Usage:"
	@echo "  make index         - Full index (first time)"
	@echo "  make reindex       - Incremental reindex (changed files only)"
	@echo "  make watch         - Watch for changes and auto-reindex"
	@echo "  make serve         - Start MCP server"
	@echo "  make clean         - Remove all indexes"
	@echo ""
	@echo "Variables:"
	@echo "  SOURCE_DIR=$(SOURCE_DIR)"
	@echo "  OUTPUT_DIR=$(OUTPUT_DIR)"
	@echo ""
	@echo "Example:"
	@echo "  make index SOURCE_DIR=/path/to/cobol OUTPUT_DIR=./my_index"

index:
	@echo "Starting full index..."
	python3 batch_parser.py --source $(SOURCE_DIR) --output $(OUTPUT_DIR)
	@echo ""
	@echo "✓ Indexing complete!"

reindex:
	@echo "Starting incremental reindex..."
	python3 batch_parser.py --source $(SOURCE_DIR) --output $(OUTPUT_DIR) --incremental
	@echo ""
	@echo "✓ Reindexing complete!"

watch:
	@echo "Starting watch mode..."
	python3 batch_parser.py --watch $(SOURCE_DIR) --output $(OUTPUT_DIR)

serve:
	@echo "Starting MCP server..."
	python3 cobol_rag_agent.py serve --index-dir $(OUTPUT_DIR)

clean:
	@echo "Removing indexes..."
	rm -rf $(OUTPUT_DIR)/*.faiss
	rm -rf $(OUTPUT_DIR)/*.json
	rm -rf $(OUTPUT_DIR)/*.gpickle
	@echo "✓ Indexes removed"

# =================================================================
# QUICK START GUIDE
# =================================================================

### QUICK START GUIDE ###

# 1. ONE-TIME SETUP
# ------------------
# Install dependencies:
pip install tree-sitter sentence-transformers faiss-cpu networkx

# Make scripts executable (Linux/Mac):
chmod +x run_parser.sh quick_index.sh scheduled_reindex.sh


# 2. BASIC USAGE
# --------------

# Option A: Using shell script (easiest)
./run_parser.sh --source /mainframe/cobol

# Option B: Using Python directly
python3 batch_parser.py --source /mainframe/cobol --output ./index

# Option C: Using make
make index SOURCE_DIR=/mainframe/cobol


# 3. INCREMENTAL UPDATES
# ----------------------
# Only process files that changed since last run

./run_parser.sh --source /mainframe/cobol --incremental

# Or
make reindex


# 4. WATCH MODE
# -------------
# Automatically reindex when files change

./run_parser.sh --source /mainframe/cobol --watch

# Or
make watch


# 5. SCHEDULED INDEXING
# ---------------------
# Add to crontab for automatic nightly reindex

# Edit crontab
crontab -e

# Add this line (runs at 2 AM daily)
0 2 * * * /path/to/scheduled_reindex.sh

# Or use systemd timer (Linux)
cat > /etc/systemd/system/cobol-reindex.timer << 'EOF'
[Unit]
Description=COBOL Reindex Timer

[Timer]
OnCalendar=daily
OnCalendar=02:00

[Install]
WantedBy=timers.target
EOF

systemctl enable cobol-reindex.timer
systemctl start cobol-reindex.timer


# 6. SERVING THE INDEX
# --------------------
# After indexing, start the MCP server

python3 cobol_rag_agent.py serve --index-dir ./index

# Or
make serve


# 7. TYPICAL WORKFLOW
# -------------------

# Day 1: Initial full index
./run_parser.sh --source /mainframe/cobol --output ./prod_index

# Day 2-30: Incremental updates
./run_parser.sh --source /mainframe/cobol --output ./prod_index --incremental

# Or set up watch mode
./run_parser.sh --source /mainframe/cobol --output ./prod_index --watch


# 8. CHECKING STATUS
# ------------------

# View statistics
cat ./index/index_stats.json | jq

# Check logs
tail -f batch_parser.log

# Check what files were processed
cat ./index/.file_tracker.json | jq


# 9. TROUBLESHOOTING
# ------------------

# If parsing fails:
# 1. Check the log file
tail -100 batch_parser.log

# 2. Try a single file first
python3 batch_parser.py --source /path/to/single/file --output ./test_index

# 3. Verify file encoding
file /mainframe/cobol/PROGRAM.cbl

# 4. Check permissions
ls -la /mainframe/cobol/


# 10. ADVANCED USAGE
# ------------------

# Process only specific file types
find /mainframe/cobol -name "*.cbl" -type f > files.txt
# Then modify batch_parser.py to read from files.txt

# Parallel processing (split directories)
./run_parser.sh --source /mainframe/cobol/batch1 --output ./index1 &
./run_parser.sh --source /mainframe/cobol/batch2 --output ./index2 &
wait
# Then merge indexes (requires custom script)

# Remote indexing via SSH
ssh mainframe "python3 batch_parser.py --source /cobol --output /tmp/index"
scp -r mainframe:/tmp/index ./remote_index

# =================================================================
# EXAMPLE OUTPUT
# =================================================================

### When you run the parser, you'll see: ###

╔═══════════════════════════════════════════════════════╗
║         COBOL Batch Parser - Index Builder           ║
╚═══════════════════════════════════════════════════════╝

Configuration:
  Source:  /mainframe/cobol
  Output:  ./index
  Mode:    full

Starting full parse...
2025-10-16 10:00:00 - INFO - Scanning for files...
2025-10-16 10:00:01 - INFO - Found 1543 COBOL files
2025-10-16 10:00:01 - INFO - Found 234 Copybook files
2025-10-16 10:00:01 - INFO - Found 89 JCL files
2025-10-16 10:00:01 - INFO - Found 12 Procedure files

2025-10-16 10:00:02 - INFO - Processing COBOL files...
2025-10-16 10:00:02 - INFO - Processing COBOL: CUSTUPDT.cbl
2025-10-16 10:00:03 - INFO - Processing COBOL: VALIDATE.cbl
2025-10-16 10:00:04 - INFO - Processing COBOL: AUDITLOG.cbl
...

2025-10-16 10:15:30 - INFO - Saving indexes...

============================================================
BATCH PARSING COMPLETED
============================================================
Total Files Found:    1878
Files Processed:      1878
Files Skipped:        0
Files Failed:         0

Total Code Chunks:    15234
Programs Found:       1543
DB2 Tables:           245
MQ Operations:        89
CICS Commands:        456

Processing Time:      930.45 seconds
Files/Second:         2.02

Output Directory:     ./index
============================================================

✓ Parsing completed successfully!

Index files created in: ./index

-rw-r--r-- 1 user group 45M Oct 16 10:15 code_index.faiss
-rw-r--r-- 1 user group 89M Oct 16 10:15 code_chunks.json
-rw-r--r-- 1 user group 12M Oct 16 10:15 program_graph.gpickle
-rw-r--r-- 1 user group 234K Oct 16 10:15 index_stats.json
-rw-r--r-- 1 user group 456K Oct 16 10:15 .file_tracker.json

# =================================================================
# FAQ
# =================================================================

Q: How long does initial indexing take?
A: ~2 files/second on average hardware. 1000 files ≈ 8-10 minutes.

Q: How much disk space do I need?
A: Indexes are typically 10-20% of source code size.

Q: Can I run multiple parsers in parallel?
A: Yes, but point them to different output directories.

Q: What if parsing fails?
A: Check batch_parser.log. Most common issues:
   - File encoding (use latin-1 or cp037 for mainframe files)
   - Permissions
   - Disk space

Q: How do I update just one program?
A: Use --incremental mode. It auto-detects changed files.

Q: Can I schedule automatic reindexing?
A: Yes, use scheduled_reindex.sh with cron or systemd timers.

Q: How do I know what's been indexed?
A: Check index_stats.json and .file_tracker.json

Q: Can I index files on a mainframe?
A: Yes, either:
   1. Mount mainframe filesystem (NFS/CIFS)
   2. FTP files to local system
   3. Run parser on mainframe (if Python available)