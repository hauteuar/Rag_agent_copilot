"""
MCP Server Wrapper for COBOL RAG with HTML Flow Generation
===========================================================
Implements proper MCP protocol for GitHub Copilot integration.
Includes interactive HTML flow diagram generation.

USAGE:
    Set INDEX_DIR environment variable, then:
    python mcp_server_rag.py
    
    Or use in VS Code settings.json:
    {
      "mcp.servers": {
        "cobol-rag": {
          "command": "python",
          "args": ["-u", "path/to/mcp_server_rag.py"],
          "env": {"INDEX_DIR": "path/to/index"}
        }
      }
    }
"""

import sys
import json
import os
import logging
import webbrowser
from typing import Dict, Any
from datetime import datetime

# Disable output buffering
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

import cobol_rag_patches  # This auto-applies all patches
# Import from cobol_rag_agent
try:
    from cobol_rag_agent import COBOLIndexer, MCPServer
except ImportError:
    error = {
        "jsonrpc": "2.0",
        "id": None,
        "error": {
            "code": -32000,
            "message": "cobol_rag_agent.py not found"
        }
    }
    print(json.dumps(error))
    sys.stdout.flush()
    sys.exit(1)

# Setup logging to file only (not stdout)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('mcp_server.log', mode='w')]
)
logger = logging.getLogger(__name__)


def generate_flow_html(mermaid_code: str, node_name: str, output_path: str = None) -> str:
    """
    Generate interactive HTML file with Mermaid diagram
    Returns the file path
    """
    if output_path is None:
        output_path = f"flow_diagram_{node_name.replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>COBOL Flow Diagram - {node_name}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #2d3748 0%, #1a202c 100%);
            color: white;
            padding: 30px;
            border-bottom: 4px solid #667eea;
        }}
        
        .header h1 {{
            font-size: 28px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        
        .header h1::before {{
            content: "📊";
            font-size: 32px;
        }}
        
        .header .subtitle {{
            color: #cbd5e0;
            font-size: 16px;
        }}
        
        .controls {{
            background: #f7fafc;
            padding: 20px 30px;
            border-bottom: 1px solid #e2e8f0;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}
        
        .btn {{
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }}
        
        .btn-primary {{
            background: #667eea;
            color: white;
        }}
        
        .btn-primary:hover {{
            background: #5a67d8;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }}
        
        .btn-secondary {{
            background: #48bb78;
            color: white;
        }}
        
        .btn-secondary:hover {{
            background: #38a169;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(72, 187, 120, 0.4);
        }}
        
        .btn-info {{
            background: #4299e1;
            color: white;
        }}
        
        .btn-info:hover {{
            background: #3182ce;
        }}
        
        .zoom-controls {{
            display: flex;
            gap: 10px;
            margin-left: auto;
        }}
        
        .diagram-container {{
            padding: 40px;
            background: white;
            min-height: 600px;
            display: flex;
            justify-content: center;
            align-items: center;
            overflow: auto;
            position: relative;
        }}
        
        .mermaid {{
            background: white;
            transition: transform 0.3s ease;
        }}
        
        .legend {{
            background: #f7fafc;
            padding: 20px 30px;
            border-top: 1px solid #e2e8f0;
        }}
        
        .legend h3 {{
            color: #2d3748;
            margin-bottom: 15px;
            font-size: 18px;
        }}
        
        .legend-items {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .legend-box {{
            width: 40px;
            height: 30px;
            border-radius: 4px;
            border: 2px solid;
        }}
        
        .legend-program {{
            background: #4A90E2;
            border-color: #2E5C8A;
        }}
        
        .legend-db2 {{
            background: #50C878;
            border-color: #2D7A4A;
        }}
        
        .legend-mq {{
            background: #FFA500;
            border-color: #CC8400;
        }}
        
        .legend-cics {{
            background: #9B59B6;
            border-color: #6C3483;
        }}
        
        .info-panel {{
            background: #edf2f7;
            padding: 20px 30px;
            border-top: 1px solid #e2e8f0;
        }}
        
        .info-panel h3 {{
            color: #2d3748;
            margin-bottom: 10px;
        }}
        
        .info-panel p {{
            color: #4a5568;
            line-height: 1.6;
        }}
        
        .timestamp {{
            color: #718096;
            font-size: 12px;
            text-align: center;
            padding: 15px;
            background: #f7fafc;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            .controls, .legend, .info-panel {{
                display: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>COBOL Program Flow Diagram</h1>
            <div class="subtitle">Program: {node_name} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        
        <div class="controls">
            <button class="btn btn-primary" onclick="downloadSVG()">
                💾 Download SVG
            </button>
            <button class="btn btn-secondary" onclick="downloadPNG()">
                🖼️ Download PNG
            </button>
            <button class="btn btn-info" onclick="window.print()">
                🖨️ Print
            </button>
            <div class="zoom-controls">
                <button class="btn btn-primary" onclick="zoomIn()">🔍 Zoom In</button>
                <button class="btn btn-primary" onclick="zoomOut()">🔍 Zoom Out</button>
                <button class="btn btn-primary" onclick="resetZoom()">↻ Reset</button>
            </div>
        </div>
        
        <div class="diagram-container" id="diagram-container">
            <div class="mermaid" id="mermaid-diagram">
{mermaid_code}
            </div>
        </div>
        
        <div class="legend">
            <h3>Legend</h3>
            <div class="legend-items">
                <div class="legend-item">
                    <div class="legend-box legend-program"></div>
                    <span><strong>Program</strong> - COBOL program module</span>
                </div>
                <div class="legend-item">
                    <div class="legend-box legend-db2"></div>
                    <span><strong>DB2 Table</strong> - Database table access</span>
                </div>
                <div class="legend-item">
                    <div class="legend-box legend-mq"></div>
                    <span><strong>MQ Operation</strong> - Message queue operation</span>
                </div>
                <div class="legend-item">
                    <div class="legend-box legend-cics"></div>
                    <span><strong>CICS Command</strong> - CICS transaction command</span>
                </div>
            </div>
        </div>
        
        <div class="info-panel">
            <h3>About This Diagram</h3>
            <p>
                This interactive flow diagram shows the program structure, dependencies, and interfaces 
                for the COBOL program <strong>{node_name}</strong>. Use the zoom controls to explore 
                different parts of the diagram. Click the download buttons to save this diagram for 
                documentation or presentations.
            </p>
        </div>
        
        <div class="timestamp">
            Generated by COBOL RAG System | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
    
    <script>
        // Initialize Mermaid
        mermaid.initialize({{ 
            startOnLoad: true,
            theme: 'default',
            flowchart: {{
                useMaxWidth: true,
                htmlLabels: true,
                curve: 'basis'
            }}
        }});
        
        // Zoom functionality
        let currentZoom = 1;
        const container = document.getElementById('diagram-container');
        const diagram = document.getElementById('mermaid-diagram');
        
        function zoomIn() {{
            currentZoom = Math.min(currentZoom + 0.2, 3);
            diagram.style.transform = `scale(${{currentZoom}})`;
        }}
        
        function zoomOut() {{
            currentZoom = Math.max(currentZoom - 0.2, 0.5);
            diagram.style.transform = `scale(${{currentZoom}})`;
        }}
        
        function resetZoom() {{
            currentZoom = 1;
            diagram.style.transform = 'scale(1)';
        }}
        
        // Download as SVG
        function downloadSVG() {{
            const svg = document.querySelector('.mermaid svg');
            if (!svg) {{
                alert('Diagram not rendered yet');
                return;
            }}
            
            const serializer = new XMLSerializer();
            const svgString = serializer.serializeToString(svg);
            const blob = new Blob([svgString], {{ type: 'image/svg+xml' }});
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = 'flow_diagram_{node_name.replace(":", "_")}.svg';
            a.click();
            
            URL.revokeObjectURL(url);
        }}
        
        // Download as PNG
        function downloadPNG() {{
            const svg = document.querySelector('.mermaid svg');
            if (!svg) {{
                alert('Diagram not rendered yet');
                return;
            }}
            
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            const svgData = new XMLSerializer().serializeToString(svg);
            const img = new Image();
            
            const svgBlob = new Blob([svgData], {{ type: 'image/svg+xml;charset=utf-8' }});
            const url = URL.createObjectURL(svgBlob);
            
            img.onload = function() {{
                canvas.width = img.width * 2;
                canvas.height = img.height * 2;
                ctx.fillStyle = 'white';
                ctx.fillRect(0, 0, canvas.width, canvas.height);
                ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
                
                canvas.toBlob(function(blob) {{
                    const pngUrl = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = pngUrl;
                    a.download = 'flow_diagram_{node_name.replace(":", "_")}.png';
                    a.click();
                    URL.revokeObjectURL(pngUrl);
                }});
                
                URL.revokeObjectURL(url);
            }};
            
            img.src = url;
        }}
        
        // Make diagram draggable
        let isDragging = false;
        let startX, startY, scrollLeft, scrollTop;
        
        container.addEventListener('mousedown', (e) => {{
            isDragging = true;
            startX = e.pageX - container.offsetLeft;
            startY = e.pageY - container.offsetTop;
            scrollLeft = container.scrollLeft;
            scrollTop = container.scrollTop;
            container.style.cursor = 'grabbing';
        }});
        
        container.addEventListener('mouseleave', () => {{
            isDragging = false;
            container.style.cursor = 'default';
        }});
        
        container.addEventListener('mouseup', () => {{
            isDragging = false;
            container.style.cursor = 'default';
        }});
        
        container.addEventListener('mousemove', (e) => {{
            if (!isDragging) return;
            e.preventDefault();
            const x = e.pageX - container.offsetLeft;
            const y = e.pageY - container.offsetTop;
            const walkX = (x - startX) * 1;
            const walkY = (y - startY) * 1;
            container.scrollLeft = scrollLeft - walkX;
            container.scrollTop = scrollTop - walkY;
        }});
    </script>
</body>
</html>"""
    
    # Write HTML file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    logger.info(f"Generated HTML flow diagram: {output_path}")
    
    # Open in browser
    abs_path = os.path.abspath(output_path)
    webbrowser.open(f'file:///{abs_path}')
    
    return abs_path


class MCPServerWrapper:
    """MCP Protocol Wrapper for COBOL RAG Agent"""
    
    def __init__(self, index_dir: str):
        self.index_dir = index_dir
        self.initialized = False
        self.server = None
        
        logger.info(f"Initializing MCP Server with index: {index_dir}")
        
        # Load indexes
        try:
            indexer = COBOLIndexer(index_dir)
            indexer.load_all()
            self.server = MCPServer(indexer.code_index, indexer.doc_index, indexer.graph)
            logger.info("Indexes loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load indexes: {e}", exc_info=True)
            raise
    
    def handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP initialize request"""
        logger.info("Handling initialize request")
        self.initialized = True
        
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "cobol-rag",
                "version": "1.0.0"
            }
        }
    
    def handle_tools_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tools/list request"""
        logger.info("Handling tools/list request")
        
        tools = [
            {
                "name": "search_code",
                "description": "Search COBOL/JCL code semantically using natural language queries. Returns relevant code chunks with program names, file locations, and similarity scores.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Natural language search query (e.g., 'DB2 SELECT customer table', 'CICS READ commands', 'MQ message processing')"
                        },
                        "top_k": {
                            "type": "integer",
                            "description": "Number of results to return (default: 5)",
                            "default": 5
                        }
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "search_docs",
                "description": "Search documentation (PDF, Word, Markdown, HTML, Text) using natural language queries. Returns relevant documentation chunks.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query for documentation"
                        },
                        "top_k": {
                            "type": "integer",
                            "description": "Number of results to return (default: 5)",
                            "default": 5
                        }
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "graph_neighbors",
                "description": "Get program relationships, dependencies, and interfaces (DB2 tables, files, MQ operations). Shows what a program calls and what calls it.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "node": {
                            "type": "string",
                            "description": "Node ID in format 'prog:PROGRAMNAME' (e.g., 'prog:CUSTUPDT') or 'table:TABLENAME' (e.g., 'table:CUSTOMER')"
                        },
                        "depth": {
                            "type": "integer",
                            "description": "Traversal depth - how many levels of relationships to explore (default: 1)",
                            "default": 1
                        }
                    },
                    "required": ["node"]
                }
            },
            {
                "name": "flow_mermaid",
                "description": "Generate Mermaid flow diagram showing program flow with inputs at top, outputs at bottom, and processing in middle. Shows only I/O interfaces (files, DB2, MQ), not all CICS commands. Includes dynamic call resolution.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "node": {
                            "type": "string",
                            "description": "Program to visualize in format 'prog:PROGRAMNAME' (e.g., 'prog:TMST9JE')"
                        },
                        "depth": {
                            "type": "integer",
                            "description": "Diagram depth - how many levels to show (default: 2)",
                            "default": 2
                        }
                    },
                    "required": ["node"]
                }
            },
            {
                "name": "flow_html",
                "description": "Generate interactive HTML visualization of program flow. Creates an HTML file and opens it in browser with zoom, pan, download as SVG/PNG. Shows inputs/outputs/processing layout.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "node": {
                            "type": "string",
                            "description": "Program to visualize in format 'prog:PROGRAMNAME' (e.g., 'prog:TMST9JE')"
                        },
                        "depth": {
                            "type": "integer",
                            "description": "Diagram depth - how many levels to show (default: 2)",
                            "default": 2
                        },
                        "output_file": {
                            "type": "string",
                            "description": "Optional output filename (default: auto-generated with timestamp)"
                        }
                    },
                    "required": ["node"]
                }
            },
            {
                "name": "full_program_chain",
                "description": "Analyze complete program execution chain. Shows full flow from entry program through all called programs with files, databases, and MQ operations. Example: TMST9JE calls TMST9JF with input files, DB2 operations, and outputs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "program": {
                            "type": "string",
                            "description": "Starting program name (e.g., 'TMST9JE')"
                        },
                        "max_depth": {
                            "type": "integer",
                            "description": "Maximum depth to traverse (default: 5)",
                            "default": 5
                        }
                    },
                    "required": ["program"]
                }
            },
            {
                "name": "resolve_dynamic_call",
                "description": "Resolve dynamic CALL statements by analyzing data structures. Handles VALUE clauses in group items (e.g., 01 group with FILLER VALUE 'TMS', variable PIC X(5)) and conditional logic.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "variable": {
                            "type": "string",
                            "description": "Variable name used in dynamic CALL (e.g., 'WS-PROGRAM-NAME', 'DYN-VAR')"
                        },
                        "context": {
                            "type": "string",
                            "description": "COBOL source code context with data definitions and CALL statement"
                        }
                    },
                    "required": ["variable", "context"]
                }
            },
            {
                "name": "combined_search",
                "description": "Comprehensive search across code, docs, and graph. Provides complete context about a topic.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query (e.g., 'customer update transaction flow')"
                        },
                        "top_k": {
                            "type": "integer",
                            "description": "Number of results per search type (default: 5)",
                            "default": 5
                        }
                    },
                    "required": ["query"]
                }
            }
        ]
        
        return {"tools": tools}
    
    def handle_tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tools/call request"""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        logger.info(f"Handling tool call: {tool_name} with args: {arguments}")
        
        # Special handler for flow_html
        if tool_name == "flow_html":
            node = arguments.get("node", "")
            depth = arguments.get("depth", 2)
            output_file = arguments.get("output_file", None)
            
            # First get the mermaid diagram
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "flow_mermaid",
                "params": {"node": node, "depth": depth}
            }
            
            response = self.server.handle_request(request)
            
            if "error" in response:
                raise Exception(response["error"]["message"])
            
            mermaid_code = response["result"]["mermaid_diagram"]
            
            # Generate HTML file
            html_path = generate_flow_html(mermaid_code, node, output_file)
            
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"""✅ Interactive flow diagram generated and opened in browser!

📄 **File:** {html_path}

🎨 **Features:**
- 🔍 Zoom in/out controls
- 📊 Interactive pan and drag
- 💾 Download as SVG or PNG
- 🖨️ Print-friendly
- 📱 Responsive design

📋 **The diagram shows:**
- 📥 **Inputs at top** (files, MQ queues)
- 💻 **Processing in middle** (programs)
- 🗄️ **Database operations** (DB2 tables with operations)
- 📤 **Outputs at bottom** (files, MQ queues)
- 🔗 **Dynamic calls resolved** (shows possible targets)

You can now explore the flow visually in your browser!"""
                    }
                ]
            }
        
        # Special handler for full_program_chain
        if tool_name == "full_program_chain":
            program = arguments.get("program", "")
            max_depth = arguments.get("max_depth", 5)
            
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "full_program_chain",
                "params": {"program": program, "max_depth": max_depth}
            }
            
            response = self.server.handle_request(request)
            
            if "error" in response:
                raise Exception(response["error"]["message"])
            
            chain = response["result"]
            
            # Format nice output
            output_lines = [
                f"# Complete Program Chain Analysis: {program}",
                "",
                "## Execution Flow",
                ""
            ]
            
            for step in chain.get('execution_flow', []):
                indent = "  " * step['depth']
                output_lines.append(f"{indent}📌 **{step['name']}** ({step['type']})")
                
                if step['inputs']:
                    output_lines.append(f"{indent}  📥 Inputs:")
                    for inp in step['inputs']:
                        output_lines.append(f"{indent}    - {inp}")
                
                if step['outputs']:
                    output_lines.append(f"{indent}  📤 Outputs:")
                    for out in step['outputs']:
                        output_lines.append(f"{indent}    - {out}")
                
                if step['calls']:
                    output_lines.append(f"{indent}  🔗 Calls:")
                    for call in step['calls']:
                        program = call['program']
                        call_type = call['call_type']
                        
                        # Format call with type indicator
                        output = f"  🔗 {program}"
                        
                        if call.get('is_dynamic'):
                            output += f" (cics_link_dynamic)"
                            
                            # Show resolution method
                            if call.get('resolved_via_group'):
                                output += f"\n       └─ Group: {call['resolved_via_group']}"
                            else:
                                output += f"\n       └─ Direct: Variable resolution"
                            
                            # Show resolution details
                            if call.get('resolution_details'):
                                details = call['resolution_details']
                                for i, detail in enumerate(details):
                                    line_num = detail.get('line', '?')
                                    value = detail.get('value', '?')
                                    condition = detail.get('condition', '')
                                    
                                    if i == 0:
                                        output += f"\n       └─ Line {line_num}: MOVE '{value}' TO {call.get('variable', '?')}"
                                    else:
                                        output += f"\n       └─ Line {line_num}: MOVE '{value}' TO {call.get('variable', '?')}"
                                    
                                    if condition and condition != 'None':
                                        output += f" [{condition}]"
                        else:
                            output += f" (static)"
                        
                        output_lines.append(output)
                
                output_lines.append("")
            
            # Add summary
            output_lines.extend([
                "## Summary",
                f"- **Programs called:** {len(chain.get('programs_called', []))}",
                f"- **Databases accessed:** {len(chain.get('databases', []))}",
                f"- **MQ queues used:** {len(chain.get('mq_queues', []))}",
                "",
                "### Database Operations"
            ])
            
            for db in chain.get('databases', []):
                output_lines.append(f"- **{db['table']}**: {db['operation']}")
            
            if chain.get('mermaid_diagram'):
                output_lines.extend([
                    "",
                    "### Flow Diagram",
                    "```mermaid",
                    chain['mermaid_diagram'],
                    "```"
                ])
            
            return {
                "content": [
                    {
                        "type": "text",
                        "text": '\n'.join(output_lines)
                    }
                ]
            }
        
        # Regular tool handlers
        method_map = {
            "search_code": "search_code",
            "search_docs": "search_docs",
            "graph_neighbors": "graph_neighbors",
            "flow_mermaid": "flow_mermaid",
            "resolve_dynamic_call": "resolve_dynamic_call",
            "combined_search": "combined_search"
        }
        
        method = method_map.get(tool_name)
        if not method:
            logger.error(f"Unknown tool: {tool_name}")
            raise Exception(f"Unknown tool: {tool_name}")
        
        # Call the underlying server
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": arguments
        }
        
        response = self.server.handle_request(request)
        logger.info(f"Tool call response: {json.dumps(response)[:200]}...")
        
        if "error" in response:
            raise Exception(response["error"]["message"])
        
        # Format result as MCP expects
        result_text = json.dumps(response["result"], indent=2)
        
        return {
            "content": [
                {
                    "type": "text",
                    "text": result_text
                }
            ]
        }
    
    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle incoming MCP request"""
        method = request.get("method")
        params = request.get("params", {})
        request_id = request.get("id")
        
        logger.info(f"Received request: method={method}, id={request_id}")
        
        try:
            if method == "initialize":
                result = self.handle_initialize(params)
            elif method == "initialized":
                # Client confirms initialization
                logger.info("Client confirmed initialization")
                return None  # No response needed for notification
            elif method == "tools/list":
                result = self.handle_tools_list(params)
            elif method == "tools/call":
                result = self.handle_tools_call(params)
            elif method == "ping":
                result = {}
            else:
                logger.error(f"Unknown method: {method}")
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                }
            
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": result
            }
            logger.info(f"Sending response: {json.dumps(response)[:200]}...")
            return response
        
        except Exception as e:
            logger.error(f"Error handling request: {e}", exc_info=True)
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": str(e)
                }
            }
    
    def run(self):
        """Run the MCP server on stdin/stdout"""
        logger.info("=" * 70)
        logger.info("MCP Server started - listening on stdin/stdout")
        logger.info("=" * 70)
        
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            
            logger.info(f"Received: {line}")
            
            try:
                request = json.loads(line)
                response = self.handle_request(request)
                
                if response is not None:  # Some notifications don't need responses
                    output = json.dumps(response)
                    print(output)
                    sys.stdout.flush()
                    logger.info(f"Sent: {output[:200]}...")
                    
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON: {e}")
                error_response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": "Parse error"
                    }
                }
                print(json.dumps(error_response))
                sys.stdout.flush()
            except Exception as e:
                logger.error(f"Unexpected error: {e}", exc_info=True)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='MCP Server for COBOL RAG')
    parser.add_argument('command', nargs='?', default='serve', 
                       help='Command to run (default: serve)')
    parser.add_argument('--index-dir', default=None,
                       help='Index directory path')
    
    args = parser.parse_args()
    
    logger.info("Starting MCP Server Wrapper")
    
    # Get index directory from args, environment, or default
    if args.index_dir:
        index_dir = args.index_dir
    else:
        index_dir = os.getenv('INDEX_DIR', './index')
    
    # Convert relative to absolute path
    index_dir = os.path.abspath(index_dir)
    logger.info(f"Index directory: {index_dir}")
    
    if not os.path.exists(index_dir):
        error = {
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": -32000,
                "message": f"Index directory not found: {index_dir}. Run batch_parser.py first."
            }
        }
        print(json.dumps(error))
        sys.stdout.flush()
        logger.error(f"Index directory not found: {index_dir}")
        sys.exit(1)
    
    try:
        server = MCPServerWrapper(index_dir)
        server.run()
    except Exception as e:
        logger.error(f"Server initialization failed: {e}", exc_info=True)
        error = {
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": -32000,
                "message": f"Server initialization failed: {str(e)}"
            }
        }
        print(json.dumps(error))
        sys.stdout.flush()
        sys.exit(1)


if __name__ == '__main__':
    main()