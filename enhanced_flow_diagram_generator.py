"""
Enhanced Flow Diagram Generator for COBOL RAG Agent
Properly visualizes CICS LINK, XCTL, and dynamic calls in Mermaid and HTML diagrams
"""

import logging
from typing import Dict, List, Any, Set, Tuple
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class EnhancedFlowDiagramGenerator:
    """
    Enhanced flow diagram generator that properly handles:
    1. CICS LINK calls
    2. CICS XCTL calls  
    3. Dynamic CALL statements (CALL with variable)
    4. Static CALL statements
    """
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        
        # Define visual styles for different call mechanisms
        self.call_styles = {
            'STATIC_CALL': {
                'arrow': '-->',
                'style': 'stroke:#2E5C8A,stroke-width:2px',
                'label_prefix': '📞',
                'description': 'Static CALL'
            },
            'DYNAMIC_CALL': {
                'arrow': '-.->',
                'style': 'stroke:#FF6B6B,stroke-width:2px,stroke-dasharray:5',
                'label_prefix': '🔄',
                'description': 'Dynamic CALL'
            },
            'CICS_LINK': {
                'arrow': '==>',
                'style': 'stroke:#4ECDC4,stroke-width:3px',
                'label_prefix': '🔗',
                'description': 'CICS LINK'
            },
            'CICS_XCTL': {
                'arrow': '===>',
                'style': 'stroke:#FF9F1C,stroke-width:3px',
                'label_prefix': '⚡',
                'description': 'CICS XCTL'
            },
            'CICS_LINK_DYNAMIC': {
                'arrow': '=.=>',
                'style': 'stroke:#4ECDC4,stroke-width:3px,stroke-dasharray:5',
                'label_prefix': '🔗🔄',
                'description': 'CICS LINK (Dynamic)'
            },
            'CICS_XCTL_DYNAMIC': {
                'arrow': '=.==>',
                'style': 'stroke:#FF9F1C,stroke-width:3px,stroke-dasharray:5',
                'label_prefix': '⚡🔄',
                'description': 'CICS XCTL (Dynamic)'
            }
        }
    
    def generate_enhanced_flow_diagram(self, session_id: str, program_name: str, 
                                      depth: int = 3) -> Dict[str, Any]:
        """
        Generate enhanced flow diagram with proper call type visualization
        
        Args:
            session_id: Session identifier
            program_name: Starting program name
            depth: How many levels deep to traverse
            
        Returns:
            Dictionary with mermaid code and HTML
        """
        try:
            logger.info(f"Generating enhanced flow diagram for {program_name}, depth={depth}")
            
            # Get all program calls with their mechanisms
            calls = self._get_program_calls_with_mechanisms(session_id, program_name, depth)
            
            if not calls:
                logger.warning(f"No calls found for {program_name}")
                return self._generate_empty_diagram(program_name)
            
            # Generate Mermaid diagram
            mermaid_code = self._generate_mermaid_with_call_types(program_name, calls, depth)
            
            # Generate HTML wrapper
            html_code = self._generate_html_diagram(mermaid_code, program_name, calls)
            
            return {
                'success': True,
                'mermaid': mermaid_code,
                'html': html_code,
                'call_summary': self._generate_call_summary(calls),
                'program_name': program_name,
                'depth': depth,
                'total_calls': len(calls)
            }
            
        except Exception as e:
            logger.error(f"Error generating enhanced flow diagram: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'mermaid': '',
                'html': ''
            }
    
    def _get_program_calls_with_mechanisms(self, session_id: str, 
                                          start_program: str, 
                                          depth: int) -> List[Dict[str, Any]]:
        """
        Retrieve all program calls with their call mechanisms
        
        Returns list of call records with:
        - source_program
        - target_program
        - call_mechanism (STATIC_CALL, DYNAMIC_CALL, CICS_LINK, CICS_XCTL)
        - variable_name (for dynamic calls)
        - line_number
        - sequence
        """
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            # Query to get all calls recursively
            query = """
            WITH RECURSIVE call_chain AS (
                -- Base case: direct calls from start program
                SELECT 
                    pf.source_program,
                    pf.target_program,
                    pf.call_mechanism,
                    pf.variable_name,
                    pf.line_number,
                    pf.call_sequence,
                    pf.confidence_score,
                    1 as level
                FROM program_flow_traces pf
                WHERE pf.session_id = ?
                  AND pf.source_program = ?
                
                UNION ALL
                
                -- Recursive case: calls from target programs
                SELECT 
                    pf.source_program,
                    pf.target_program,
                    pf.call_mechanism,
                    pf.variable_name,
                    pf.line_number,
                    pf.call_sequence,
                    pf.confidence_score,
                    cc.level + 1
                FROM program_flow_traces pf
                INNER JOIN call_chain cc ON pf.source_program = cc.target_program
                WHERE pf.session_id = ?
                  AND cc.level < ?
            )
            SELECT DISTINCT 
                source_program,
                target_program,
                call_mechanism,
                variable_name,
                line_number,
                call_sequence,
                confidence_score,
                level
            FROM call_chain
            ORDER BY level, call_sequence
            """
            
            cursor.execute(query, (session_id, start_program, session_id, depth))
            rows = cursor.fetchall()
            
            calls = []
            for row in rows:
                call = {
                    'source_program': row[0],
                    'target_program': row[1],
                    'call_mechanism': row[2] or 'STATIC_CALL',
                    'variable_name': row[3],
                    'line_number': row[4],
                    'sequence': row[5],
                    'confidence': row[6] or 0.8,
                    'level': row[7]
                }
                calls.append(call)
            
            logger.info(f"Found {len(calls)} calls for {start_program}")
            return calls
            
        except Exception as e:
            logger.error(f"Error retrieving program calls: {str(e)}")
            return []
    
    def _generate_mermaid_with_call_types(self, start_program: str, 
                                         calls: List[Dict], 
                                         depth: int) -> str:
        """
        Generate Mermaid diagram code with proper call type visualization
        """
        lines = []
        lines.append("graph TD")
        lines.append("")
        lines.append("%% Style definitions")
        lines.append("classDef programNode fill:#4A90E2,stroke:#2E5C8A,stroke-width:2px,color:#fff")
        lines.append("classDef dynamicNode fill:#FF6B6B,stroke:#C92A2A,stroke-width:2px,color:#fff")
        lines.append("classDef cicsNode fill:#4ECDC4,stroke:#2A9D8F,stroke-width:2px,color:#000")
        lines.append("classDef startNode fill:#51CF66,stroke:#2F9E44,stroke-width:3px,color:#fff")
        lines.append("")
        
        # Track all programs (nodes)
        all_programs = set([start_program])
        for call in calls:
            all_programs.add(call['source_program'])
            all_programs.add(call['target_program'])
        
        # Define nodes with appropriate styles
        lines.append("%% Node definitions")
        for program in sorted(all_programs):
            safe_id = self._safe_id(program)
            
            if program == start_program:
                lines.append(f'    {safe_id}["{program}\\n(Entry Point)"]:::startNode')
            else:
                lines.append(f'    {safe_id}["{program}"]:::programNode')
        
        lines.append("")
        lines.append("%% Call relationships")
        
        # Group calls by mechanism for better organization
        calls_by_mechanism = {}
        for call in calls:
            mechanism = call['call_mechanism']
            if mechanism not in calls_by_mechanism:
                calls_by_mechanism[mechanism] = []
            calls_by_mechanism[mechanism].append(call)
        
        # Generate edges for each call mechanism type
        for mechanism in sorted(calls_by_mechanism.keys()):
            calls_of_type = calls_by_mechanism[mechanism]
            style_info = self.call_styles.get(mechanism, self.call_styles['STATIC_CALL'])
            
            lines.append(f"    %% {style_info['description']} calls")
            
            for call in calls_of_type:
                source_id = self._safe_id(call['source_program'])
                target_id = self._safe_id(call['target_program'])
                arrow = style_info['arrow']
                label_prefix = style_info['label_prefix']
                
                # Build label
                label_parts = [label_prefix]
                
                if call.get('variable_name'):
                    label_parts.append(f"via {call['variable_name']}")
                
                if call.get('line_number'):
                    label_parts.append(f"L{call['line_number']}")
                
                label = ' '.join(label_parts)
                
                lines.append(f'    {source_id} {arrow}|"{label}"| {target_id}')
            
            lines.append("")
        
        # Add legend
        lines.append("%% Legend")
        lines.append("subgraph Legend")
        lines.append('    L1["📞 Static CALL"]')
        lines.append('    L2["🔄 Dynamic CALL"]')
        lines.append('    L3["🔗 CICS LINK"]')
        lines.append('    L4["⚡ CICS XCTL"]')
        lines.append("end")
        
        return '\n'.join(lines)
    
    def _generate_html_diagram(self, mermaid_code: str, program_name: str, 
                              calls: List[Dict]) -> str:
        """
        Generate complete HTML page with the Mermaid diagram
        """
        call_summary = self._generate_call_summary(calls)
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Program Flow: {program_name}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
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
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #2E5C8A 0%, #4A90E2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        
        .header p {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .call-summary {{
            background: #f8f9fa;
            padding: 25px;
            border-bottom: 2px solid #e9ecef;
        }}
        
        .call-summary h2 {{
            color: #2E5C8A;
            margin-bottom: 20px;
            font-size: 1.5em;
        }}
        
        .call-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        
        .stat-box {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #4A90E2;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .stat-box.dynamic {{
            border-left-color: #FF6B6B;
        }}
        
        .stat-box.cics-link {{
            border-left-color: #4ECDC4;
        }}
        
        .stat-box.cics-xctl {{
            border-left-color: #FF9F1C;
        }}
        
        .stat-label {{
            font-size: 0.9em;
            color: #6c757d;
            margin-bottom: 5px;
        }}
        
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #2E5C8A;
        }}
        
        .diagram-container {{
            padding: 40px;
            background: white;
            overflow-x: auto;
        }}
        
        .controls {{
            text-align: center;
            margin-bottom: 20px;
        }}
        
        .btn {{
            background: #4A90E2;
            color: white;
            border: none;
            padding: 12px 24px;
            margin: 0 5px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1em;
            transition: all 0.3s ease;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .btn:hover {{
            background: #2E5C8A;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }}
        
        .btn:active {{
            transform: translateY(0);
        }}
        
        #mermaid-diagram {{
            display: flex;
            justify-content: center;
            margin-top: 20px;
            transition: transform 0.3s ease;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
            border-top: 1px solid #e9ecef;
        }}
        
        .legend-info {{
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 6px;
            padding: 15px;
            margin: 20px 0;
        }}
        
        .legend-info h3 {{
            color: #856404;
            margin-bottom: 10px;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            margin: 8px 0;
            font-size: 0.95em;
        }}
        
        .legend-icon {{
            font-size: 1.2em;
            margin-right: 10px;
            width: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Program Flow Analysis</h1>
            <p>Entry Point: <strong>{program_name}</strong></p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="call-summary">
            <h2>📊 Call Statistics</h2>
            <div class="call-stats">
                <div class="stat-box">
                    <div class="stat-label">Total Calls</div>
                    <div class="stat-value">{call_summary['total']}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">📞 Static Calls</div>
                    <div class="stat-value">{call_summary['static']}</div>
                </div>
                <div class="stat-box dynamic">
                    <div class="stat-label">🔄 Dynamic Calls</div>
                    <div class="stat-value">{call_summary['dynamic']}</div>
                </div>
                <div class="stat-box cics-link">
                    <div class="stat-label">🔗 CICS LINK</div>
                    <div class="stat-value">{call_summary['cics_link']}</div>
                </div>
                <div class="stat-box cics-xctl">
                    <div class="stat-label">⚡ CICS XCTL</div>
                    <div class="stat-value">{call_summary['cics_xctl']}</div>
                </div>
            </div>
            
            <div class="legend-info">
                <h3>🔑 Call Type Legend</h3>
                <div class="legend-item">
                    <span class="legend-icon">📞</span>
                    <span><strong>Static CALL:</strong> Direct program call with literal name</span>
                </div>
                <div class="legend-item">
                    <span class="legend-icon">🔄</span>
                    <span><strong>Dynamic CALL:</strong> Program call using a variable (runtime determination)</span>
                </div>
                <div class="legend-item">
                    <span class="legend-icon">🔗</span>
                    <span><strong>CICS LINK:</strong> CICS transaction link (returns to caller)</span>
                </div>
                <div class="legend-item">
                    <span class="legend-icon">⚡</span>
                    <span><strong>CICS XCTL:</strong> CICS transaction transfer (no return)</span>
                </div>
            </div>
        </div>
        
        <div class="diagram-container">
            <div class="controls">
                <button class="btn" onclick="zoomIn()">🔍 Zoom In</button>
                <button class="btn" onclick="zoomOut()">🔎 Zoom Out</button>
                <button class="btn" onclick="resetZoom()">↺ Reset</button>
                <button class="btn" onclick="downloadSVG()">💾 Download SVG</button>
                <button class="btn" onclick="downloadPNG()">📷 Download PNG</button>
            </div>
            
            <div id="mermaid-diagram">
                <pre class="mermaid">
{mermaid_code}
                </pre>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by COBOL RAG Enhanced Flow Analyzer</p>
            <p>Analyzing {len(calls)} program calls across multiple levels</p>
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
                curve: 'basis',
                padding: 20
            }}
        }});
        
        // Zoom controls
        let currentZoom = 1;
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
        
        // Download functions
        function downloadSVG() {{
            const svg = document.querySelector('.mermaid svg');
            if (!svg) {{
                alert('Diagram not rendered yet. Please wait.');
                return;
            }}
            
            const serializer = new XMLSerializer();
            const svgString = serializer.serializeToString(svg);
            const blob = new Blob([svgString], {{ type: 'image/svg+xml' }});
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = '{program_name}_flow.svg';
            link.click();
            URL.revokeObjectURL(url);
        }}
        
        function downloadPNG() {{
            const svg = document.querySelector('.mermaid svg');
            if (!svg) {{
                alert('Diagram not rendered yet. Please wait.');
                return;
            }}
            
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            const svgString = new XMLSerializer().serializeToString(svg);
            const img = new Image();
            
            img.onload = function() {{
                canvas.width = img.width;
                canvas.height = img.height;
                ctx.fillStyle = 'white';
                ctx.fillRect(0, 0, canvas.width, canvas.height);
                ctx.drawImage(img, 0, 0);
                
                canvas.toBlob(function(blob) {{
                    const url = URL.createObjectURL(blob);
                    const link = document.createElement('a');
                    link.href = url;
                    link.download = '{program_name}_flow.png';
                    link.click();
                    URL.revokeObjectURL(url);
                }});
            }};
            
            img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgString)));
        }}
    </script>
</body>
</html>
"""
        return html
    
    def _generate_call_summary(self, calls: List[Dict]) -> Dict[str, int]:
        """Generate summary statistics of call types"""
        summary = {
            'total': len(calls),
            'static': 0,
            'dynamic': 0,
            'cics_link': 0,
            'cics_xctl': 0
        }
        
        for call in calls:
            mechanism = call.get('call_mechanism', 'STATIC_CALL')
            
            if mechanism == 'STATIC_CALL':
                summary['static'] += 1
            elif mechanism == 'DYNAMIC_CALL':
                summary['dynamic'] += 1
            elif mechanism in ['CICS_LINK', 'CICS_LINK_DYNAMIC']:
                summary['cics_link'] += 1
            elif mechanism in ['CICS_XCTL', 'CICS_XCTL_DYNAMIC']:
                summary['cics_xctl'] += 1
        
        return summary
    
    def _safe_id(self, name: str) -> str:
        """Convert program name to safe Mermaid ID"""
        return name.replace('-', '_').replace(' ', '_')
    
    def _generate_empty_diagram(self, program_name: str) -> Dict[str, Any]:
        """Generate empty diagram when no calls found"""
        mermaid_code = f"""
graph TD
    {self._safe_id(program_name)}["{program_name}\\n(No calls found)"]
    classDef startNode fill:#51CF66,stroke:#2F9E44,stroke-width:3px,color:#fff
    class {self._safe_id(program_name)} startNode
"""
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Program Flow: {program_name}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
</head>
<body>
    <h1>Program: {program_name}</h1>
    <p>No program calls found in the analysis.</p>
    <div class="mermaid">
{mermaid_code}
    </div>
    <script>
        mermaid.initialize({{ startOnLoad: true }});
    </script>
</body>
</html>
"""
        
        return {
            'success': True,
            'mermaid': mermaid_code,
            'html': html,
            'call_summary': {'total': 0, 'static': 0, 'dynamic': 0, 'cics_link': 0, 'cics_xctl': 0},
            'program_name': program_name,
            'total_calls': 0
        }


# Integration function for your RAG system
def integrate_enhanced_flow_diagrams(mainframe_analyzer):
    """
    Integrate enhanced flow diagram generator into your MainframeAnalyzer
    
    Usage:
        # In your MainframeAnalyzer class
        self.flow_diagram_generator = EnhancedFlowDiagramGenerator(self.db_manager)
        
        # Generate diagram
        result = self.flow_diagram_generator.generate_enhanced_flow_diagram(
            session_id=session_id,
            program_name='YOURPROGRAM',
            depth=3
        )
        
        # Save HTML
        with open('flow_diagram.html', 'w') as f:
            f.write(result['html'])
    """
    pass


if __name__ == "__main__":
    # Example usage
    print("Enhanced Flow Diagram Generator")
    print("================================")
    print("\nThis module provides:")
    print("✓ CICS LINK call visualization (🔗)")
    print("✓ CICS XCTL call visualization (⚡)")
    print("✓ Dynamic call visualization (🔄)")
    print("✓ Static call visualization (📞)")
    print("\nIntegrate into your MainframeAnalyzer to use.")