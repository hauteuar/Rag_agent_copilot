#!/usr/bin/env python3
"""
Graph Diagnostic Tool - Check what's actually in your program graph
===================================================================
Run this to see what nodes are in your graph and why they might not be showing colors
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.getcwd())

def main():
    print("=" * 70)
    print("COBOL RAG GRAPH DIAGNOSTIC TOOL")
    print("=" * 70)
    print()
    
    # Import patches and agent
    print("Step 1: Loading patches...")
    try:
        import cobol_rag_patches
        print("✓ Patches loaded")
    except Exception as e:
        print(f"✗ Could not load patches: {e}")
        return
    
    print("\nStep 2: Loading index...")
    try:
        from cobol_rag_agent import COBOLIndexer
        indexer = COBOLIndexer('./index')
        indexer.load_all()
        print(f"✓ Index loaded: {len(indexer.graph.graph.nodes)} nodes")
    except Exception as e:
        print(f"✗ Could not load index: {e}")
        return
    
    print("\nStep 3: Analyzing graph structure...")
    graph = indexer.graph.graph
    
    # Count node types
    node_types = {}
    for node, data in graph.nodes(data=True):
        node_type = data.get('node_type', data.get('type', 'unknown'))
        node_types[node_type] = node_types.get(node_type, 0) + 1
    
    print("\nNode Type Summary:")
    for ntype, count in sorted(node_types.items()):
        print(f"  {ntype:30s}: {count:5d} nodes")
    
    # Find a sample program
    print("\nStep 4: Finding sample program...")
    program_nodes = [n for n, d in graph.nodes(data=True) 
                     if d.get('node_type') == 'program' or n.startswith('prog:')]
    
    if not program_nodes:
        print("✗ No program nodes found!")
        return
    
    sample_prog = program_nodes[0]
    print(f"✓ Sample program: {sample_prog}")
    
    # Check what this program connects to
    print(f"\nStep 5: Analyzing {sample_prog}...")
    
    # Outgoing edges
    print("\n  Outgoing connections (what program uses):")
    for successor in graph.successors(sample_prog):
        succ_data = graph.nodes[successor]
        succ_type = succ_data.get('node_type', succ_data.get('type', 'unknown'))
        edge_data = graph.get_edge_data(sample_prog, successor) or {}
        edge_type = edge_data.get('edge_type', edge_data.get('type', 'unknown'))
        print(f"    → {successor:40s} ({succ_type:20s}) via {edge_type}")
    
    # Incoming edges
    print("\n  Incoming connections (what calls/uses program):")
    for predecessor in graph.predecessors(sample_prog):
        pred_data = graph.nodes[predecessor]
        pred_type = pred_data.get('node_type', pred_data.get('type', 'unknown'))
        edge_data = graph.get_edge_data(predecessor, sample_prog) or {}
        edge_type = edge_data.get('edge_type', edge_data.get('type', 'unknown'))
        print(f"    ← {predecessor:40s} ({pred_type:20s}) via {edge_type}")
    
    # Check for CICS files
    print("\nStep 6: Checking for CICS file nodes...")
    cics_nodes = [n for n, d in graph.nodes(data=True) 
                  if 'cics' in d.get('node_type', '').lower()]
    
    if cics_nodes:
        print(f"✓ Found {len(cics_nodes)} CICS file nodes")
        for node in cics_nodes[:5]:  # Show first 5
            node_data = graph.nodes[node]
            print(f"    {node}: {node_data}")
    else:
        print("✗ No CICS file nodes found!")
        print("   This is why your diagram shows no green files")
    
    # Check for DB2 tables
    print("\nStep 7: Checking for database nodes...")
    db_nodes = [n for n, d in graph.nodes(data=True) 
                if d.get('node_type') in ['db2_table', 'table']]
    
    if db_nodes:
        print(f"✓ Found {len(db_nodes)} database nodes")
        for node in db_nodes[:5]:  # Show first 5
            node_data = graph.nodes[node]
            print(f"    {node}: {node_data}")
    else:
        print("✗ No database nodes found!")
        print("   This is why your diagram shows no green cylinders")
    
    # Check for MQ nodes
    print("\nStep 8: Checking for MQ nodes...")
    mq_nodes = [n for n, d in graph.nodes(data=True) 
                if d.get('node_type') in ['mq_operation', 'mq_queue']]
    
    if mq_nodes:
        print(f"✓ Found {len(mq_nodes)} MQ nodes")
        for node in mq_nodes[:5]:  # Show first 5
            node_data = graph.nodes[node]
            print(f"    {node}: {node_data}")
    else:
        print("✗ No MQ nodes found!")
        print("   This is why your diagram shows no orange boxes")
    
    print("\n" + "=" * 70)
    print("DIAGNOSIS COMPLETE")
    print("=" * 70)
    print()
    
    # Provide recommendations
    print("RECOMMENDATIONS:")
    print()
    
    if not cics_nodes and not db_nodes:
        print("❌ CRITICAL: No I/O nodes found in graph!")
        print()
        print("This explains why your flow diagram shows only blue boxes.")
        print()
        print("SOLUTION:")
        print("1. Make sure cobol_rag_patches.py v1.0.1 is imported in batch_parser.py")
        print("2. Delete old index: rm -rf ./index")
        print("3. Re-run: python batch_parser.py --source /path/to/cobol --output ./index")
        print("4. Check batch_parser.log for 'Added CICS INPUT file' messages")
        print()
    elif not cics_nodes:
        print("⚠️  WARNING: No CICS file nodes found")
        print("   Your COBOL code might not have CICS file operations")
        print("   Or the patches aren't being applied during indexing")
        print()
    elif not db_nodes:
        print("⚠️  WARNING: No database nodes found")
        print("   Your COBOL code might not have DB2 operations")
        print()
    else:
        print("✅ Graph structure looks good!")
        print("   If colors still wrong, check mcp_server_rag.py")
        print()

if __name__ == '__main__':
    main()