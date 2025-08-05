#!/usr/bin/env python3
"""
Fix dead code in nat_traversal.rs by:
1. Removing genuinely unused code
2. Making internal-use code pub(super) or pub(crate)
3. Adding proper feature flags where needed
"""

import re
import sys

def analyze_dead_code(file_path):
    """Analyze the dead code patterns in the file."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Find all #[allow(dead_code)] patterns with context
    pattern = r'([ \t]*#\[allow\(dead_code\)\].*?\n)(.*?)(?=\n[ \t]*(?:pub|fn|struct|enum|const|type|impl|\}|#\[))'
    matches = re.findall(pattern, content, re.DOTALL)
    
    print(f"Found {len(matches)} #[allow(dead_code)] patterns")
    
    # Categorize them
    categories = {
        'multi_path_infrastructure': [],
        'coordination_tracking': [],
        'resource_management': [],
        'statistics': [],
        'future_use': [],
        'memory_constrained': [],
        'unused_struct': [],
        'unused_function': [],
        'unused_field': [],
        'other': []
    }
    
    for allow_line, code in matches:
        # Check the comment in the allow line
        if 'multi-path' in allow_line or 'multi_path' in allow_line:
            categories['multi_path_infrastructure'].append((allow_line, code))
        elif 'coordination' in allow_line:
            categories['coordination_tracking'].append((allow_line, code))
        elif 'resource' in allow_line:
            categories['resource_management'].append((allow_line, code))
        elif 'statistics' in allow_line or 'stats' in allow_line:
            categories['statistics'].append((allow_line, code))
        elif 'future' in allow_line or 'reserved' in allow_line:
            categories['future_use'].append((allow_line, code))
        elif 'memory' in allow_line:
            categories['memory_constrained'].append((allow_line, code))
        elif 'struct ' in code:
            categories['unused_struct'].append((allow_line, code))
        elif 'fn ' in code:
            categories['unused_function'].append((allow_line, code))
        elif ':' in code and not 'fn ' in code:
            categories['unused_field'].append((allow_line, code))
        else:
            categories['other'].append((allow_line, code))
    
    return categories

def generate_fixes(categories):
    """Generate fix recommendations for each category."""
    fixes = {
        'remove_completely': [],
        'make_pub_super': [],
        'make_pub_crate': [],
        'add_feature_flag': [],
        'keep_with_todo': []
    }
    
    # Multi-path infrastructure - remove for now, add TODO
    for item in categories['multi_path_infrastructure']:
        fixes['remove_completely'].append({
            'pattern': item[0] + item[1],
            'reason': 'Multi-path infrastructure not yet implemented',
            'todo': 'TODO: Implement multi-path transmission when needed'
        })
    
    # Coordination tracking - likely used internally
    for item in categories['coordination_tracking']:
        fixes['make_pub_super'].append({
            'pattern': item[0] + item[1],
            'reason': 'Used for internal coordination tracking'
        })
    
    # Resource management - make pub(super) for Connection access
    for item in categories['resource_management']:
        fixes['make_pub_super'].append({
            'pattern': item[0] + item[1],
            'reason': 'Resource management accessed by Connection'
        })
    
    # Statistics - make pub(crate) for monitoring
    for item in categories['statistics']:
        fixes['make_pub_crate'].append({
            'pattern': item[0] + item[1],
            'reason': 'Statistics exposed for monitoring'
        })
    
    # Memory constrained - add feature flag
    for item in categories['memory_constrained']:
        fixes['add_feature_flag'].append({
            'pattern': item[0] + item[1],
            'feature': 'low_memory',
            'reason': 'Used in memory-constrained environments'
        })
    
    return fixes

if __name__ == '__main__':
    file_path = 'src/connection/nat_traversal.rs'
    
    print("Analyzing dead code in nat_traversal.rs...")
    categories = analyze_dead_code(file_path)
    
    print("\nCategorization summary:")
    for cat, items in categories.items():
        if items:
            print(f"  {cat}: {len(items)} items")
    
    print("\nGenerating fixes...")
    fixes = generate_fixes(categories)
    
    print("\nRecommended fixes:")
    for fix_type, items in fixes.items():
        if items:
            print(f"\n{fix_type}: {len(items)} items")
            for item in items[:3]:  # Show first 3 examples
                print(f"  - {item.get('reason', '')}")