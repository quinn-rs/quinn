#!/usr/bin/env python3
"""
Analyze benchmark results from cargo-criterion and generate a markdown report.
"""

import json
import sys
from collections import defaultdict
from typing import Dict, List, Any


def parse_criterion_output(json_file: str) -> Dict[str, Any]:
    """Parse criterion JSON output."""
    benchmarks = defaultdict(dict)
    
    with open(json_file, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                if entry.get('type') == 'benchmark-complete':
                    bench_id = entry['id']
                    benchmarks[bench_id] = {
                        'mean': entry.get('mean', {}).get('point_estimate', 0),
                        'median': entry.get('median', {}).get('point_estimate', 0),
                        'std_dev': entry.get('std_dev', {}).get('point_estimate', 0),
                        'throughput': entry.get('throughput', None),
                    }
            except json.JSONDecodeError:
                continue
    
    return benchmarks


def format_time(nanoseconds: float) -> str:
    """Format time in appropriate units."""
    if nanoseconds < 1000:
        return f"{nanoseconds:.0f} ns"
    elif nanoseconds < 1_000_000:
        return f"{nanoseconds/1000:.1f} µs"
    elif nanoseconds < 1_000_000_000:
        return f"{nanoseconds/1_000_000:.1f} ms"
    else:
        return f"{nanoseconds/1_000_000_000:.2f} s"


def generate_report(benchmarks: Dict[str, Any]) -> str:
    """Generate markdown report from benchmark results."""
    report = []
    report.append("### Benchmark Results Summary\n")
    report.append("| Benchmark | Mean | Median | Std Dev |")
    report.append("|-----------|------|--------|---------|")
    
    # Group benchmarks by category
    categories = defaultdict(list)
    for bench_id, results in benchmarks.items():
        category = bench_id.split('/')[0] if '/' in bench_id else 'misc'
        categories[category].append((bench_id, results))
    
    # Sort and display by category
    for category, benches in sorted(categories.items()):
        if len(categories) > 1:
            report.append(f"| **{category}** | | | |")
        
        for bench_id, results in sorted(benches):
            bench_name = bench_id.split('/')[-1]
            mean = format_time(results['mean'])
            median = format_time(results['median'])
            std_dev = format_time(results['std_dev'])
            report.append(f"| {bench_name} | {mean} | {median} | {std_dev} |")
    
    # Add performance characteristics
    report.append("\n### Performance Characteristics\n")
    
    # Find fastest and slowest benchmarks
    sorted_benches = sorted(benchmarks.items(), key=lambda x: x[1]['mean'])
    if sorted_benches:
        fastest = sorted_benches[0]
        slowest = sorted_benches[-1]
        
        report.append(f"- **Fastest**: {fastest[0]} ({format_time(fastest[1]['mean'])})")
        report.append(f"- **Slowest**: {slowest[0]} ({format_time(slowest[1]['mean'])})")
    
    # Add notes
    report.append("\n### Notes\n")
    report.append("- All measurements are wall-clock time")
    report.append("- Results may vary based on system load and hardware")
    report.append("- Benchmarks run on Ubuntu latest with stable Rust")
    
    return '\n'.join(report)


def main():
    if len(sys.argv) != 2:
        print("Usage: analyze-benchmarks.py <benchmark-results.json>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    
    try:
        benchmarks = parse_criterion_output(json_file)
        report = generate_report(benchmarks)
        print(report)
    except Exception as e:
        print(f"Error analyzing benchmarks: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()