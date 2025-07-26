#!/usr/bin/env python3
"""
Compare benchmark results between baseline and current run.
"""

import json
import sys
from typing import Dict, Any, Tuple


def parse_criterion_output(json_file: str) -> Dict[str, Any]:
    """Parse criterion JSON output."""
    benchmarks = {}
    
    with open(json_file, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                if entry.get('type') == 'benchmark-complete':
                    bench_id = entry['id']
                    benchmarks[bench_id] = {
                        'mean': entry.get('mean', {}).get('point_estimate', 0),
                        'median': entry.get('median', {}).get('point_estimate', 0),
                    }
            except json.JSONDecodeError:
                continue
    
    return benchmarks


def calculate_change(baseline: float, current: float) -> Tuple[float, str]:
    """Calculate percentage change and determine status."""
    if baseline == 0:
        return 0, "🔵 NEW"
    
    change = ((current - baseline) / baseline) * 100
    
    if change > 10:
        status = "🔴 REGRESSION"
    elif change > 5:
        status = "🟡 SLOWER"
    elif change < -10:
        status = "🟢 IMPROVED"
    elif change < -5:
        status = "🟢 FASTER"
    else:
        status = "⚪ STABLE"
    
    return change, status


def format_time(nanoseconds: float) -> str:
    """Format time in appropriate units."""
    if nanoseconds < 1000:
        return f"{nanoseconds:.0f}ns"
    elif nanoseconds < 1_000_000:
        return f"{nanoseconds/1000:.1f}µs"
    elif nanoseconds < 1_000_000_000:
        return f"{nanoseconds/1_000_000:.1f}ms"
    else:
        return f"{nanoseconds/1_000_000_000:.2f}s"


def generate_comparison_report(baseline: Dict[str, Any], current: Dict[str, Any]) -> str:
    """Generate comparison report between baseline and current benchmarks."""
    report = []
    report.append("### Performance Comparison\n")
    
    # Check thresholds
    regression_threshold = 10  # 10% slower is a regression
    improvement_threshold = 10  # 10% faster is notable
    
    regressions = []
    improvements = []
    
    report.append("| Benchmark | Baseline | Current | Change | Status |")
    report.append("|-----------|----------|---------|--------|--------|")
    
    # Compare all benchmarks
    all_benches = set(baseline.keys()) | set(current.keys())
    
    for bench_id in sorted(all_benches):
        baseline_mean = baseline.get(bench_id, {}).get('mean', 0)
        current_mean = current.get(bench_id, {}).get('mean', 0)
        
        if bench_id not in baseline:
            report.append(f"| {bench_id} | - | {format_time(current_mean)} | NEW | 🔵 NEW |")
        elif bench_id not in current:
            report.append(f"| {bench_id} | {format_time(baseline_mean)} | - | REMOVED | ⚫ REMOVED |")
        else:
            change, status = calculate_change(baseline_mean, current_mean)
            
            if "REGRESSION" in status:
                regressions.append((bench_id, change))
            elif "IMPROVED" in status:
                improvements.append((bench_id, change))
            
            report.append(f"| {bench_id} | {format_time(baseline_mean)} | {format_time(current_mean)} | {change:+.1f}% | {status} |")
    
    # Summary section
    report.append("\n### Summary\n")
    
    if regressions:
        report.append(f"**⚠️ {len(regressions)} Performance Regressions Detected:**")
        for bench, change in regressions:
            report.append(f"- {bench}: {change:+.1f}% slower")
        report.append("")
    
    if improvements:
        report.append(f"**✅ {len(improvements)} Performance Improvements:**")
        for bench, change in improvements:
            report.append(f"- {bench}: {abs(change):.1f}% faster")
        report.append("")
    
    # Configuration
    report.append("### Configuration")
    report.append(f"- Regression threshold: >{regression_threshold}% slower")
    report.append(f"- Improvement threshold: >{improvement_threshold}% faster")
    report.append("- Measurements: Mean execution time")
    
    return '\n'.join(report)


def main():
    if len(sys.argv) != 3:
        print("Usage: compare-benchmarks.py <baseline.json> <current.json>")
        sys.exit(1)
    
    baseline_file = sys.argv[1]
    current_file = sys.argv[2]
    
    try:
        baseline = parse_criterion_output(baseline_file)
        current = parse_criterion_output(current_file)
        report = generate_comparison_report(baseline, current)
        print(report)
    except Exception as e:
        print(f"Error comparing benchmarks: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()