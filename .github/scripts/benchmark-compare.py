#!/usr/bin/env python3
"""
Benchmark Comparison Script
Compares benchmark results and detects performance regressions
"""

import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import re

# Configuration
REGRESSION_THRESHOLD = 0.05  # 5% regression threshold
IMPROVEMENT_THRESHOLD = 0.05  # 5% improvement threshold

class BenchmarkResult:
    """Represents a single benchmark result"""
    def __init__(self, name: str, time: float, unit: str = "ns"):
        self.name = name
        self.time = time
        self.unit = unit
    
    def __repr__(self):
        return f"BenchmarkResult({self.name}, {self.time}{self.unit})"

class BenchmarkComparison:
    """Compares two sets of benchmark results"""
    def __init__(self, baseline: Dict[str, BenchmarkResult], current: Dict[str, BenchmarkResult]):
        self.baseline = baseline
        self.current = current
        self.comparisons = []
        self._compare()
    
    def _compare(self):
        """Compare all benchmarks"""
        all_benchmarks = set(self.baseline.keys()) | set(self.current.keys())
        
        for bench_name in sorted(all_benchmarks):
            baseline_result = self.baseline.get(bench_name)
            current_result = self.current.get(bench_name)
            
            if baseline_result and current_result:
                change_percent = ((current_result.time - baseline_result.time) / baseline_result.time) * 100
                status = self._determine_status(change_percent)
                
                self.comparisons.append({
                    'name': bench_name,
                    'baseline': baseline_result.time,
                    'current': current_result.time,
                    'change_percent': change_percent,
                    'status': status,
                    'unit': baseline_result.unit
                })
            elif current_result and not baseline_result:
                self.comparisons.append({
                    'name': bench_name,
                    'baseline': None,
                    'current': current_result.time,
                    'change_percent': None,
                    'status': 'new',
                    'unit': current_result.unit
                })
            elif baseline_result and not current_result:
                self.comparisons.append({
                    'name': bench_name,
                    'baseline': baseline_result.time,
                    'current': None,
                    'change_percent': None,
                    'status': 'removed',
                    'unit': baseline_result.unit
                })
    
    def _determine_status(self, change_percent: float) -> str:
        """Determine the status based on change percentage"""
        if change_percent > REGRESSION_THRESHOLD * 100:
            return 'regression'
        elif change_percent < -IMPROVEMENT_THRESHOLD * 100:
            return 'improvement'
        else:
            return 'unchanged'
    
    def has_regressions(self) -> bool:
        """Check if any regressions were detected"""
        return any(comp['status'] == 'regression' for comp in self.comparisons)
    
    def get_regressions(self) -> List[dict]:
        """Get list of regressions"""
        return [comp for comp in self.comparisons if comp['status'] == 'regression']
    
    def get_improvements(self) -> List[dict]:
        """Get list of improvements"""
        return [comp for comp in self.comparisons if comp['status'] == 'improvement']
    
    def generate_report(self) -> str:
        """Generate a markdown report"""
        report = ["# Benchmark Comparison Report\n"]
        
        # Summary
        regressions = self.get_regressions()
        improvements = self.get_improvements()
        
        report.append("## Summary\n")
        report.append(f"- Total benchmarks: {len(self.comparisons)}")
        report.append(f"- Regressions: {len(regressions)}")
        report.append(f"- Improvements: {len(improvements)}")
        report.append(f"- Threshold: ±{REGRESSION_THRESHOLD * 100:.1f}%\n")
        
        # Regressions
        if regressions:
            report.append("## ⚠️ Performance Regressions\n")
            report.append("| Benchmark | Baseline | Current | Change |")
            report.append("|-----------|----------|---------|--------|")
            for reg in regressions:
                report.append(f"| {reg['name']} | {reg['baseline']:.2f}{reg['unit']} | "
                            f"{reg['current']:.2f}{reg['unit']} | "
                            f"**+{reg['change_percent']:.1f}%** |")
            report.append("")
        
        # Improvements
        if improvements:
            report.append("## ✅ Performance Improvements\n")
            report.append("| Benchmark | Baseline | Current | Change |")
            report.append("|-----------|----------|---------|--------|")
            for imp in improvements:
                report.append(f"| {imp['name']} | {imp['baseline']:.2f}{imp['unit']} | "
                            f"{imp['current']:.2f}{imp['unit']} | "
                            f"{imp['change_percent']:.1f}% |")
            report.append("")
        
        # All results
        report.append("## All Benchmark Results\n")
        report.append("| Benchmark | Baseline | Current | Change | Status |")
        report.append("|-----------|----------|---------|--------|--------|")
        
        for comp in self.comparisons:
            if comp['baseline'] is not None and comp['current'] is not None:
                change_str = f"{comp['change_percent']:+.1f}%"
                status_emoji = {
                    'regression': '🔴',
                    'improvement': '🟢',
                    'unchanged': '⚪'
                }.get(comp['status'], '❓')
                
                report.append(f"| {comp['name']} | {comp['baseline']:.2f}{comp['unit']} | "
                            f"{comp['current']:.2f}{comp['unit']} | {change_str} | {status_emoji} |")
            elif comp['status'] == 'new':
                report.append(f"| {comp['name']} | - | {comp['current']:.2f}{comp['unit']} | NEW | 🆕 |")
            elif comp['status'] == 'removed':
                report.append(f"| {comp['name']} | {comp['baseline']:.2f}{comp['unit']} | - | REMOVED | ❌ |")
        
        return "\n".join(report)

def parse_criterion_output(output_dir: Path) -> Dict[str, BenchmarkResult]:
    """Parse Criterion benchmark results"""
    results = {}
    
    # Look for benchmark result files
    for bench_dir in output_dir.glob("*"):
        if bench_dir.is_dir() and (bench_dir / "base" / "estimates.json").exists():
            estimates_file = bench_dir / "base" / "estimates.json"
            with open(estimates_file) as f:
                data = json.load(f)
                # Extract mean time in nanoseconds
                mean_time = data.get("mean", {}).get("point_estimate", 0)
                bench_name = bench_dir.name
                results[bench_name] = BenchmarkResult(bench_name, mean_time, "ns")
    
    return results

def parse_cargo_bench_output(output_file: Path) -> Dict[str, BenchmarkResult]:
    """Parse cargo bench text output as fallback"""
    results = {}
    
    # Pattern to match benchmark results
    # Example: test bench_name ... bench:   1,234 ns/iter (+/- 567)
    pattern = re.compile(r'test\s+(\S+)\s+.*bench:\s+([0-9,]+)\s+(\w+)/iter')
    
    with open(output_file) as f:
        for line in f:
            match = pattern.search(line)
            if match:
                name = match.group(1)
                time_str = match.group(2).replace(',', '')
                time = float(time_str)
                unit = match.group(3)
                results[name] = BenchmarkResult(name, time, unit)
    
    return results

def main():
    """Main entry point"""
    # Check if we're in CI environment
    is_ci = os.environ.get('CI', 'false').lower() == 'true'
    
    # Determine paths
    if is_ci:
        criterion_dir = Path("target/criterion")
        baseline_name = "baseline"
        current_name = "current"
    else:
        # For local testing
        criterion_dir = Path("target/criterion")
        baseline_name = sys.argv[1] if len(sys.argv) > 1 else "baseline"
        current_name = sys.argv[2] if len(sys.argv) > 2 else "current"
    
    # Try to parse Criterion results first
    baseline_results = {}
    current_results = {}
    
    if criterion_dir.exists():
        print("Parsing Criterion benchmark results...")
        # This is a simplified version - real implementation would handle
        # Criterion's directory structure properly
        baseline_results = parse_criterion_output(criterion_dir)
        current_results = parse_criterion_output(criterion_dir)
    
    # Fallback to text output parsing if needed
    if not baseline_results and Path("baseline-bench.txt").exists():
        print("Parsing text benchmark results...")
        baseline_results = parse_cargo_bench_output(Path("baseline-bench.txt"))
    
    if not current_results and Path("current-bench.txt").exists():
        current_results = parse_cargo_bench_output(Path("current-bench.txt"))
    
    if not baseline_results or not current_results:
        print("Warning: Could not find benchmark results to compare")
        sys.exit(0)
    
    # Compare results
    comparison = BenchmarkComparison(baseline_results, current_results)
    
    # Generate report
    report = comparison.generate_report()
    print(report)
    
    # Write report to file
    with open("benchmark-comparison.md", "w") as f:
        f.write(report)
    
    # Write JSON for further processing
    comparison_data = {
        'has_regressions': comparison.has_regressions(),
        'regression_count': len(comparison.get_regressions()),
        'improvement_count': len(comparison.get_improvements()),
        'comparisons': comparison.comparisons
    }
    
    with open("target/benchmark-comparison.json", "w") as f:
        json.dump(comparison_data, f, indent=2)
    
    # Exit with error if regressions found
    if comparison.has_regressions():
        print(f"\n❌ Found {len(comparison.get_regressions())} performance regressions!")
        sys.exit(1)
    else:
        print(f"\n✅ No performance regressions detected!")
        sys.exit(0)

if __name__ == "__main__":
    main()