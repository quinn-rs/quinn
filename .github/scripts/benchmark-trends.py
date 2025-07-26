#!/usr/bin/env python3
"""
Analyze benchmark trends over time and generate a report.
"""

import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple


def load_benchmark_history(directory: str) -> Dict[str, List[Tuple[datetime, float]]]:
    """Load all benchmark results from history directory."""
    history = defaultdict(list)
    
    for filename in sorted(os.listdir(directory)):
        if filename.startswith('results-') and filename.endswith('.json'):
            # Extract timestamp from filename: results-YYYYMMDD-HHMMSS-sha.json
            parts = filename.split('-')
            date_str = parts[1]
            time_str = parts[2]
            timestamp = datetime.strptime(f"{date_str}-{time_str}", "%Y%m%d-%H%M%S")
            
            filepath = os.path.join(directory, filename)
            with open(filepath, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        if entry.get('type') == 'benchmark-complete':
                            bench_id = entry['id']
                            mean = entry.get('mean', {}).get('point_estimate', 0)
                            history[bench_id].append((timestamp, mean))
                    except json.JSONDecodeError:
                        continue
    
    return history


def calculate_trend(values: List[float]) -> str:
    """Calculate trend direction from values."""
    if len(values) < 2:
        return "📊 STABLE"
    
    # Simple linear regression
    n = len(values)
    x = list(range(n))
    y = values
    
    x_mean = sum(x) / n
    y_mean = sum(y) / n
    
    numerator = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(n))
    denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
    
    if denominator == 0:
        return "📊 STABLE"
    
    slope = numerator / denominator
    
    # Calculate percentage change
    percent_change = (slope / y_mean) * 100
    
    if percent_change > 5:
        return "📈 DEGRADING"
    elif percent_change < -5:
        return "📉 IMPROVING"
    else:
        return "📊 STABLE"


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


def generate_trend_report(history: Dict[str, List[Tuple[datetime, float]]]) -> str:
    """Generate trend analysis report."""
    report = []
    report.append("## Benchmark Performance Trends\n")
    
    # Get date range
    all_dates = []
    for bench_history in history.values():
        all_dates.extend([date for date, _ in bench_history])
    
    if all_dates:
        min_date = min(all_dates)
        max_date = max(all_dates)
        report.append(f"**Period**: {min_date.strftime('%Y-%m-%d')} to {max_date.strftime('%Y-%m-%d')}\n")
    
    report.append("| Benchmark | Current | 7-day Avg | 30-day Avg | Trend |")
    report.append("|-----------|---------|-----------|------------|-------|")
    
    for bench_id in sorted(history.keys()):
        bench_history = sorted(history[bench_id], key=lambda x: x[0])
        
        if not bench_history:
            continue
        
        # Get current value
        current_time = bench_history[-1][1]
        
        # Calculate averages
        now = bench_history[-1][0]
        values_7d = [val for date, val in bench_history if (now - date).days <= 7]
        values_30d = [val for date, val in bench_history if (now - date).days <= 30]
        
        avg_7d = sum(values_7d) / len(values_7d) if values_7d else current_time
        avg_30d = sum(values_30d) / len(values_30d) if values_30d else current_time
        
        # Calculate trend
        recent_values = [val for _, val in bench_history[-10:]]
        trend = calculate_trend(recent_values)
        
        report.append(f"| {bench_id} | {format_time(current_time)} | {format_time(avg_7d)} | {format_time(avg_30d)} | {trend} |")
    
    # Notable changes section
    report.append("\n### Notable Changes\n")
    
    degrading = []
    improving = []
    
    for bench_id, bench_history in history.items():
        if len(bench_history) < 5:
            continue
        
        recent_values = [val for _, val in sorted(bench_history, key=lambda x: x[0])[-10:]]
        trend = calculate_trend(recent_values)
        
        if "DEGRADING" in trend:
            oldest = recent_values[0]
            newest = recent_values[-1]
            change = ((newest - oldest) / oldest) * 100
            degrading.append((bench_id, change))
        elif "IMPROVING" in trend:
            oldest = recent_values[0]
            newest = recent_values[-1]
            change = ((newest - oldest) / oldest) * 100
            improving.append((bench_id, change))
    
    if degrading:
        report.append("**⚠️ Performance Degradations:**")
        for bench, change in sorted(degrading, key=lambda x: x[1], reverse=True)[:5]:
            report.append(f"- {bench}: {change:+.1f}% slower over recent runs")
        report.append("")
    
    if improving:
        report.append("**✅ Performance Improvements:**")
        for bench, change in sorted(improving, key=lambda x: abs(x[1]), reverse=True)[:5]:
            report.append(f"- {bench}: {abs(change):.1f}% faster over recent runs")
    
    return '\n'.join(report)


def main():
    if len(sys.argv) != 2:
        print("Usage: benchmark-trends.py <benchmark-directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    
    try:
        history = load_benchmark_history(directory)
        report = generate_trend_report(history)
        print(report)
    except Exception as e:
        print(f"Error analyzing trends: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()