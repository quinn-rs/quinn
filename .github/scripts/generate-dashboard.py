#!/usr/bin/env python3
"""
Generate a performance dashboard HTML page from benchmark history.
"""

import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple


def load_benchmark_history(directory: str) -> Dict[str, List[Tuple[str, float]]]:
    """Load all benchmark results from history directory."""
    history = defaultdict(list)
    
    for filename in sorted(os.listdir(directory)):
        if filename.startswith('results-') and filename.endswith('.json'):
            parts = filename.split('-')
            date_str = parts[1]
            time_str = parts[2]
            timestamp = f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:8]} {time_str[:2]}:{time_str[2:4]}"
            
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


def generate_dashboard_html(history: Dict[str, List[Tuple[str, float]]]) -> str:
    """Generate HTML dashboard with charts."""
    
    # Prepare data for charts
    chart_data = {}
    for bench_id, data in history.items():
        chart_data[bench_id] = {
            'labels': [d[0] for d in data[-30:]],  # Last 30 data points
            'data': [d[1] / 1_000_000 for d in data[-30:]]  # Convert to milliseconds
        }
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ant-quic Performance Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1 {{
            color: #333;
            text-align: center;
        }}
        .updated {{
            text-align: center;
            color: #666;
            margin-bottom: 30px;
        }}
        .chart-container {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .chart-title {{
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 10px;
            color: #333;
        }}
        canvas {{
            max-height: 300px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-title {{
            font-size: 14px;
            color: #666;
            margin-bottom: 5px;
        }}
        .summary-value {{
            font-size: 24px;
            font-weight: 600;
            color: #333;
        }}
        .improving {{ color: #10b981; }}
        .degrading {{ color: #ef4444; }}
        .stable {{ color: #6b7280; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 ant-quic Performance Dashboard</h1>
        <div class="updated">Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        
        <div class="summary">
            <div class="summary-card">
                <div class="summary-title">Total Benchmarks</div>
                <div class="summary-value">{len(history)}</div>
            </div>
            <div class="summary-card">
                <div class="summary-title">Data Points</div>
                <div class="summary-value">{sum(len(v) for v in history.values())}</div>
            </div>
            <div class="summary-card">
                <div class="summary-title">Latest Run</div>
                <div class="summary-value">{max(d[0] for v in history.values() for d in v) if history else 'N/A'}</div>
            </div>
        </div>
    """
    
    # Generate charts for each benchmark
    for i, (bench_id, data) in enumerate(sorted(chart_data.items())):
        html += f"""
        <div class="chart-container">
            <div class="chart-title">{bench_id}</div>
            <canvas id="chart{i}"></canvas>
        </div>
        """
    
    html += """
    </div>
    <script>
        const chartData = """ + json.dumps(chart_data) + """;
        
        let chartIndex = 0;
        for (const [benchId, data] of Object.entries(chartData).sort()) {
            const ctx = document.getElementById('chart' + chartIndex).getContext('2d');
            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: data.labels,
                    datasets: [{
                        label: 'Execution Time (ms)',
                        data: data.data,
                        borderColor: 'rgb(59, 130, 246)',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        tension: 0.1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        x: {
                            display: false
                        },
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Time (ms)'
                            }
                        }
                    }
                }
            });
            chartIndex++;
        }
    </script>
</body>
</html>"""
    
    return html


def main():
    if len(sys.argv) != 3:
        print("Usage: generate-dashboard.py <benchmark-directory> <output.html>")
        sys.exit(1)
    
    directory = sys.argv[1]
    output_file = sys.argv[2]
    
    try:
        history = load_benchmark_history(directory)
        html = generate_dashboard_html(history)
        
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            f.write(html)
        
        print(f"Dashboard generated: {output_file}")
    except Exception as e:
        print(f"Error generating dashboard: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()