#!/usr/bin/env python3
"""
Analyze performance trends from endpoint validation results.
"""

import json
import argparse
import os
from datetime import datetime
from typing import Dict, List, Any
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path


def load_results(file_path: str) -> Dict[str, Any]:
    """Load test results from JSON."""
    with open(file_path, 'r') as f:
        return json.load(f)


def load_historical_data(history_dir: str) -> List[Dict[str, Any]]:
    """Load historical test results."""
    history = []
    
    if os.path.exists(history_dir):
        for file in Path(history_dir).glob('*.json'):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    data['timestamp'] = file.stem  # Use filename as timestamp
                    history.append(data)
            except:
                continue
    
    return sorted(history, key=lambda x: x['timestamp'])


def generate_performance_plots(current: Dict[str, Any], 
                             history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate performance visualization plots."""
    plots = {}
    
    # Set style
    sns.set_theme(style="whitegrid")
    plt.rcParams['figure.figsize'] = (10, 6)
    
    # 1. Success rate over time
    if history:
        dates = [h['timestamp'] for h in history]
        success_rates = [h.get('summary', {}).get('success_rate', 0) for h in history]
        
        plt.figure()
        plt.plot(dates, success_rates, marker='o', linewidth=2, markersize=8)
        plt.axhline(y=80, color='r', linestyle='--', label='Threshold (80%)')
        plt.title('QUIC Endpoint Success Rate Over Time')
        plt.xlabel('Date')
        plt.ylabel('Success Rate (%)')
        plt.xticks(rotation=45)
        plt.legend()
        plt.tight_layout()
        plt.savefig('success_rate_trend.png', dpi=150)
        plots['success_rate_trend'] = 'success_rate_trend.png'
        plt.close()
    
    # 2. Handshake time by endpoint
    endpoints_data = current.get('endpoints', [])
    if endpoints_data:
        endpoint_names = []
        handshake_times = []
        
        for ep in endpoints_data:
            if ep.get('success') and 'metrics' in ep:
                name = ep['endpoint'].split(':')[0]
                time = ep['metrics'].get('handshake_time_ms', 0)
                if time > 0:
                    endpoint_names.append(name)
                    handshake_times.append(time)
        
        if endpoint_names:
            plt.figure()
            plt.barh(endpoint_names, handshake_times)
            plt.xlabel('Handshake Time (ms)')
            plt.title('QUIC Handshake Time by Endpoint')
            plt.tight_layout()
            plt.savefig('handshake_times.png', dpi=150)
            plots['handshake_times'] = 'handshake_times.png'
            plt.close()
    
    # 3. Protocol support distribution
    protocol_counts = {}
    for ep in endpoints_data:
        if ep.get('success'):
            for proto in ep.get('successful_protocols', []):
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
    
    if protocol_counts:
        plt.figure()
        plt.pie(protocol_counts.values(), labels=protocol_counts.keys(), autopct='%1.1f%%')
        plt.title('QUIC Protocol Support Distribution')
        plt.savefig('protocol_distribution.png', dpi=150)
        plots['protocol_distribution'] = 'protocol_distribution.png'
        plt.close()
    
    # 4. Regional performance (if available)
    regional_data = {}
    for ep in endpoints_data:
        if 'region' in ep and ep.get('success'):
            region = ep['region']
            if region not in regional_data:
                regional_data[region] = []
            if 'metrics' in ep:
                regional_data[region].append(ep['metrics'].get('rtt_ms', 0))
    
    if regional_data:
        plt.figure()
        regions = list(regional_data.keys())
        avg_rtts = [sum(rtts)/len(rtts) if rtts else 0 for rtts in regional_data.values()]
        
        plt.bar(regions, avg_rtts)
        plt.xlabel('Region')
        plt.ylabel('Average RTT (ms)')
        plt.title('Average RTT by Region')
        plt.tight_layout()
        plt.savefig('regional_performance.png', dpi=150)
        plots['regional_performance'] = 'regional_performance.png'
        plt.close()
    
    return plots


def generate_html_report(current: Dict[str, Any], 
                        history: List[Dict[str, Any]], 
                        plots: Dict[str, str]) -> str:
    """Generate HTML performance report."""
    summary = current.get('summary', {})
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>QUIC Endpoint Performance Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; }}
        .metric {{ display: inline-block; margin: 10px; padding: 10px; background: white; border-radius: 5px; }}
        .success {{ color: green; }}
        .warning {{ color: orange; }}
        .error {{ color: red; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        img {{ max-width: 100%; height: auto; margin: 10px 0; }}
        .plot-container {{ margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>QUIC Endpoint Performance Report</h1>
    <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <div class="metric">
            <strong>Success Rate:</strong> 
            <span class="{'success' if summary.get('success_rate', 0) >= 80 else 'warning'}">
                {summary.get('success_rate', 0):.1f}%
            </span>
        </div>
        <div class="metric">
            <strong>Endpoints Tested:</strong> {summary.get('total_endpoints', 0)}
        </div>
        <div class="metric">
            <strong>Successful:</strong> {summary.get('passed_endpoints', 0)}
        </div>
        <div class="metric">
            <strong>Avg Handshake Time:</strong> {summary.get('average_handshake_time', 0):.1f}ms
        </div>
    </div>
    
    <h2>Performance Trends</h2>
    """
    
    # Add plots
    for plot_name, plot_file in plots.items():
        html += f"""
    <div class="plot-container">
        <h3>{plot_name.replace('_', ' ').title()}</h3>
        <img src="{plot_file}" alt="{plot_name}">
    </div>
        """
    
    # Add endpoint details table
    html += """
    <h2>Endpoint Details</h2>
    <table>
        <tr>
            <th>Endpoint</th>
            <th>Status</th>
            <th>Protocols</th>
            <th>Handshake Time</th>
            <th>RTT</th>
            <th>Features</th>
        </tr>
    """
    
    for ep in current.get('endpoints', []):
        status_class = 'success' if ep.get('success') else 'error'
        status_text = '✅ Success' if ep.get('success') else '❌ Failed'
        
        protocols = ', '.join(ep.get('successful_protocols', []))
        handshake = ep.get('metrics', {}).get('handshake_time_ms', 'N/A')
        rtt = ep.get('metrics', {}).get('rtt_ms', 'N/A')
        features = ', '.join(ep.get('features_tested', []))
        
        html += f"""
        <tr>
            <td>{ep.get('endpoint', 'Unknown')}</td>
            <td class="{status_class}">{status_text}</td>
            <td>{protocols or 'None'}</td>
            <td>{handshake}ms</td>
            <td>{rtt}ms</td>
            <td>{features or 'N/A'}</td>
        </tr>
        """
    
    html += """
    </table>
    
    <h2>Historical Performance</h2>
    <p>Showing trends from the last {history_count} runs.</p>
    
</body>
</html>
    """.format(history_count=len(history))
    
    return html


def save_to_history(results: Dict[str, Any], history_dir: str):
    """Save current results to history."""
    os.makedirs(history_dir, exist_ok=True)
    
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    file_path = os.path.join(history_dir, f'{timestamp}.json')
    
    with open(file_path, 'w') as f:
        json.dump(results, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description='Analyze endpoint performance')
    parser.add_argument('--results', required=True, help='Path to test results JSON')
    parser.add_argument('--history', required=True, help='Path to history directory')
    parser.add_argument('--output', required=True, help='Path to output HTML report')
    
    args = parser.parse_args()
    
    # Load data
    current_results = load_results(args.results)
    historical_data = load_historical_data(args.history)
    
    # Save current to history
    save_to_history(current_results, args.history)
    
    # Generate plots
    plots = generate_performance_plots(current_results, historical_data)
    
    # Generate HTML report
    html_report = generate_html_report(current_results, historical_data, plots)
    
    # Save report
    with open(args.output, 'w') as f:
        f.write(html_report)
    
    print(f"Performance report generated: {args.output}")


if __name__ == '__main__':
    main()