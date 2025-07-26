#!/usr/bin/env python3
"""
Update endpoint status in the YAML configuration based on test results.
"""

import yaml
import json
import argparse
from datetime import datetime
from typing import Dict, List, Any


def load_yaml(file_path: str) -> Dict[str, Any]:
    """Load YAML configuration file."""
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)


def load_results(file_path: str) -> Dict[str, Any]:
    """Load test results from JSON."""
    with open(file_path, 'r') as f:
        return json.load(f)


def update_endpoint_status(config: Dict[str, Any], results: Dict[str, Any]) -> Dict[str, Any]:
    """Update endpoint status based on test results."""
    # Create a map of results by endpoint
    result_map = {r['endpoint']: r for r in results.get('endpoints', [])}
    
    # Update each endpoint
    for endpoint in config['endpoints']:
        key = f"{endpoint['host']}:{endpoint['port']}"
        
        if key in result_map:
            result = result_map[key]
            
            # Update status
            endpoint['last_tested'] = datetime.utcnow().isoformat() + 'Z'
            endpoint['last_status'] = 'success' if result['success'] else 'failed'
            
            # Update metrics if available
            if 'metrics' in result:
                if 'metrics' not in endpoint:
                    endpoint['metrics'] = {}
                
                endpoint['metrics'].update({
                    'handshake_time_ms': result['metrics'].get('handshake_time_ms'),
                    'rtt_ms': result['metrics'].get('rtt_ms'),
                    'success_rate': result['metrics'].get('success_rate', 0)
                })
            
            # Update supported protocols
            if 'protocols_tested' in result:
                endpoint['verified_protocols'] = result.get('successful_protocols', [])
            
            # Add failure reason if failed
            if not result['success'] and 'error' in result:
                endpoint['last_error'] = result['error']
            elif 'last_error' in endpoint:
                del endpoint['last_error']
    
    return config


def add_statistics(config: Dict[str, Any], results: Dict[str, Any]) -> Dict[str, Any]:
    """Add overall statistics to the configuration."""
    stats = results.get('summary', {})
    
    if 'statistics' not in config:
        config['statistics'] = {}
    
    config['statistics'].update({
        'last_run': datetime.utcnow().isoformat() + 'Z',
        'total_endpoints': stats.get('total_endpoints', 0),
        'successful_endpoints': stats.get('passed_endpoints', 0),
        'success_rate': stats.get('success_rate', 0),
        'average_handshake_time_ms': stats.get('average_handshake_time', 0),
        'protocols_seen': stats.get('protocols_seen', [])
    })
    
    return config


def main():
    parser = argparse.ArgumentParser(description='Update endpoint status from test results')
    parser.add_argument('--config', required=True, help='Path to endpoint configuration YAML')
    parser.add_argument('--results', required=True, help='Path to test results JSON')
    parser.add_argument('--output', required=True, help='Path to output updated YAML')
    
    args = parser.parse_args()
    
    # Load files
    config = load_yaml(args.config)
    results = load_results(args.results)
    
    # Update endpoint status
    config = update_endpoint_status(config, results)
    
    # Add statistics
    config = add_statistics(config, results)
    
    # Save updated configuration
    with open(args.output, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    
    print(f"Updated {len(config['endpoints'])} endpoints")
    print(f"Success rate: {config['statistics']['success_rate']}%")


if __name__ == '__main__':
    main()