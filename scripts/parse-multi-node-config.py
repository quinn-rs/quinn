#!/usr/bin/env python3
"""
Multi-Node Configuration Parser
Parses the YAML configuration file and extracts node information for the setup script.
"""

import yaml
import sys
import os

def parse_config(config_file):
    """Parse the YAML configuration file and extract node information."""
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f"Error parsing YAML: {e}", file=sys.stderr)
        sys.exit(1)

    # Check if there's an active_config specified
    active_config = config.get('active_config')
    if active_config and active_config in config:
        # Use the active configuration
        node_config = config[active_config]['nodes']
    else:
        # Use the main nodes configuration
        node_config = config['nodes']

    # Extract node information
    bootstrap_nodes = node_config.get('bootstrap', [])
    client_nodes = node_config.get('clients', [])
    nat_gateways = node_config.get('nat_gateways', [])

    return bootstrap_nodes, client_nodes, nat_gateways

def format_nodes_for_shell(nodes):
    """Format node list for shell script consumption."""
    if not nodes:
        return ""
    return ",".join(nodes)

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    config_file = os.path.join(project_root, "configs", "multi-node-test.yaml")

    bootstrap_nodes, client_nodes, nat_gateways = parse_config(config_file)

    # Output in format expected by shell script (only non-empty node types)
    if bootstrap_nodes:
        print(f"BOOTSTRAP_NODES={format_nodes_for_shell(bootstrap_nodes)}")
    if client_nodes:
        print(f"CLIENT_NODES={format_nodes_for_shell(client_nodes)}")
    if nat_gateways:
        print(f"NAT_GATEWAYS={format_nodes_for_shell(nat_gateways)}")

    # Validate that we have at least one bootstrap node
    if not bootstrap_nodes:
        print("Error: No bootstrap nodes configured", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()