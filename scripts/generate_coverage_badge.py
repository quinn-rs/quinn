#!/usr/bin/env python3
"""
Generate coverage badge SVG for ant-quic

This script creates an SVG badge showing the current test coverage percentage.
"""

import json
import sys
import os
from pathlib import Path

def get_color(percentage):
    """Get badge color based on coverage percentage"""
    if percentage >= 90:
        return "#4c1"  # bright green
    elif percentage >= 80:
        return "#97ca00"  # green
    elif percentage >= 70:
        return "#dfb317"  # yellow
    elif percentage >= 60:
        return "#fe7d37"  # orange
    else:
        return "#e05d44"  # red

def generate_badge(percentage, output_path="coverage/coverage-badge.svg"):
    """Generate SVG badge with coverage percentage"""
    color = get_color(percentage)
    percentage_str = f"{percentage:.1f}%"
    
    # SVG template
    svg_template = f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="114" height="20" role="img" aria-label="coverage: {percentage_str}">
    <title>coverage: {percentage_str}</title>
    <linearGradient id="s" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
        <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <clipPath id="r">
        <rect width="114" height="20" rx="3" fill="#fff"/>
    </clipPath>
    <g clip-path="url(#r)">
        <rect width="61" height="20" fill="#555"/>
        <rect x="61" width="53" height="20" fill="{color}"/>
        <rect width="114" height="20" fill="url(#s)"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
        <text aria-hidden="true" x="315" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="510">coverage</text>
        <text x="315" y="140" transform="scale(.1)" fill="#fff" textLength="510">coverage</text>
        <text aria-hidden="true" x="865" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="430">{percentage_str}</text>
        <text x="865" y="140" transform="scale(.1)" fill="#fff" textLength="430">{percentage_str}</text>
    </g>
</svg>'''
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Write SVG file
    with open(output_path, 'w') as f:
        f.write(svg_template)
    
    print(f"Badge generated: {output_path} ({percentage_str}, {color})")

def main():
    # Default paths
    coverage_file = "coverage/tarpaulin-report.json"
    output_path = "coverage/coverage-badge.svg"
    
    # Parse arguments
    if len(sys.argv) > 1:
        coverage_file = sys.argv[1]
    if len(sys.argv) > 2:
        output_path = sys.argv[2]
    
    # Check if coverage file exists
    if not os.path.exists(coverage_file):
        print(f"Error: Coverage file '{coverage_file}' not found")
        print("Run './scripts/coverage.sh' first to generate coverage data")
        sys.exit(1)
    
    # Load coverage data
    try:
        with open(coverage_file, 'r') as f:
            data = json.load(f)
        
        percentage = data.get('coverage', 0.0)
    except Exception as e:
        print(f"Error reading coverage file: {e}")
        sys.exit(1)
    
    # Generate badge
    generate_badge(percentage, output_path)
    
    # Also create a shields.io JSON endpoint file
    shields_data = {
        "schemaVersion": 1,
        "label": "coverage",
        "message": f"{percentage:.1f}%",
        "color": get_color(percentage).replace("#", "")
    }
    
    shields_path = output_path.replace(".svg", ".json")
    with open(shields_path, 'w') as f:
        json.dump(shields_data, f, indent=2)
    
    print(f"Shields.io JSON: {shields_path}")

if __name__ == "__main__":
    main()