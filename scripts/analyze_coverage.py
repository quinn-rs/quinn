#!/usr/bin/env python3
"""
Coverage Analysis Tool for ant-quic

This script analyzes test coverage reports and provides:
- Detailed coverage statistics
- Identification of untested code
- Recommendations for improving coverage
- Priority ranking of files needing tests
"""

import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Tuple
import argparse

class CoverageAnalyzer:
    def __init__(self, coverage_file: str):
        self.coverage_file = coverage_file
        self.data = self._load_coverage()
        
    def _load_coverage(self) -> dict:
        """Load coverage data from JSON file"""
        with open(self.coverage_file, 'r') as f:
            return json.load(f)
    
    def get_overall_coverage(self) -> float:
        """Get overall project coverage percentage"""
        return self.data.get('coverage', 0.0)
    
    def get_files_by_coverage(self) -> List[Tuple[str, float, int, int]]:
        """Get files sorted by coverage percentage"""
        files = []
        for file_path, file_data in self.data.get('files', {}).items():
            coverage = file_data.get('coverage', 0.0)
            covered = file_data.get('covered_lines', 0)
            total = file_data.get('total_lines', 0)
            files.append((file_path, coverage, covered, total))
        
        return sorted(files, key=lambda x: x[1])
    
    def get_uncovered_files(self, threshold: float = 50.0) -> List[Tuple[str, float]]:
        """Get files with coverage below threshold"""
        return [(f, c) for f, c, _, _ in self.get_files_by_coverage() if c < threshold]
    
    def analyze_critical_files(self) -> List[Dict[str, any]]:
        """Identify critical files that need better coverage"""
        critical_patterns = [
            'src/connection',
            'src/endpoint',
            'src/nat_traversal',
            'src/frame',
            'src/transport',
            'src/crypto',
        ]
        
        critical_files = []
        for file_path, coverage, covered, total in self.get_files_by_coverage():
            # Check if file matches critical patterns
            is_critical = any(pattern in file_path for pattern in critical_patterns)
            
            if is_critical and coverage < 80:
                uncovered = total - covered
                priority = self._calculate_priority(file_path, coverage, uncovered)
                
                critical_files.append({
                    'file': file_path,
                    'coverage': coverage,
                    'uncovered_lines': uncovered,
                    'total_lines': total,
                    'priority': priority,
                    'reason': self._get_criticality_reason(file_path)
                })
        
        return sorted(critical_files, key=lambda x: x['priority'], reverse=True)
    
    def _calculate_priority(self, file_path: str, coverage: float, uncovered_lines: int) -> float:
        """Calculate priority score for improving coverage"""
        # Base score from lack of coverage
        base_score = (100 - coverage) / 100.0
        
        # Weight by file importance
        importance_weights = {
            'connection': 3.0,
            'endpoint': 3.0,
            'nat_traversal': 2.5,
            'frame': 2.0,
            'transport': 2.0,
            'crypto': 2.5,
            'quic_node': 2.0,
        }
        
        weight = 1.0
        for key, w in importance_weights.items():
            if key in file_path:
                weight = w
                break
        
        # Factor in number of uncovered lines
        lines_factor = min(uncovered_lines / 100.0, 1.0)
        
        return base_score * weight * (1 + lines_factor)
    
    def _get_criticality_reason(self, file_path: str) -> str:
        """Get reason why file is critical"""
        reasons = {
            'connection': 'Core QUIC connection handling',
            'endpoint': 'QUIC endpoint management',
            'nat_traversal': 'NAT traversal functionality',
            'frame': 'QUIC frame encoding/decoding',
            'transport': 'Transport layer implementation',
            'crypto': 'Cryptographic operations',
            'quic_node': 'High-level P2P node API',
        }
        
        for key, reason in reasons.items():
            if key in file_path:
                return reason
        
        return 'Core functionality'
    
    def generate_recommendations(self) -> List[str]:
        """Generate specific recommendations for improving coverage"""
        recommendations = []
        overall = self.get_overall_coverage()
        
        if overall < 80:
            recommendations.append(f"⚠️  Overall coverage ({overall:.1f}%) is below target (80%)")
        
        # Analyze critical files
        critical = self.analyze_critical_files()
        if critical:
            recommendations.append("\n📋 Priority files needing coverage:")
            for i, file_info in enumerate(critical[:5], 1):
                recommendations.append(
                    f"   {i}. {file_info['file']} ({file_info['coverage']:.1f}%)\n"
                    f"      - {file_info['reason']}\n"
                    f"      - {file_info['uncovered_lines']} lines need tests"
                )
        
        # Check for completely untested files
        untested = [f for f, c, _, _ in self.get_files_by_coverage() if c == 0]
        if untested:
            recommendations.append(f"\n❌ {len(untested)} files have 0% coverage")
        
        # Module-level analysis
        module_coverage = self._analyze_modules()
        low_modules = [(m, c) for m, c in module_coverage.items() if c < 70]
        if low_modules:
            recommendations.append("\n📦 Modules with low coverage:")
            for module, cov in sorted(low_modules, key=lambda x: x[1]):
                recommendations.append(f"   - {module}: {cov:.1f}%")
        
        return recommendations
    
    def _analyze_modules(self) -> Dict[str, float]:
        """Analyze coverage by module"""
        modules = {}
        
        for file_path, coverage, covered, total in self.get_files_by_coverage():
            # Extract module from path
            parts = file_path.split('/')
            if len(parts) > 2 and parts[0] == 'src':
                module = parts[1].replace('.rs', '')
                
                if module not in modules:
                    modules[module] = {'covered': 0, 'total': 0}
                
                modules[module]['covered'] += covered
                modules[module]['total'] += total
        
        # Calculate module percentages
        module_coverage = {}
        for module, stats in modules.items():
            if stats['total'] > 0:
                module_coverage[module] = (stats['covered'] / stats['total']) * 100
        
        return module_coverage
    
    def generate_report(self) -> str:
        """Generate comprehensive coverage report"""
        report = []
        
        # Header
        report.append("=" * 60)
        report.append("ant-quic Test Coverage Analysis")
        report.append("=" * 60)
        report.append("")
        
        # Overall coverage
        overall = self.get_overall_coverage()
        status = "✅" if overall >= 80 else "❌"
        report.append(f"Overall Coverage: {overall:.2f}% {status}")
        report.append("")
        
        # File statistics
        files = self.get_files_by_coverage()
        total_files = len(files)
        tested_files = len([f for f in files if f[1] > 0])
        well_tested = len([f for f in files if f[1] >= 80])
        
        report.append("File Statistics:")
        report.append(f"  Total files: {total_files}")
        report.append(f"  Files with tests: {tested_files} ({tested_files/total_files*100:.1f}%)")
        report.append(f"  Well-tested files (≥80%): {well_tested} ({well_tested/total_files*100:.1f}%)")
        report.append("")
        
        # Recommendations
        recommendations = self.generate_recommendations()
        if recommendations:
            report.append("Recommendations:")
            report.extend(recommendations)
            report.append("")
        
        # Test writing guide
        critical = self.analyze_critical_files()
        if critical:
            report.append("Test Writing Priority Guide:")
            report.append("-" * 40)
            for i, file_info in enumerate(critical[:3], 1):
                report.append(f"\n{i}. {file_info['file']}")
                report.append(f"   Current coverage: {file_info['coverage']:.1f}%")
                report.append(f"   Missing tests for: {file_info['uncovered_lines']} lines")
                report.append(f"   Suggested test focus:")
                report.extend(self._suggest_tests_for_file(file_info['file']))
        
        return "\n".join(report)
    
    def _suggest_tests_for_file(self, file_path: str) -> List[str]:
        """Suggest specific tests for a file"""
        suggestions = []
        
        # Pattern-based suggestions
        if 'nat_traversal' in file_path:
            suggestions.extend([
                "   - Test different NAT type combinations",
                "   - Test coordination timeout scenarios",
                "   - Test candidate discovery edge cases"
            ])
        elif 'connection' in file_path:
            suggestions.extend([
                "   - Test connection state transitions",
                "   - Test error handling paths",
                "   - Test concurrent operations"
            ])
        elif 'frame' in file_path:
            suggestions.extend([
                "   - Test frame encoding/decoding roundtrips",
                "   - Test malformed frame handling",
                "   - Test boundary conditions"
            ])
        elif 'crypto' in file_path:
            suggestions.extend([
                "   - Test key generation and validation",
                "   - Test signature verification",
                "   - Test error cases"
            ])
        else:
            suggestions.extend([
                "   - Test happy path scenarios",
                "   - Test error conditions",
                "   - Test edge cases"
            ])
        
        return suggestions

def main():
    parser = argparse.ArgumentParser(description='Analyze ant-quic test coverage')
    parser.add_argument('coverage_file', nargs='?', default='coverage/tarpaulin-report.json',
                        help='Path to coverage JSON file')
    parser.add_argument('--threshold', type=float, default=50.0,
                        help='Coverage threshold for identifying low-coverage files')
    parser.add_argument('--top', type=int, default=10,
                        help='Number of lowest-coverage files to show')
    parser.add_argument('--output', help='Output file for report')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.coverage_file):
        print(f"Error: Coverage file '{args.coverage_file}' not found")
        print("Run './scripts/coverage.sh' first to generate coverage data")
        sys.exit(1)
    
    analyzer = CoverageAnalyzer(args.coverage_file)
    report = analyzer.generate_report()
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to: {args.output}")
    else:
        print(report)
    
    # Exit with error if coverage is below 80%
    if analyzer.get_overall_coverage() < 80:
        sys.exit(1)

if __name__ == "__main__":
    main()