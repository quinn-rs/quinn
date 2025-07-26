#!/usr/bin/env python3
"""
ant-quic Interoperability Test Script

This script tests ant-quic against various QUIC implementations
and validates protocol compliance.
"""

import subprocess
import json
import time
import sys
import argparse
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# Test endpoints
TEST_ENDPOINTS = {
    "ant-quic": {
        "url": "quic.saorsalabs.com:9000",
        "supports_nat": True,
        "supports_0rtt": True,
    },
    "cloudflare": {
        "url": "quic.cloudflare.com:443",
        "supports_nat": False,
        "supports_0rtt": True,
    },
    "google": {
        "url": "quic.google.com:443",
        "supports_nat": False,
        "supports_0rtt": True,
    },
    "facebook": {
        "url": "facebook.com:443",
        "supports_nat": False,
        "supports_0rtt": True,
    },
}

class QuicTester:
    def __init__(self, client_path: str = "ant-quic"):
        self.client_path = client_path
        self.results = []

    def test_basic_connectivity(self, endpoint: str) -> Tuple[bool, float, str]:
        """Test basic QUIC connectivity"""
        start_time = time.time()

        try:
            result = subprocess.run(
                [self.client_path, "--connect", endpoint, "--timeout", "10"],
                capture_output=True,
                text=True,
                timeout=15
            )

            duration = time.time() - start_time

            if result.returncode == 0:
                return True, duration, "Connected successfully"
            else:
                return False, duration, f"Connection failed: {result.stderr}"

        except subprocess.TimeoutExpired:
            return False, 15.0, "Connection timeout"
        except Exception as e:
            return False, 0.0, f"Error: {str(e)}"

    def test_0rtt(self, endpoint: str) -> Tuple[bool, str]:
        """Test 0-RTT support"""
        # First connection to get session ticket
        try:
            result1 = subprocess.run(
                [self.client_path, "--connect", endpoint, "--save-session", "/tmp/session.ticket"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result1.returncode != 0:
                return False, "Failed to establish initial connection"

            # Second connection with 0-RTT
            result2 = subprocess.run(
                [self.client_path, "--connect", endpoint, "--session", "/tmp/session.ticket", "--enable-0rtt"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result2.returncode == 0 and "0-RTT accepted" in result2.stdout:
                return True, "0-RTT successful"
            else:
                return False, "0-RTT not accepted or failed"

        except Exception as e:
            return False, f"Error: {str(e)}"

    def test_nat_traversal(self, endpoint: str) -> Tuple[bool, Dict[str, any]]:
        """Test NAT traversal capabilities"""
        try:
            result = subprocess.run(
                [self.client_path, "--connect", endpoint, "--enable-nat-traversal", "--json-output"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                try:
                    output = json.loads(result.stdout)
                    return True, {
                        "connection_type": output.get("connection_type", "unknown"),
                        "nat_type": output.get("nat_type", "unknown"),
                        "candidates_tried": output.get("candidates_tried", 0),
                        "hole_punching_used": output.get("hole_punching_used", False),
                        "relay_used": output.get("relay_used", False),
                    }
                except json.JSONDecodeError:
                    return True, {"error": "Invalid JSON output"}
            else:
                return False, {"error": result.stderr}

        except Exception as e:
            return False, {"error": str(e)}

    def test_performance(self, endpoint: str, size_mb: int = 10) -> Tuple[bool, Dict[str, float]]:
        """Test throughput and latency"""
        try:
            # Throughput test
            result = subprocess.run(
                [self.client_path, "--connect", endpoint, "--download-test", str(size_mb)],
                capture_output=True,
                text=True,
                timeout=60
            )

            metrics = {
                "throughput_mbps": 0.0,
                "latency_ms": 0.0,
                "jitter_ms": 0.0,
                "packet_loss": 0.0,
            }

            if result.returncode == 0:
                # Parse output for metrics
                for line in result.stdout.split('\n'):
                    if "Throughput:" in line:
                        metrics["throughput_mbps"] = float(line.split()[-2])
                    elif "RTT:" in line:
                        metrics["latency_ms"] = float(line.split()[-2])
                    elif "Jitter:" in line:
                        metrics["jitter_ms"] = float(line.split()[-2])
                    elif "Loss:" in line:
                        metrics["packet_loss"] = float(line.split()[-1].rstrip('%'))

                return True, metrics
            else:
                return False, metrics

        except Exception as e:
            return False, {"error": str(e)}

    def test_migration(self, endpoint: str) -> Tuple[bool, str]:
        """Test connection migration"""
        try:
            result = subprocess.run(
                [self.client_path, "--connect", endpoint, "--test-migration"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0 and "Migration successful" in result.stdout:
                return True, "Connection migration successful"
            else:
                return False, "Migration failed or not supported"

        except Exception as e:
            return False, f"Error: {str(e)}"

    def run_all_tests(self, endpoint_name: str, endpoint_info: Dict) -> Dict:
        """Run all tests against an endpoint"""
        print(f"\n{'='*60}")
        print(f"Testing: {endpoint_name} ({endpoint_info['url']})")
        print(f"{'='*60}")

        results = {
            "endpoint": endpoint_name,
            "url": endpoint_info["url"],
            "timestamp": datetime.now().isoformat(),
            "tests": {}
        }

        # Basic connectivity
        print("1. Testing basic connectivity...", end=" ", flush=True)
        success, duration, message = self.test_basic_connectivity(endpoint_info["url"])
        results["tests"]["connectivity"] = {
            "success": success,
            "duration": duration,
            "message": message
        }
        print("✓" if success else "✗")

        if not success:
            print(f"   Failed: {message}")
            return results

        # 0-RTT test
        if endpoint_info.get("supports_0rtt", False):
            print("2. Testing 0-RTT...", end=" ", flush=True)
            success, message = self.test_0rtt(endpoint_info["url"])
            results["tests"]["0rtt"] = {
                "success": success,
                "message": message
            }
            print("✓" if success else "✗")

        # NAT traversal test
        if endpoint_info.get("supports_nat", False):
            print("3. Testing NAT traversal...", end=" ", flush=True)
            success, nat_info = self.test_nat_traversal(endpoint_info["url"])
            results["tests"]["nat_traversal"] = {
                "success": success,
                "details": nat_info
            }
            print("✓" if success else "✗")
            if success:
                print(f"   Connection type: {nat_info.get('connection_type', 'unknown')}")
                print(f"   NAT type: {nat_info.get('nat_type', 'unknown')}")

        # Performance test
        print("4. Testing performance...", end=" ", flush=True)
        success, metrics = self.test_performance(endpoint_info["url"])
        results["tests"]["performance"] = {
            "success": success,
            "metrics": metrics
        }
        print("✓" if success else "✗")
        if success:
            print(f"   Throughput: {metrics.get('throughput_mbps', 0):.2f} Mbps")
            print(f"   Latency: {metrics.get('latency_ms', 0):.2f} ms")

        # Migration test
        print("5. Testing connection migration...", end=" ", flush=True)
        success, message = self.test_migration(endpoint_info["url"])
        results["tests"]["migration"] = {
            "success": success,
            "message": message
        }
        print("✓" if success else "✗")

        return results

def main():
    parser = argparse.ArgumentParser(description="ant-quic interoperability tester")
    parser.add_argument("--client", default="ant-quic", help="Path to ant-quic client")
    parser.add_argument("--endpoint", help="Test specific endpoint")
    parser.add_argument("--output", help="Output file for results (JSON)")
    parser.add_argument("--all", action="store_true", help="Test all endpoints")

    args = parser.parse_args()

    tester = QuicTester(args.client)
    all_results = []

    if args.all:
        # Test all endpoints
        for name, info in TEST_ENDPOINTS.items():
            results = tester.run_all_tests(name, info)
            all_results.append(results)
    elif args.endpoint:
        # Test specific endpoint
        if args.endpoint in TEST_ENDPOINTS:
            results = tester.run_all_tests(args.endpoint, TEST_ENDPOINTS[args.endpoint])
            all_results.append(results)
        else:
            # Custom endpoint
            results = tester.run_all_tests("custom", {"url": args.endpoint})
            all_results.append(results)
    else:
        # Test default ant-quic endpoint
        results = tester.run_all_tests("ant-quic", TEST_ENDPOINTS["ant-quic"])
        all_results.append(results)

    # Generate summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")

    total_tests = 0
    passed_tests = 0

    for result in all_results:
        endpoint_passed = 0
        endpoint_total = 0

        for test_name, test_result in result["tests"].items():
            endpoint_total += 1
            total_tests += 1
            if test_result.get("success", False):
                endpoint_passed += 1
                passed_tests += 1

        print(f"{result['endpoint']}: {endpoint_passed}/{endpoint_total} tests passed")

    print(f"\nOverall: {passed_tests}/{total_tests} tests passed ({passed_tests/total_tests*100:.1f}%)")

    # Save results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                "test_run": datetime.now().isoformat(),
                "client": args.client,
                "results": all_results
            }, f, indent=2)
        print(f"\nResults saved to: {args.output}")

if __name__ == "__main__":
    main()
