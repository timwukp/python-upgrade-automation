#!/usr/bin/env python3
"""
Sample Python application with legacy patterns that need upgrading
This simulates a typical Python 3.8 application that needs modernization
"""

import collections  # Legacy import - should use collections.abc for ABCs
import imp  # Deprecated in Python 3.4, removed in Python 3.12
import json
import os
from typing import Dict, List

# Legacy collections usage (deprecated)
def process_data(items: collections.Iterable) -> Dict:
    """Process iterable data - uses deprecated collections.Iterable"""
    result = {}
    for item in items:
        if isinstance(item, collections.Mapping):
            result.update(item)
    return result

# Using deprecated imp module
def load_config_module(config_path: str):
    """Load configuration module using deprecated imp"""
    try:
        return imp.load_source('config', config_path)
    except Exception as e:
        print(f"Failed to load config: {e}")
        return None

# Old-style string formatting (should use f-strings)
def generate_report(user_name: str, score: int) -> str:
    """Generate user report with old string formatting"""
    return "User %s has score %d" % (user_name, score)

# Missing type hints and using old patterns
def calculate_average(numbers):
    """Calculate average without proper type hints"""
    if not numbers:
        return 0
    return sum(numbers) / len(numbers)

# Using deprecated dict.has_key() pattern (Python 2 style)
def check_config(config_dict: Dict, key: str) -> bool:
    """Check if config has key - old style"""
    # This would be config_dict.has_key(key) in Python 2
    # Using 'in' operator is more modern
    if key in config_dict.keys():  # Inefficient - should just use 'in config_dict'
        return True
    return False

# Old exception handling pattern
def safe_divide(a: float, b: float) -> float:
    """Safe division with old exception handling"""
    try:
        result = a / b
    except ZeroDivisionError, e:  # Python 2 syntax - should use 'as'
        print("Division by zero error: %s" % str(e))
        return 0.0
    return result

# Main execution
if __name__ == "__main__":
    # Test the legacy functions
    sample_data = [{'name': 'Alice', 'score': 95}, {'name': 'Bob', 'score': 87}]
    
    print("Processing sample data...")
    result = process_data(sample_data)
    print("Result: %s" % json.dumps(result, indent=2))
    
    # Test configuration loading
    config = load_config_module('config.py')
    if config:
        print("Config loaded successfully")
    
    # Test report generation
    report = generate_report("John Doe", 92)
    print(report)
    
    # Test average calculation
    scores = [95, 87, 92, 78, 85]
    avg = calculate_average(scores)
    print("Average score: %.2f" % avg)