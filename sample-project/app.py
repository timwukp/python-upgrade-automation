#!/usr/bin/env python3
"""
Sample Python application with legacy patterns that need upgrading
This simulates a typical Python 3.8 application that needs modernization
"""

import collections.abc  # Modern import for abstract base classes
import importlib.util  # Modern replacement for deprecated imp module
import json
import os
from typing import Dict, List

# Modern collections usage
def process_data(items: collections.abc.Iterable) -> Dict:
    """Process iterable data - uses modern collections.abc.Iterable"""
    result = {}
    for item in items:
        if isinstance(item, collections.abc.Mapping):
            result.update(item)
    return result

# Modern module loading using importlib
def load_config_module(config_path: str):
    """Load configuration module using modern importlib"""
    try:
        spec = importlib.util.spec_from_file_location("config", config_path)
        if spec and spec.loader:
            config_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(config_module)
            return config_module
    except Exception as e:
        print(f"Failed to load config: {e}")
    return None

# Modern string formatting with f-strings
def generate_report(user_name: str, score: int) -> str:
    """Generate user report with modern f-string formatting"""
    return f"User {user_name} has score {score}"

# Proper type hints and modern patterns
def calculate_average(numbers: List[float]) -> float:
    """Calculate average with proper type hints"""
    if not numbers:
        return 0.0
    return sum(numbers) / len(numbers)

# Modern dictionary checking
def check_config(config_dict: Dict, key: str) -> bool:
    """Check if config has key - modern style"""
    return key in config_dict  # Direct membership test - more efficient

# Modern exception handling
def safe_divide(a: float, b: float) -> float:
    """Safe division with modern exception handling"""
    try:
        result = a / b
    except ZeroDivisionError as e:  # Modern Python 3 syntax
        print(f"Division by zero error: {e}")
        return 0.0
    return result

# Main execution with modern patterns
def main() -> None:
    """Main function with proper structure"""
    # Test the modernized functions
    sample_data = [{'name': 'Alice', 'score': 95}, {'name': 'Bob', 'score': 87}]
    
    print("Processing sample data...")
    result = process_data(sample_data)
    print(f"Result: {json.dumps(result, indent=2)}")
    
    # Test configuration loading
    config_path = 'config.py'
    if os.path.exists(config_path):
        config = load_config_module(config_path)
        if config:
            print("Config loaded successfully")
    
    # Test report generation
    report = generate_report("John Doe", 92)
    print(report)
    
    # Test average calculation
    scores = [95.0, 87.0, 92.0, 78.0, 85.0]
    avg = calculate_average(scores)
    print(f"Average score: {avg:.2f}")

if __name__ == "__main__":
    main()