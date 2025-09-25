#!/usr/bin/env python3
"""
Modernized Python application - upgraded from legacy patterns
This demonstrates the results of automated Python code modernization
"""

import collections.abc  # Modern import for abstract base classes
import importlib.util  # Modern replacement for deprecated imp module
import json
import os
from typing import Dict, List, Union, Iterable, Mapping, Optional

# Modern collections usage
def process_data(items: Iterable[Dict]) -> Dict:
    """Process iterable data - uses modern collections.abc.Iterable"""
    result = {}
    for item in items:
        if isinstance(item, Mapping):
            result.update(item)
    return result

# Modern module loading using importlib
def load_config_module(config_path: str) -> Optional[object]:
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
def calculate_average(numbers: List[Union[int, float]]) -> float:
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

# Additional modern improvements
def process_user_data(users: List[Dict[str, Union[str, int]]]) -> Dict[str, float]:
    """Process user data with comprehensive type hints and modern patterns"""
    results = {}
    
    for user in users:
        name = user.get('name', 'Unknown')
        score = user.get('score', 0)
        
        # Modern string formatting and type checking
        if isinstance(score, (int, float)) and score > 0:
            results[name] = float(score)
        else:
            print(f"Invalid score for user {name}: {score}")
    
    return results

def calculate_statistics(scores: List[float]) -> Dict[str, float]:
    """Calculate comprehensive statistics"""
    if not scores:
        return {'count': 0, 'average': 0.0, 'min': 0.0, 'max': 0.0}
    
    return {
        'count': len(scores),
        'average': sum(scores) / len(scores),
        'min': min(scores),
        'max': max(scores)
    }

# Main execution with modern patterns
def main() -> None:
    """Main function with proper structure"""
    # Test data
    sample_data = [
        {'name': 'Alice', 'score': 95},
        {'name': 'Bob', 'score': 87},
        {'name': 'Charlie', 'score': 92}
    ]
    
    print("Processing sample data...")
    result = process_data(sample_data)
    print(f"Result: {json.dumps(result, indent=2)}")
    
    # Test modern user data processing
    user_results = process_user_data(sample_data)
    print(f"User results: {user_results}")
    
    # Test statistics calculation
    scores = list(user_results.values())
    stats = calculate_statistics(scores)
    print(f"Statistics: {json.dumps(stats, indent=2)}")
    
    # Test configuration loading (if config file exists)
    config_path = 'config.py'
    if os.path.exists(config_path):
        config = load_config_module(config_path)
        if config:
            print("Config loaded successfully")
    
    # Test report generation
    for name, score in user_results.items():
        report = generate_report(name, int(score))
        print(report)
    
    # Test safe division
    division_result = safe_divide(10.0, 2.0)
    print(f"Division result: {division_result}")
    
    # Test division by zero handling
    zero_division = safe_divide(10.0, 0.0)
    print(f"Zero division result: {zero_division}")

if __name__ == "__main__":
    main()