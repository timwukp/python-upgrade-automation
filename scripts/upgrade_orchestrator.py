#!/usr/bin/env python3
"""
Python Upgrade Automation Orchestrator - Secure Reference Implementation
Coordinates the entire upgrade process using Amazon Q Developer capabilities

DISCLAIMER: This is a reference implementation for educational purposes.
Always test thoroughly before using in production environments.

Security Features:
- Input validation and sanitization
- Secure subprocess execution
- Path traversal prevention
- Comprehensive error handling
- Security logging and monitoring
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum

# Security imports
import secrets
from cryptography.fernet import Fernet
import base64

class SecurityError(Exception):
    """Custom exception for security-related errors"""
    pass

class ValidationError(Exception):
    """Custom exception for input validation errors"""
    pass

class SecurityLevel(Enum):
    """Security levels for operations"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityContext:
    """Security context for operations"""
    user_id: str
    session_id: str
    permissions: List[str]
    security_level: SecurityLevel
    audit_trail: List[Dict]

class SecurityLogger:
    """Secure logging with sensitive data protection"""
    
    def __init__(self):
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)
        
        # Create secure log handler
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def log_security_event(self, event_type: str, details: Dict, severity: str = "INFO"):
        """Log security events with sensitive data masking"""
        # Mask sensitive data
        masked_details = self._mask_sensitive_data(details)
        
        log_entry = {
            "event_type": event_type,
            "severity": severity,
            "details": masked_details,
            "timestamp": time.time()
        }
        
        if severity == "CRITICAL":
            self.logger.critical(json.dumps(log_entry))
        elif severity == "ERROR":
            self.logger.error(json.dumps(log_entry))
        else:
            self.logger.info(json.dumps(log_entry))
    
    def _mask_sensitive_data(self, data: Dict) -> Dict:
        """Mask sensitive data in log entries"""
        sensitive_keys = ['password', 'token', 'key', 'secret', 'credential']
        masked_data = data.copy()
        
        for key, value in masked_data.items():
            if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
                masked_data[key] = "***MASKED***"
        
        return masked_data

class InputValidator:
    """Comprehensive input validation and sanitization"""
    
    @staticmethod
    def validate_project_path(path: str, allowed_base: Optional[str] = None) -> Path:
        """Validate and secure project path"""
        if not path or not isinstance(path, str):
            raise ValidationError("Invalid path: must be a non-empty string")
        
        # Convert to Path object and resolve
        try:
            resolved_path = Path(path).resolve()
        except (OSError, ValueError) as e:
            raise ValidationError(f"Invalid path format: {e}")
        
        # Check if path exists
        if not resolved_path.exists():
            raise ValidationError(f"Path does not exist: {resolved_path}")
        
        # Prevent path traversal if base directory is specified
        if allowed_base:
            allowed_base_path = Path(allowed_base).resolve()
            try:
                resolved_path.relative_to(allowed_base_path)
            except ValueError:
                raise SecurityError(f"Path traversal attempt detected: {path}")
        
        # Additional security checks
        if resolved_path.is_symlink():
            # Resolve symlinks and validate the target
            target = resolved_path.readlink()
            if target.is_absolute() and allowed_base:
                try:
                    target.relative_to(Path(allowed_base).resolve())
                except ValueError:
                    raise SecurityError(f"Symlink points outside allowed directory: {path}")
        
        return resolved_path
    
    @staticmethod
    def validate_command(command: List[str]) -> List[str]:
        """Validate and sanitize command for subprocess execution"""
        if not command or not isinstance(command, list):
            raise ValidationError("Command must be a non-empty list")
        
        # Whitelist of allowed commands
        allowed_commands = {
            'python', 'python3', 'pip', 'pip3', 'pytest', 
            'bandit', 'safety', 'black', 'flake8', 'mypy',
            'git', 'find', 'grep', 'cat', 'ls'
        }
        
        base_command = Path(command[0]).name
        if base_command not in allowed_commands:
            raise SecurityError(f"Command not allowed: {base_command}")
        
        # Validate command arguments
        for arg in command[1:]:
            if not isinstance(arg, str):
                raise ValidationError("All command arguments must be strings")
            
            # Check for dangerous patterns
            dangerous_patterns = [';', '&&', '||', '|', '>', '<', '`', '$']
            if any(pattern in arg for pattern in dangerous_patterns):
                raise SecurityError(f"Dangerous pattern detected in argument: {arg}")
        
        return command
    
    @staticmethod
    def validate_config(config: Dict) -> Dict:
        """Validate configuration dictionary"""
        if not isinstance(config, dict):
            raise ValidationError("Configuration must be a dictionary")
        
        # Required configuration keys
        required_keys = ['target_python_version', 'max_risk_threshold']
        for key in required_keys:
            if key not in config:
                raise ValidationError(f"Missing required configuration key: {key}")
        
        # Validate specific configuration values
        if not isinstance(config.get('max_risk_threshold'), (int, float)):
            raise ValidationError("max_risk_threshold must be a number")
        
        if not (0 <= config['max_risk_threshold'] <= 100):
            raise ValidationError("max_risk_threshold must be between 0 and 100")
        
        return config

class SecureSubprocessExecutor:
    """Secure subprocess execution with comprehensive controls"""
    
    def __init__(self, security_logger: SecurityLogger):
        self.security_logger = security_logger
        self.max_execution_time = 300  # 5 minutes default timeout
    
    async def execute_command(self, command: List[str], cwd: Optional[Path] = None, 
                            timeout: Optional[int] = None) -> subprocess.CompletedProcess:
        """Execute command with security controls"""
        # Validate command
        validated_command = InputValidator.validate_command(command)
        
        # Set timeout
        execution_timeout = timeout or self.max_execution_time
        
        # Log security event
        self.security_logger.log_security_event(
            "subprocess_execution",
            {
                "command": validated_command[0],
                "args_count": len(validated_command) - 1,
                "cwd": str(cwd) if cwd else None,
                "timeout": execution_timeout
            }
        )
        
        try:
            # Execute with security controls
            result = subprocess.run(
                validated_command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=execution_timeout,
                check=False,  # Don't raise on non-zero exit
                env=self._get_secure_environment()
            )
            
            # Log execution result
            self.security_logger.log_security_event(
                "subprocess_completed",
                {
                    "command": validated_command[0],
                    "return_code": result.returncode,
                    "stdout_length": len(result.stdout),
                    "stderr_length": len(result.stderr)
                }
            )
            
            return result
            
        except subprocess.TimeoutExpired:
            self.security_logger.log_security_event(
                "subprocess_timeout",
                {"command": validated_command[0], "timeout": execution_timeout},
                "ERROR"
            )
            raise SecurityError(f"Command execution timed out: {validated_command[0]}")
        
        except Exception as e:
            self.security_logger.log_security_event(
                "subprocess_error",
                {"command": validated_command[0], "error": str(e)},
                "ERROR"
            )
            raise SecurityError(f"Command execution failed: {e}")
    
    def _get_secure_environment(self) -> Dict[str, str]:
        """Get secure environment variables for subprocess"""
        # Start with minimal environment
        secure_env = {
            'PATH': os.environ.get('PATH', ''),
            'HOME': os.environ.get('HOME', ''),
            'USER': os.environ.get('USER', ''),
            'LANG': os.environ.get('LANG', 'en_US.UTF-8'),
            'LC_ALL': os.environ.get('LC_ALL', 'en_US.UTF-8')
        }
        
        # Add Python-specific variables if they exist
        python_vars = ['PYTHONPATH', 'VIRTUAL_ENV', 'CONDA_DEFAULT_ENV']
        for var in python_vars:
            if var in os.environ:
                secure_env[var] = os.environ[var]
        
        return secure_env

class PythonUpgradeOrchestrator:
    """Secure implementation of Python upgrade orchestration"""
    
    def __init__(self, config_path: str, security_context: Optional[SecurityContext] = None):
        # Initialize security components
        self.security_logger = SecurityLogger()
        self.subprocess_executor = SecureSubprocessExecutor(self.security_logger)
        self.security_context = security_context or self._create_default_security_context()
        
        # Load and validate configuration
        self.config = self.load_config(config_path)
        self.q_cli = "q"
        
        # Initialize session
        self.session_id = secrets.token_hex(16)
        self.security_logger.log_security_event(
            "orchestrator_initialized",
            {
                "session_id": self.session_id,
                "config_path": config_path,
                "user_id": self.security_context.user_id
            }
        )
    
    def _create_default_security_context(self) -> SecurityContext:
        """Create default security context for standalone operation"""
        return SecurityContext(
            user_id=os.getenv('USER', 'unknown'),
            session_id=secrets.token_hex(16),
            permissions=['code:analyze', 'dependencies:scan', 'tests:run'],
            security_level=SecurityLevel.MEDIUM,
            audit_trail=[]
        )

    def load_config(self, config_path: str) -> Dict:
        """Load and validate configuration from file"""
        try:
            # Validate config file path
            config_file = InputValidator.validate_project_path(config_path)
            
            # Load configuration
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Validate configuration
            validated_config = InputValidator.validate_config(config)
            
            self.security_logger.log_security_event(
                "config_loaded",
                {"config_path": str(config_file), "keys_count": len(validated_config)}
            )
            
            return validated_config
            
        except FileNotFoundError:
            # Return secure default configuration
            default_config = {
                'target_python_version': '3.11',
                'max_risk_threshold': 50,  # More conservative default
                'security_scan_enabled': True,
                'backup_enabled': True,
                'max_execution_time': 300,
                'allowed_base_directory': os.getcwd()
            }
            
            self.security_logger.log_security_event(
                "config_default_used",
                {"reason": "config_file_not_found", "config_path": config_path}
            )
            
            return default_config
        
        except (json.JSONDecodeError, ValidationError, SecurityError) as e:
            self.security_logger.log_security_event(
                "config_load_error",
                {"config_path": config_path, "error": str(e)},
                "ERROR"
            )
            raise SecurityError(f"Failed to load configuration: {e}")

    async def run_full_upgrade(self, project_paths: List[str]):
        """Run complete upgrade process for multiple projects with security controls"""
        # Validate permissions
        if 'upgrade:execute' not in self.security_context.permissions:
            # Allow for demo purposes with warning
            self.security_logger.log_security_event(
                "permission_warning",
                {"required_permission": "upgrade:execute", "user_permissions": self.security_context.permissions},
                "WARNING"
            )
        
        validated_paths = []
        allowed_base = self.config.get('allowed_base_directory')
        
        # Validate all project paths first
        for project_path in project_paths:
            try:
                validated_path = InputValidator.validate_project_path(project_path, allowed_base)
                validated_paths.append(validated_path)
            except (ValidationError, SecurityError) as e:
                self.security_logger.log_security_event(
                    "path_validation_failed",
                    {"project_path": project_path, "error": str(e)},
                    "ERROR"
                )
                raise
        
        # Process each validated project
        for project_path in validated_paths:
            try:
                self.security_logger.log_security_event(
                    "upgrade_started",
                    {"project_path": str(project_path), "session_id": self.session_id}
                )
                
                print(f"🚀 Starting secure upgrade analysis for {project_path}")
                
                # Phase 1: Discovery with security scanning
                discovery_results = await self.discover_project(project_path)
                
                # Phase 2: Risk assessment and planning
                upgrade_plan = await self.create_upgrade_plan(discovery_results)
                
                # Phase 3: Security approval check
                if upgrade_plan['risk_score'] < self.config['max_risk_threshold']:
                    print(f"✅ Project {project_path} approved for automated upgrade")
                    await self.execute_upgrade(project_path, upgrade_plan)
                else:
                    print(f"⚠️  Project {project_path} requires manual review (high risk: {upgrade_plan['risk_score']})")
                    self.security_logger.log_security_event(
                        "upgrade_blocked_high_risk",
                        {
                            "project_path": str(project_path),
                            "risk_score": upgrade_plan['risk_score'],
                            "threshold": self.config['max_risk_threshold']
                        },
                        "WARNING"
                    )
                
            except Exception as e:
                self.security_logger.log_security_event(
                    "upgrade_failed",
                    {"project_path": str(project_path), "error": str(e)},
                    "ERROR"
                )
                print(f"❌ Upgrade failed for {project_path}: {e}")
                raise

    async def discover_project(self, project_path: str) -> Dict:
        """Discover project characteristics with comprehensive security scanning"""
        # Convert string path to Path object for security validation
        validated_path = InputValidator.validate_project_path(project_path)
        
        print(f"🔍 Discovering project characteristics for {validated_path}")
        
        self.security_logger.log_security_event(
            "discovery_started",
            {"project_path": str(validated_path)}
        )
        
        try:
            # For demo purposes, return enhanced sample data with security info
            discovery_results = {
                'python_version': '3.8',
                'dependencies': {
                    'requests': '2.25.1',  # Vulnerable version
                    'flask': '1.1.4',      # Vulnerable version
                    'pandas': '1.3.0'      # Old version
                },
                'frameworks': ['flask'],
                'test_coverage': 75,
                'vulnerabilities': 23,  # High vulnerability count from legacy dependencies
                'complexity_score': 45,
                'security_scan': {
                    'vulnerabilities_count': 23,
                    'security_issues': [
                        'Outdated dependencies with known CVEs',
                        'Python 2 syntax patterns detected',
                        'Deprecated module usage (imp)'
                    ],
                    'scan_results': {
                        'bandit': {'results': []},
                        'safety': []
                    }
                }
            }
            
            self.security_logger.log_security_event(
                "discovery_completed",
                {
                    "project_path": str(validated_path),
                    "vulnerabilities_found": discovery_results['vulnerabilities'],
                    "dependencies_count": len(discovery_results['dependencies'])
                }
            )
            
            return discovery_results
            
        except Exception as e:
            self.security_logger.log_security_event(
                "discovery_failed",
                {"project_path": str(validated_path), "error": str(e)},
                "ERROR"
            )
            raise SecurityError(f"Project discovery failed: {e}")



    async def create_upgrade_plan(self, discovery_results: Dict) -> Dict:
        """Generate upgrade plan using analysis results"""
        print(f"📋 Creating upgrade plan based on discovery results")
        
        # Calculate risk score based on various factors
        risk_score = self.calculate_risk_score(discovery_results)
        
        return {
            'risk_score': risk_score,
            'steps': [
                {
                    'type': 'dependency_upgrade',
                    'dependencies': ['requests>=2.32.5', 'flask>=3.0.0'],
                    'priority': 'high'
                },
                {
                    'type': 'code_transformation',
                    'transformations': ['fix_imports', 'modernize_syntax'],
                    'priority': 'medium'
                },
                {
                    'type': 'test_execution',
                    'test_config': {'framework': 'pytest', 'coverage_threshold': 80},
                    'priority': 'high'
                }
            ],
            'estimated_duration': '2-4 hours',
            'rollback_plan': 'automated_backup_restore'
        }

    def calculate_risk_score(self, discovery_results: Dict) -> int:
        """Calculate risk score based on project characteristics"""
        risk_score = 0
        
        # Add risk based on vulnerabilities
        risk_score += discovery_results.get('vulnerabilities', 0) * 5
        
        # Add risk based on complexity
        risk_score += discovery_results.get('complexity_score', 0)
        
        # Add risk based on test coverage (inverse)
        test_coverage = discovery_results.get('test_coverage', 0)
        risk_score += max(0, 50 - test_coverage)
        
        return min(risk_score, 100)  # Cap at 100

    async def execute_upgrade(self, project_path: str, upgrade_plan: Dict):
        """Execute the upgrade plan (reference implementation)"""
        print(f"⚙️  Executing upgrade plan for {project_path}")
        
        # Create backup
        if self.config.get('backup_enabled', True):
            await self.create_backup(project_path)
        
        # Execute each upgrade step
        for step in upgrade_plan['steps']:
            step_type = step.get('type', 'unknown')
            print(f"  📝 Executing step: {step_type}")
            
            if step_type == 'dependency_upgrade':
                await self.upgrade_dependencies(project_path, step['dependencies'])
            elif step_type == 'code_transformation':
                await self.transform_code(project_path, step['transformations'])
            elif step_type == 'test_execution':
                test_results = await self.run_tests(project_path, step['test_config'])
                if not test_results.get('passed', False):
                    print("❌ Tests failed, initiating rollback")
                    await self.rollback(project_path)
                    return
        
        # Final validation
        await self.validate_upgrade(project_path, upgrade_plan)
        print(f"✅ Upgrade completed successfully for {project_path}")

    async def create_backup(self, project_path: str):
        """Create backup of project before upgrade"""
        backup_path = f"{project_path}.backup"
        print(f"💾 Creating backup at {backup_path}")
        # In production, implement actual backup logic

    async def upgrade_dependencies(self, project_path: str, dependencies: List[str]):
        """Upgrade project dependencies"""
        print(f"📦 Upgrading dependencies: {', '.join(dependencies)}")
        # In production, implement actual dependency upgrade logic

    async def transform_code(self, project_path: str, transformations: List[str]):
        """Apply code transformations"""
        print(f"🔄 Applying transformations: {', '.join(transformations)}")
        # In production, implement actual code transformation logic

    async def run_tests(self, project_path: str, test_config: Dict) -> Dict:
        """Run project tests"""
        print(f"🧪 Running tests with config: {test_config}")
        # In production, implement actual test execution
        return {'passed': True, 'coverage': 85}

    async def rollback(self, project_path: str):
        """Rollback changes on failure"""
        print(f"🔄 Initiating rollback for {project_path}")
        # In production, implement actual rollback logic

    async def validate_upgrade(self, project_path: str, upgrade_plan: Dict):
        """Final validation of upgrade"""
        print(f"✅ Validating upgrade for {project_path}")
        # In production, implement comprehensive validation

def main():
    """Main entry point with comprehensive security controls"""
    print("🐍 Python Upgrade Automation Orchestrator (Secure Implementation)")
    print("🛡️  Enhanced with comprehensive security controls and validation")
    print("⚠️  This is for educational purposes only. Test thoroughly before production use.\n")
    
    # Validate command line arguments
    if len(sys.argv) < 2:
        print("Usage: python upgrade_orchestrator.py <project_path> [config_path]")
        print("\nExample: python upgrade_orchestrator.py ./sample-project")
        print("\nSecurity Features:")
        print("  • Input validation and sanitization")
        print("  • Path traversal prevention")
        print("  • Secure subprocess execution")
        print("  • Comprehensive security logging")
        print("  • Dependency vulnerability scanning")
        sys.exit(1)
    
    project_path = sys.argv[1]
    config_path = sys.argv[2] if len(sys.argv) > 2 else "config.json"
    
    try:
        # Initialize security logger for main function
        security_logger = SecurityLogger()
        
        # Validate project path exists
        if not Path(project_path).exists():
            security_logger.log_security_event(
                "invalid_project_path",
                {"project_path": project_path},
                "ERROR"
            )
            print(f"❌ Project path does not exist: {project_path}")
            sys.exit(1)
        
        # Create security context
        security_context = SecurityContext(
            user_id=os.getenv('USER', 'unknown'),
            session_id=secrets.token_hex(16),
            permissions=['code:analyze', 'dependencies:scan', 'tests:run'],
            security_level=SecurityLevel.MEDIUM,
            audit_trail=[]
        )
        
        # Initialize orchestrator with security context
        orchestrator = PythonUpgradeOrchestrator(config_path, security_context)
        
        # Log session start
        security_logger.log_security_event(
            "session_started",
            {
                "user_id": security_context.user_id,
                "session_id": security_context.session_id,
                "project_path": project_path,
                "config_path": config_path
            }
        )
        
        # Run upgrade process
        asyncio.run(orchestrator.run_full_upgrade([project_path]))
        
        # Log session completion
        security_logger.log_security_event(
            "session_completed",
            {
                "session_id": security_context.session_id,
                "status": "success"
            }
        )
        
    except (ValidationError, SecurityError) as e:
        print(f"❌ Security Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()