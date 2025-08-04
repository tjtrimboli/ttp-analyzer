"""
Enhanced Configuration Manager for TTP Analyzer
Supports performance modes and mode-specific overrides.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    """Enhanced configuration manager with performance mode support."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration with performance mode handling."""
        
        # Step 1: Start with Python defaults
        self.config = self._get_python_defaults()
        
        # Step 2: Load from YAML file
        yaml_config = self._load_yaml_config(config_path)
        if yaml_config:
            self.config.update(yaml_config)
            print(f"Loaded configuration from YAML file")
        else:
            print("No YAML config found, using defaults")
        
        # Step 3: Override with environment variables
        self._load_from_environment()
        
        # Step 4: Apply performance mode specific overrides
        self._apply_performance_mode_overrides()
        
        # Step 5: Create required directories
        self._create_directories()
        
        # Debug: Show final configuration
        print(f"Final configuration - Mode: {self.config.get('PERFORMANCE_MODE')}, "
              f"LOG_LEVEL: {self.config.get('LOG_LEVEL')}")
        
    def _get_python_defaults(self) -> Dict[str, Any]:
        """Get comprehensive default configuration values."""
        return {
            # Performance mode (NEW)
            'PERFORMANCE_MODE': 'balanced',
            
            # Directories
            'GROUPS_DIR': 'groups',
            'OUTPUT_DIR': 'output',
            'DATA_DIR': 'data',
            'LOG_DIR': 'logs',
            
            # Files
            'ATTACK_DATA_FILE': 'data/attack_data.json',
            'LOG_FILE': 'logs/ttp_analyzer.log',
            
            # Logging
            'LOG_LEVEL': 'INFO',
            'LOG_FORMAT': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            
            # HTTP Settings
            'REQUEST_TIMEOUT': 15,
            'RATE_LIMIT_DELAY': 0.5,
            'MAX_RETRIES': 2,
            'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            
            # TTP Extraction (base values - will be overridden by mode)
            'MIN_CONFIDENCE_THRESHOLD': 0.6,
            'ENABLE_HEURISTIC_EXTRACTION': True,
            'MAX_REPORT_SIZE_MB': 25,
            'MIN_CONTENT_LENGTH': 100,
            
            # Visualization
            'FIGURE_DPI': 150,
            'FIGURE_SIZE': [12, 8],
            'COLOR_PALETTE': 'husl',
            
            # Timeline Analysis
            'PHASE_WINDOW_DAYS': 30,
            'ACTIVITY_GAP_THRESHOLD_DAYS': 30,
            
            # Performance
            'MAX_CONCURRENT_REQUESTS': 3,
            'CACHE_REPORTS': False,
            'CACHE_DURATION_HOURS': 0,
            
            # Validation
            'VALIDATION_RULES': {
                'validate_technique_ids': True,
                'validate_dates': False,
                'validate_sources': False,
                'require_minimum_ttps': False
            },
            
            # Error Handling
            'ERROR_HANDLING': {
                'continue_on_parse_error': True,
                'max_consecutive_failures': 5,
                'retry_failed_reports': False,
                'fail_fast_on_critical_errors': False
            },
            
            # Experimental Features
            'EXPERIMENTAL': {
                'adaptive_confidence': True,
                'smart_content_filtering': True,
                'batch_processing': False,
                'performance_monitoring': True
            },
            
            # Performance Targets
            'PERFORMANCE_TARGETS': {
                'fast_max_total_analysis_time_seconds': 30.0,
                'balanced_max_total_analysis_time_seconds': 60.0,
                'comprehensive_max_total_analysis_time_seconds': 120.0
            },
            
            # Debug
            'DEBUG_MODE': False,
            'VERBOSE_TIMING': False,
            'PROFILE_ENABLED': False,
            
            # Migration
            'LEGACY_COMPATIBILITY': True,
            'WARN_ON_DEPRECATED_SETTINGS': True
        }
    
    def _load_yaml_config(self, config_path: Optional[str] = None) -> Optional[Dict]:
        """Load configuration from YAML file."""
        
        # Determine config file path
        if config_path:
            config_file = Path(config_path)
        else:
            # Look for config files in order of preference
            possible_configs = [
                Path('config.yaml'),     # New config (preferred)
                Path('config.yaml'),             # Original config
                Path('config.yml'),              # Alternative extension
                Path('ttp_config.yaml'),         # Alternative name
                Path('src/config.yaml')          # Fallback location
            ]
            
            config_file = None
            for candidate in possible_configs:
                if candidate.exists():
                    config_file = candidate
                    break
        
        if not config_file or not config_file.exists():
            print(f"No YAML config file found (looked for: {[str(p) for p in possible_configs if not config_path]})")
            return None
        
        try:
            print(f"Loading config from: {config_file}")
            
            with open(config_file, 'r', encoding='utf-8') as f:
                yaml_config = yaml.safe_load(f)
            
            if yaml_config:
                print(f"Loaded {len(yaml_config)} settings from YAML")
                return yaml_config
            else:
                print(f"YAML file is empty: {config_file}")
                return None
                
        except yaml.YAMLError as e:
            print(f"YAML parsing error in {config_file}: {e}")
            return None
        except Exception as e:
            print(f"Failed to load config from {config_file}: {e}")
            return None
    
    def _load_from_environment(self):
        """Load configuration from environment variables."""
        env_mapping = {
            # Core settings
            'TTP_PERFORMANCE_MODE': 'PERFORMANCE_MODE',
            'TTP_GROUPS_DIR': 'GROUPS_DIR',
            'TTP_OUTPUT_DIR': 'OUTPUT_DIR',
            'TTP_DATA_DIR': 'DATA_DIR',
            'TTP_LOG_DIR': 'LOG_DIR',
            'TTP_LOG_LEVEL': 'LOG_LEVEL',
            
            # HTTP settings
            'TTP_REQUEST_TIMEOUT': 'REQUEST_TIMEOUT',
            'TTP_RATE_LIMIT_DELAY': 'RATE_LIMIT_DELAY',
            'TTP_MAX_RETRIES': 'MAX_RETRIES',
            
            # Extraction settings
            'TTP_MIN_CONFIDENCE': 'MIN_CONFIDENCE_THRESHOLD',
            'TTP_ENABLE_HEURISTIC': 'ENABLE_HEURISTIC_EXTRACTION',
            'TTP_MAX_REPORT_SIZE': 'MAX_REPORT_SIZE_MB',
            'TTP_MIN_CONTENT_LENGTH': 'MIN_CONTENT_LENGTH',
            
            # Performance settings
            'TTP_FIGURE_DPI': 'FIGURE_DPI',
            'TTP_PHASE_WINDOW_DAYS': 'PHASE_WINDOW_DAYS',
            'TTP_ACTIVITY_GAP_DAYS': 'ACTIVITY_GAP_THRESHOLD_DAYS',
            'TTP_MAX_CONCURRENT': 'MAX_CONCURRENT_REQUESTS',
            'TTP_CACHE_REPORTS': 'CACHE_REPORTS',
            'TTP_CACHE_DURATION': 'CACHE_DURATION_HOURS'
        }
        
        env_overrides = 0
        
        for env_var, config_key in env_mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                # Convert to appropriate type
                if config_key in ['REQUEST_TIMEOUT', 'MAX_RETRIES', 'MAX_REPORT_SIZE_MB', 
                                 'FIGURE_DPI', 'PHASE_WINDOW_DAYS', 'ACTIVITY_GAP_THRESHOLD_DAYS',
                                 'MAX_CONCURRENT_REQUESTS', 'CACHE_DURATION_HOURS', 'MIN_CONTENT_LENGTH']:
                    try:
                        self.config[config_key] = int(value)
                        env_overrides += 1
                    except ValueError:
                        print(f"Invalid integer value for {env_var}: {value}")
                elif config_key in ['RATE_LIMIT_DELAY', 'MIN_CONFIDENCE_THRESHOLD']:
                    try:
                        self.config[config_key] = float(value)
                        env_overrides += 1
                    except ValueError:
                        print(f"Invalid float value for {env_var}: {value}")
                elif config_key in ['ENABLE_HEURISTIC_EXTRACTION', 'CACHE_REPORTS']:
                    self.config[config_key] = value.lower() in ('true', '1', 'yes', 'on')
                    env_overrides += 1
                else:
                    self.config[config_key] = value
                    env_overrides += 1
                    
                print(f"Environment override: {config_key} = {self.config[config_key]}")
        
        if env_overrides > 0:
            print(f"Applied {env_overrides} environment variable overrides")
    
    def _apply_performance_mode_overrides(self):
        """Apply performance mode specific configuration overrides."""
        performance_mode = self.config.get('PERFORMANCE_MODE', 'balanced').lower()
        
        # Define mode-specific overrides
        mode_overrides = {
            'fast': {
                'MIN_CONFIDENCE_THRESHOLD': 0.8,
                'MIN_CONTENT_LENGTH': 50,
                'REQUEST_TIMEOUT': 10,
                'ENABLE_HEURISTIC_EXTRACTION': False,
                'LOG_LEVEL': 'WARNING',
                'VALIDATION_RULES': {
                    'validate_technique_ids': True,
                    'validate_dates': False,
                    'validate_sources': False,
                    'require_minimum_ttps': False
                }
            },
            'balanced': {
                'MIN_CONFIDENCE_THRESHOLD': 0.6,
                'MIN_CONTENT_LENGTH': 100,
                'REQUEST_TIMEOUT': 15,
                'ENABLE_HEURISTIC_EXTRACTION': False,  # Disabled for speed
                'LOG_LEVEL': 'INFO',
                'VALIDATION_RULES': {
                    'validate_technique_ids': True,
                    'validate_dates': False,
                    'validate_sources': False,
                    'require_minimum_ttps': False
                }
            },
            'comprehensive': {
                'MIN_CONFIDENCE_THRESHOLD': 0.4,
                'MIN_CONTENT_LENGTH': 150,
                'REQUEST_TIMEOUT': 30,
                'ENABLE_HEURISTIC_EXTRACTION': True,
                'LOG_LEVEL': 'INFO',  # Keep INFO, not DEBUG by default
                'VALIDATION_RULES': {
                    'validate_technique_ids': True,
                    'validate_dates': True,
                    'validate_sources': True,
                    'require_minimum_ttps': False
                }
            }
        }
        
        # Check for YAML-defined overrides first
        yaml_override_key = f"{performance_mode.upper()}_MODE_OVERRIDES"
        yaml_overrides = self.config.get(yaml_override_key, {})
        
        # Get default overrides for the mode
        default_overrides = mode_overrides.get(performance_mode, {})
        
        # Combine YAML overrides with defaults (YAML takes precedence)
        combined_overrides = {**default_overrides, **yaml_overrides}
        
        if combined_overrides:
            print(f"Applying {performance_mode} mode overrides...")
            overrides_applied = 0
            
            for key, value in combined_overrides.items():
                old_value = self.config.get(key)
                self.config[key] = value
                overrides_applied += 1
                
                if old_value != value:
                    print(f"  {key}: {old_value} → {value}")
            
            print(f"Applied {overrides_applied} mode-specific overrides")
        
        # Ensure performance mode is set
        self.config['PERFORMANCE_MODE'] = performance_mode
    
    def _create_directories(self):
        """Create required directories if they don't exist."""
        directories = [
            self.config['GROUPS_DIR'],
            self.config['OUTPUT_DIR'],
            self.config['DATA_DIR'],
            self.config['LOG_DIR']
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
    
    def get_performance_mode(self) -> str:
        """Get the current performance mode."""
        return self.config.get('PERFORMANCE_MODE', 'balanced').lower()
    
    def is_mode(self, mode: str) -> bool:
        """Check if current mode matches the specified mode."""
        return self.get_performance_mode() == mode.lower()
    
    def get_mode_config(self, mode: str) -> Dict[str, Any]:
        """Get configuration for a specific performance mode."""
        # Create a temporary config with mode overrides applied
        temp_config = self.config.copy()
        
        # Apply mode-specific overrides
        yaml_override_key = f"{mode.upper()}_MODE_OVERRIDES"
        overrides = temp_config.get(yaml_override_key, {})
        
        temp_config.update(overrides)
        temp_config['PERFORMANCE_MODE'] = mode
        
        return temp_config
    
    def validate(self) -> bool:
        """Validate configuration values."""
        valid = True
        
        # Validate performance mode
        valid_modes = ['fast', 'balanced', 'comprehensive']
        if self.get_performance_mode() not in valid_modes:
            print(f"Invalid performance mode: {self.get_performance_mode()}. Must be one of: {valid_modes}")
            valid = False
        
        # Validate directories
        required_dirs = ['GROUPS_DIR', 'OUTPUT_DIR', 'DATA_DIR', 'LOG_DIR']
        for dir_key in required_dirs:
            if not self.get(dir_key):
                print(f"Required directory configuration missing: {dir_key}")
                valid = False
        
        # Validate numeric values
        numeric_validations = [
            ('REQUEST_TIMEOUT', (0, float('inf'))),
            ('RATE_LIMIT_DELAY', (0, float('inf'))),
            ('MIN_CONFIDENCE_THRESHOLD', (0, 1)),
            ('MAX_REPORT_SIZE_MB', (1, 1000)),
            ('MIN_CONTENT_LENGTH', (1, 10000))
        ]
        
        for key, (min_val, max_val) in numeric_validations:
            value = self.config[key]
            if not isinstance(value, (int, float)) or not (min_val <= value <= max_val):
                print(f"{key} must be a number between {min_val} and {max_val}")
                valid = False
        
        # Validate log level
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.config['LOG_LEVEL'].upper() not in valid_log_levels:
            print(f"LOG_LEVEL must be one of: {valid_log_levels}")
            valid = False
        
        return valid
    
    def get_performance_targets(self, mode: Optional[str] = None) -> Dict[str, float]:
        """Get performance targets for a specific mode."""
        if mode is None:
            mode = self.get_performance_mode()
        
        targets = self.config.get('PERFORMANCE_TARGETS', {})
        mode_targets = {}
        
        prefix = f"{mode}_"
        for key, value in targets.items():
            if key.startswith(prefix):
                clean_key = key[len(prefix):]
                mode_targets[clean_key] = value
        
        return mode_targets
    
    def print_mode_comparison(self):
        """Print a comparison of all performance modes."""
        print("\n" + "=" * 60)
        print("PERFORMANCE MODE COMPARISON")
        print("=" * 60)
        
        modes = ['fast', 'balanced', 'comprehensive']
        comparison_keys = [
            'MIN_CONFIDENCE_THRESHOLD',
            'MIN_CONTENT_LENGTH', 
            'ENABLE_HEURISTIC_EXTRACTION',
            'REQUEST_TIMEOUT'
        ]
        
        # Print header
        print(f"{'Setting':<30} {'Fast':<12} {'Balanced':<12} {'Comprehensive':<15}")
        print("-" * 72)
        
        # Print comparison
        for key in comparison_keys:
            values = []
            for mode in modes:
                mode_config = self.get_mode_config(mode)
                value = mode_config.get(key, 'N/A')
                values.append(str(value)[:11])  # Truncate for display
            
            print(f"{key:<30} {values[0]:<12} {values[1]:<12} {values[2]:<15}")
        
        # Print performance targets
        print("\nPerformance Targets:")
        for mode in modes:
            targets = self.get_performance_targets(mode)
            max_time = targets.get('max_total_analysis_time_seconds', 'N/A')
            print(f"  {mode.capitalize():<15} Max time: {max_time}s")
        
        print("=" * 60)
    
    def save_current_config(self, output_path: str):
        """Save current configuration to a YAML file."""
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Create a clean version of config for saving
            save_config = self.config.copy()
            
            # Add metadata
            save_config['_metadata'] = {
                'generated_by': 'TTP Analyzer',
                'performance_mode': self.get_performance_mode(),
                'timestamp': str(Path(output_path).stat().st_mtime if output_file.exists() else 'new')
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump(save_config, f, default_flow_style=False, indent=2)
                
            print(f"Configuration saved to: {output_file}")
                
        except Exception as e:
            print(f"Failed to save config to {output_path}: {e}")
    
    # Attribute access methods
    def __getattr__(self, name: str) -> Any:
        """Get configuration value by attribute name."""
        if name in self.config:
            return self.config[name]
        raise AttributeError(f"Configuration key '{name}' not found")
        
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with optional default."""
        return self.config.get(key, default)
        
    def set(self, key: str, value: Any):
        """Set configuration value."""
        self.config[key] = value
        
    def update(self, config_dict: Dict[str, Any]):
        """Update configuration with dictionary values."""
        self.config.update(config_dict)
        
    def to_dict(self) -> Dict[str, Any]:
        """Return configuration as dictionary."""
        return self.config.copy()
        
    def __str__(self) -> str:
        """String representation of configuration."""
        return f"TTPConfig(mode={self.get_performance_mode()}, {len(self.config)} settings)"
        
    def __repr__(self) -> str:
        """Detailed string representation."""
        return f"TTPConfig(mode={self.get_performance_mode()}, config={self.config})"
