"""
TTP Analyzer Configuration File
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    """Configuration manager with proper precedence handling."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration with proper loading order."""
        
        # Step 1: Start with Python defaults (lowest priority)
        self.config = self._get_python_defaults()
        
        # Step 2: Load from YAML file (higher priority)
        yaml_config = self._load_yaml_config(config_path)
        if yaml_config:
            self.config.update(yaml_config)
            print(f"Loaded configuration from YAML file")
        else:
            print("No YAML config found, using defaults")
        
        # Step 3: Override with environment variables (highest priority)
        self._load_from_environment()
        
        # Step 4: Create required directories
        self._create_directories()
        
        # Debug: Show final log level
        print(f"Final LOG_LEVEL: {self.config.get('LOG_LEVEL')}")
        
    def _get_python_defaults(self) -> Dict[str, Any]:
        """Get default configuration values from Python."""
        return {
            # Directories
            'GROUPS_DIR': 'groups',
            'OUTPUT_DIR': 'output',
            'DATA_DIR': 'data',
            'LOG_DIR': 'logs',
            
            # Files
            'ATTACK_DATA_FILE': 'data/attack_data.json',
            'LOG_FILE': 'logs/ttp_analyzer.log',
            
            # Logging (these should be overridden by YAML)
            'LOG_LEVEL': 'INFO',  # Default - should be overridden by YAML
            'LOG_FORMAT': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            
            # HTTP Settings
            'REQUEST_TIMEOUT': 30,
            'RATE_LIMIT_DELAY': 1.0,
            'MAX_RETRIES': 3,
            'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            
            # TTP Extraction
            'MIN_CONFIDENCE_THRESHOLD': 0.3,
            'ENABLE_HEURISTIC_EXTRACTION': True,
            'MAX_REPORT_SIZE_MB': 50,
            
            # Visualization
            'FIGURE_DPI': 300,
            'FIGURE_SIZE': (12, 8),
            'COLOR_PALETTE': 'husl',
            
            # Timeline Analysis
            'PHASE_WINDOW_DAYS': 30,
            'ACTIVITY_GAP_THRESHOLD_DAYS': 30,
            
            # Performance
            'MAX_CONCURRENT_REQUESTS': 5,
            'CACHE_REPORTS': True,
            'CACHE_DURATION_HOURS': 24
        }
    
    def _load_yaml_config(self, config_path: Optional[str] = None) -> Optional[Dict]:
        """Load configuration from YAML file with proper precedence."""
        
        # Determine config file path
        if config_path:
            config_file = Path(config_path)
        else:
            # Look for config files in order of preference
            possible_configs = [
                Path('config.yaml'),          # Project root (preferred)
                Path('config.yml'),           # Alternative extension
                Path('ttp_config.yaml'),      # Alternative name
                Path('src/config.yaml')       # Fallback location
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
                # Debug: Show what was loaded
                if 'LOG_LEVEL' in yaml_config:
                    print(f"YAML LOG_LEVEL: {yaml_config['LOG_LEVEL']}")
                
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
        """Load configuration from environment variables (highest priority)."""
        env_mapping = {
            'TTP_GROUPS_DIR': 'GROUPS_DIR',
            'TTP_OUTPUT_DIR': 'OUTPUT_DIR',
            'TTP_DATA_DIR': 'DATA_DIR',
            'TTP_LOG_DIR': 'LOG_DIR',
            'TTP_LOG_LEVEL': 'LOG_LEVEL',
            'TTP_REQUEST_TIMEOUT': 'REQUEST_TIMEOUT',
            'TTP_RATE_LIMIT_DELAY': 'RATE_LIMIT_DELAY',
            'TTP_MAX_RETRIES': 'MAX_RETRIES',
            'TTP_MIN_CONFIDENCE': 'MIN_CONFIDENCE_THRESHOLD',
            'TTP_ENABLE_HEURISTIC': 'ENABLE_HEURISTIC_EXTRACTION',
            'TTP_MAX_REPORT_SIZE': 'MAX_REPORT_SIZE_MB',
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
                                 'MAX_CONCURRENT_REQUESTS', 'CACHE_DURATION_HOURS']:
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
        
    def save_to_file(self, config_path: str):
        """Save current configuration to YAML file."""
        try:
            config_file = Path(config_path)
            config_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_file, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)
                
            print(f"Configuration saved to: {config_file}")
                
        except Exception as e:
            print(f"Failed to save config to {config_path}: {e}")
            
    def validate(self) -> bool:
        """Validate configuration values."""
        valid = True
        
        # Validate directories
        required_dirs = ['GROUPS_DIR', 'OUTPUT_DIR', 'DATA_DIR', 'LOG_DIR']
        for dir_key in required_dirs:
            if not self.get(dir_key):
                print(f"Required directory configuration missing: {dir_key}")
                valid = False
                
        # Validate numeric values
        if not isinstance(self.config['REQUEST_TIMEOUT'], (int, float)) or self.config['REQUEST_TIMEOUT'] <= 0:
            print("REQUEST_TIMEOUT must be a positive number")
            valid = False
            
        if not isinstance(self.config['RATE_LIMIT_DELAY'], (int, float)) or self.config['RATE_LIMIT_DELAY'] < 0:
            print("RATE_LIMIT_DELAY must be a non-negative number")
            valid = False
            
        if not isinstance(self.config['MIN_CONFIDENCE_THRESHOLD'], (int, float)) or not (0 <= self.config['MIN_CONFIDENCE_THRESHOLD'] <= 1):
            print("MIN_CONFIDENCE_THRESHOLD must be between 0 and 1")
            valid = False
            
        # Validate log level
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.config['LOG_LEVEL'].upper() not in valid_log_levels:
            print(f"LOG_LEVEL must be one of: {valid_log_levels}")
            valid = False
            
        return valid
    
    def debug_config_loading(self):
        """Debug configuration loading process."""
        print("\n🔍 Configuration Loading Debug:")
        print("=" * 40)
        
        # Check what files exist
        config_files = [
            Path('config.yaml'),
            Path('config.yml'), 
            Path('ttp_config.yaml'),
            Path('src/config.yaml')
        ]
        
        print("📁 Config file search:")
        for config_file in config_files:
            exists = "" if config_file.exists() else ""
            print(f"   {exists} {config_file}")
        
        # Show current values
        print(f"\nCurrent configuration:")
        print(f"   LOG_LEVEL: {self.config['LOG_LEVEL']}")
        print(f"   MIN_CONFIDENCE_THRESHOLD: {self.config['MIN_CONFIDENCE_THRESHOLD']}")
        print(f"   ENABLE_HEURISTIC_EXTRACTION: {self.config['ENABLE_HEURISTIC_EXTRACTION']}")
        
        # Show environment variables
        env_vars = [var for var in os.environ.keys() if var.startswith('TTP_')]
        if env_vars:
            print(f"\nEnvironment variables:")
            for var in env_vars:
                print(f"   {var} = {os.environ[var]}")
        else:
            print(f"\nNo TTP_* environment variables set")
        
        print("=" * 40)
        
    def __str__(self) -> str:
        """String representation of configuration."""
        return f"TTPAnalyzerConfig({len(self.config)} settings, LOG_LEVEL={self.config['LOG_LEVEL']})"
        
    def __repr__(self) -> str:
        """Detailed string representation."""
        return f"TTPAnalyzerConfig({self.config})"
