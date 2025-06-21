"""
Configuration Management Module for TTP Analyzer.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    """Configuration manager for TTP Analyzer application."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration with default values and load from file if provided."""
        
        # Default configuration
        self.defaults = {
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
        
        # Load configuration from file if provided
        if config_path:
            self.load_from_file(config_path)
        else:
            # Look for default config files
            default_configs = ['config.yaml', 'config.yml', 'ttp_config.yaml']
            for config_file in default_configs:
                if Path(config_file).exists():
                    self.load_from_file(config_file)
                    break
        
        # Override with environment variables
        self.load_from_environment()
        
        # Ensure required directories exist
        self.create_directories()
        
    def load_from_file(self, config_path: str):
        """Load configuration from YAML file."""
        try:
            config_file = Path(config_path)
            if not config_file.exists():
                raise FileNotFoundError(f"Config file not found: {config_path}")
            
            with open(config_file, 'r', encoding='utf-8') as f:
                file_config = yaml.safe_load(f)
                
            if file_config:
                self.defaults.update(file_config)
                
        except Exception as e:
            logging.warning(f"Failed to load config from {config_path}: {e}")
            
    def load_from_environment(self):
        """Load configuration from environment variables."""
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
        
        for env_var, config_key in env_mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                # Convert to appropriate type
                if config_key in ['REQUEST_TIMEOUT', 'MAX_RETRIES', 'MAX_REPORT_SIZE_MB', 
                                 'FIGURE_DPI', 'PHASE_WINDOW_DAYS', 'ACTIVITY_GAP_THRESHOLD_DAYS',
                                 'MAX_CONCURRENT_REQUESTS', 'CACHE_DURATION_HOURS']:
                    try:
                        self.defaults[config_key] = int(value)
                    except ValueError:
                        logging.warning(f"Invalid integer value for {env_var}: {value}")
                elif config_key in ['RATE_LIMIT_DELAY', 'MIN_CONFIDENCE_THRESHOLD']:
                    try:
                        self.defaults[config_key] = float(value)
                    except ValueError:
                        logging.warning(f"Invalid float value for {env_var}: {value}")
                elif config_key in ['ENABLE_HEURISTIC_EXTRACTION', 'CACHE_REPORTS']:
                    self.defaults[config_key] = value.lower() in ('true', '1', 'yes', 'on')
                else:
                    self.defaults[config_key] = value
                    
    def create_directories(self):
        """Create required directories if they don't exist."""
        directories = [
            self.GROUPS_DIR,
            self.OUTPUT_DIR,
            self.DATA_DIR,
            self.LOG_DIR
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            
    def __getattr__(self, name: str) -> Any:
        """Get configuration value by attribute name."""
        if name in self.defaults:
            return self.defaults[name]
        raise AttributeError(f"Configuration key '{name}' not found")
        
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with optional default."""
        return self.defaults.get(key, default)
        
    def set(self, key: str, value: Any):
        """Set configuration value."""
        self.defaults[key] = value
        
    def update(self, config_dict: Dict[str, Any]):
        """Update configuration with dictionary values."""
        self.defaults.update(config_dict)
        
    def to_dict(self) -> Dict[str, Any]:
        """Return configuration as dictionary."""
        return self.defaults.copy()
        
    def save_to_file(self, config_path: str):
        """Save current configuration to YAML file."""
        try:
            config_file = Path(config_path)
            config_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_file, 'w', encoding='utf-8') as f:
                yaml.dump(self.defaults, f, default_flow_style=False, indent=2)
                
        except Exception as e:
            logging.error(f"Failed to save config to {config_path}: {e}")
            
    def validate(self) -> bool:
        """Validate configuration values."""
        valid = True
        
        # Validate directories
        required_dirs = ['GROUPS_DIR', 'OUTPUT_DIR', 'DATA_DIR', 'LOG_DIR']
        for dir_key in required_dirs:
            if not self.get(dir_key):
                logging.error(f"Required directory configuration missing: {dir_key}")
                valid = False
                
        # Validate numeric values
        if not isinstance(self.REQUEST_TIMEOUT, (int, float)) or self.REQUEST_TIMEOUT <= 0:
            logging.error("REQUEST_TIMEOUT must be a positive number")
            valid = False
            
        if not isinstance(self.RATE_LIMIT_DELAY, (int, float)) or self.RATE_LIMIT_DELAY < 0:
            logging.error("RATE_LIMIT_DELAY must be a non-negative number")
            valid = False
            
        if not isinstance(self.MIN_CONFIDENCE_THRESHOLD, (int, float)) or not (0 <= self.MIN_CONFIDENCE_THRESHOLD <= 1):
            logging.error("MIN_CONFIDENCE_THRESHOLD must be between 0 and 1")
            valid = False
            
        # Validate log level
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.LOG_LEVEL.upper() not in valid_log_levels:
            logging.error(f"LOG_LEVEL must be one of: {valid_log_levels}")
            valid = False
            
        return valid
        
    def __str__(self) -> str:
        """String representation of configuration."""
        return f"TTPAnalyzerConfig({len(self.defaults)} settings)"
        
    def __repr__(self) -> str:
        """Detailed string representation."""
        return f"TTPAnalyzerConfig({self.defaults})"
