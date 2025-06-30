#!/usr/bin/env python3
"""
Installation Test Script for TTP Analyzer
Run this script to validate that all components are working correctly.
"""

import sys
import os
import logging
from pathlib import Path

def test_imports():
    """Test that all required modules can be imported."""
    print("Testing imports...")
    
    try:
        # Test core dependencies
        import requests
        import yaml
        import json
        import pandas as pd
        import numpy as np
        import matplotlib.pyplot as plt
        import seaborn as sns
        print("✓ Core dependencies imported successfully")
        
        # Test optional dependencies
        try:
            import PyPDF2
            print("✓ PyPDF2 available for PDF parsing")
        except ImportError:
            print("⚠ PyPDF2 not available - PDF parsing will be disabled")
            
        try:
            from bs4 import BeautifulSoup
            print("✓ BeautifulSoup available for HTML parsing")
        except ImportError:
            print("⚠ BeautifulSoup not available - HTML parsing will be limited")
            
        return True
        
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

def test_module_imports():
    """Test that TTP Analyzer modules can be imported."""
    print("\nTesting TTP Analyzer modules...")
    
    try:
        # Add src directory to path if running from project root
        src_path = Path(__file__).parent / "src"
        if src_path.exists():
            sys.path.insert(0, str(src_path))
        
        from src.config import Config
        from src.report_parser import ReportParser
        from src.ttp_extractor import TTPExtractor
        from src.timeline_analyzer import TimelineAnalyzer
        from src.visualization import VisualizationEngine
        
        print("✓ All TTP Analyzer modules imported successfully")
        return True
        
    except ImportError as e:
        print(f"✗ Module import error: {e}")
        return False

def test_configuration():
    """Test configuration loading."""
    print("\nTesting configuration...")
    
    try:
        # Add src directory to path if needed
        src_path = Path(__file__).parent / "src"
        if src_path.exists():
            sys.path.insert(0, str(src_path))
            
        from src.config import Config
        
        # Test default configuration
        config = Config()
        
        # Test some key configuration values
        assert hasattr(config, 'GROUPS_DIR')
        assert hasattr(config, 'OUTPUT_DIR')
        assert hasattr(config, 'LOG_LEVEL')
        
        print(f"✓ Configuration loaded successfully")
        print(f"  - Groups directory: {config.GROUPS_DIR}")
        print(f"  - Output directory: {config.OUTPUT_DIR}")
        print(f"  - Log level: {config.LOG_LEVEL}")
        
        return True
        
    except Exception as e:
        print(f"✗ Configuration error: {e}")
        return False

def test_directories():
    """Test directory structure."""
    print("\nTesting directory structure...")
    
    required_dirs = ['groups', 'output', 'data', 'logs']
    missing_dirs = []
    
    for dir_name in required_dirs:
        dir_path = Path(dir_name)
        if dir_path.exists():
            print(f"✓ {dir_name}/ directory exists")
        else:
            print(f"⚠ {dir_name}/ directory missing - will be created on first run")
            missing_dirs.append(dir_name)
    
    # Check for groups structure
    groups_dir = Path('groups')
    if groups_dir.exists():
        actors = [d.name for d in groups_dir.iterdir() if d.is_dir() and (d / 'reports.txt').exists()]
        if actors:
            print(f"✓ Found {len(actors)} threat actor(s): {', '.join(actors)}")
        else:
            print("⚠ No threat actors found in groups/ directory")
            print("  Run the example setup script to create sample data")
    
    return True

def test_main_script():
    """Test that the main script is functional."""
    print("\nTesting main script...")
    
    main_script = Path('ttp_analyzer.py')
    if main_script.exists():
        print("✓ Main script (ttp_analyzer.py) found")
        
        # Test help functionality
        try:
            import subprocess
            result = subprocess.run([sys.executable, 'ttp_analyzer.py', '--help'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✓ Main script help function works")
            else:
                print("⚠ Main script help returned non-zero exit code")
        except Exception as e:
            print(f"⚠ Could not test main script: {e}")
            
        return True
    else:
        print("✗ Main script (ttp_analyzer.py) not found")
        return False

def test_attack_data():
    """Test MITRE ATT&CK data access."""
    print("\nTesting MITRE ATT&CK data access...")
    
    try:
        # Add src directory to path if needed
        src_path = Path(__file__).parent / "src"
        if src_path.exists():
            sys.path.insert(0, str(src_path))
            
        from src.config import Config
        from src.ttp_extractor import TTPExtractor
        
        config = Config()
        
        # Check if data file exists
        data_file = Path(config.ATTACK_DATA_FILE)
        if not data_file.exists():
            print("⚠ MITRE ATT&CK data not found")
            print("  Run: python ttp_analyzer.py --update-attack-data")
            return True
        
        extractor = TTPExtractor(config)
        techniques = extractor.get_all_techniques()
        
        if len(techniques) > 10:  # Should have many techniques if properly loaded
            print(f"✓ Loaded {len(techniques)} MITRE ATT&CK techniques")
            
            sample_technique = list(techniques.keys())[0]
            print(f"  - Sample technique: {sample_technique} - {techniques[sample_technique]['name']}")
        else:
            print("⚠ Limited ATT&CK data available - may need to update")
            print("  Run: python ttp_analyzer.py --update-attack-data")
        
        return True
        
    except Exception as e:
        print(f"⚠ ATT&CK data test failed: {e}")
        print("  Run: python ttp_analyzer.py --update-attack-data")
        return True

def create_sample_structure():
    """Create sample directory structure for testing."""
    print("\nCreating sample directory structure...")
    
    # Create directories
    dirs = ['groups', 'output', 'data', 'logs']
    for dir_name in dirs:
        Path(dir_name).mkdir(exist_ok=True)
        print(f"✓ Created {dir_name}/ directory")
    
    # Create sample threat actor
    sample_actor = Path('groups/test_actor')
    sample_actor.mkdir(exist_ok=True)
    
    # Create sample reports.txt with test URLs
    reports_file = sample_actor / 'reports.txt'
    sample_content = """# Test Actor Reports
# This is a sample reports file for testing
https://attack.mitre.org/groups/G0006/
https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a
"""
    
    with open(reports_file, 'w') as f:
        f.write(sample_content)
    
    print("✓ Created sample threat actor: test_actor")
    return True

def run_sample_analysis():
    """Run a sample analysis to test functionality."""
    print("\nRunning sample analysis...")
    
    try:
        # Check if we have the main script and sample data
        if not Path('ttp_analyzer.py').exists():
            print("⚠ Cannot run sample analysis - main script not found")
            return False
            
        if not Path('groups/test_actor').exists():
            print("⚠ Cannot run sample analysis - no test actor found")
            return False
        
        # Try to run list-actors command
        import subprocess
        result = subprocess.run([sys.executable, 'ttp_analyzer.py', '--list-actors'], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✓ List actors command successful")
            if 'test_actor' in result.stdout:
                print("✓ Test actor found in list")
            else:
                print("⚠ Test actor not found in output")
        else:
            print(f"⚠ List actors command failed: {result.stderr}")
        
        return True
        
    except Exception as e:
        print(f"⚠ Sample analysis test failed: {e}")
        return False

def main():
    """Run all installation tests."""
    print("TTP Analyzer Installation Test")
    print("=" * 40)
    
    tests = [
        ("Import Dependencies", test_imports),
        ("Module Imports", test_module_imports),
        ("Configuration", test_configuration),
        ("Directory Structure", test_directories),
        ("Main Script", test_main_script),
        ("ATT&CK Data", test_attack_data)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n{test_name}")
        print("-" * len(test_name))
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"✗ Test failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 40)
    print("TEST SUMMARY")
    print("=" * 40)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{test_name:<20} {status}")
    
    print(f"\nPassed: {passed}/{total}")
    
    if passed == total:
        print("\n🎉 All tests passed! TTP Analyzer is ready to use.")
        print("\nNext steps:")
        print("1. Set up your threat actor directories in groups/")
        print("2. Add report URLs to reports.txt files")
        print("3. Run: python ttp_analyzer.py --actor <actor_name>")
    else:
        print(f"\n⚠ {total - passed} test(s) failed. Please check the errors above.")
        
        # Offer to create sample structure
        response = input("\nWould you like to create a sample directory structure for testing? (y/n): ")
        if response.lower().startswith('y'):
            create_sample_structure()
            print("\nSample structure created. You can now run:")
            print("python ttp_analyzer.py --list-actors")
            print("python ttp_analyzer.py --actor test_actor")
    
    print("\nFor more information, see README.md")

if __name__ == "__main__":
    main()
