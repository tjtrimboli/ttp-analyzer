#!/usr/bin/env python3
"""
Fixed debug script to test TTP extraction functionality
"""

import sys
import os
from pathlib import Path

print("=== TTP Extraction Debug Test (FIXED) ===")
print(f"Python version: {sys.version}")
print(f"Current directory: {os.getcwd()}")
print(f"Python path: {sys.path[:3]}...")  # Show first 3 entries

# Correctly add the project root to path (where src/ directory is located)
project_root = Path.cwd()
src_path = project_root / "src"

print(f"Project root: {project_root}")
print(f"Looking for src directory at: {src_path}")
print(f"Src directory exists: {src_path.exists()}")

if not src_path.exists():
    print("❌ src directory not found!")
    print("Please run this script from the project root directory")
    sys.exit(1)

# Add project root to path so we can import src modules
sys.path.insert(0, str(project_root))
print(f"Added {project_root} to Python path")

# List files in src directory
src_files = list(src_path.glob("*.py"))
print(f"Python files in src: {[f.name for f in src_files]}")

# Test imports one by one
print("\n=== Testing Imports ===")

try:
    from src.config import Config
    print("✅ Config imported successfully")
except Exception as e:
    print(f"❌ Failed to import Config: {e}")
    sys.exit(1)

try:
    from src.ttp_extractor import TTPExtractor
    print("✅ TTPExtractor imported successfully")
except Exception as e:
    print(f"❌ Failed to import TTPExtractor: {e}")
    sys.exit(1)

# Test config initialization
print("\n=== Testing Config ===")
try:
    config = Config()
    print("✅ Config initialized successfully")
    print(f"   Groups dir: {config.GROUPS_DIR}")
    print(f"   Min confidence: {config.MIN_CONFIDENCE_THRESHOLD}")
    print(f"   Attack data file: {config.ATTACK_DATA_FILE}")
except Exception as e:
    print(f"❌ Failed to initialize Config: {e}")
    sys.exit(1)

# Test TTP extractor initialization
print("\n=== Testing TTP Extractor ===")
try:
    extractor = TTPExtractor(config)
    print("✅ TTPExtractor initialized successfully")
    
    # Check if techniques loaded
    techniques = extractor.get_all_techniques()
    print(f"✅ Loaded {len(techniques)} techniques")
    
    # Show some statistics
    id_patterns = len(extractor.technique_id_patterns)
    name_patterns = len(extractor.technique_name_patterns)
    print(f"   ID patterns: {id_patterns}")
    print(f"   Name patterns: {name_patterns}")
    
    if len(techniques) == 0:
        print("❌ No techniques loaded - check MITRE ATT&CK data")
        
        # Check for attack data file
        attack_data_file = Path(config.ATTACK_DATA_FILE)
        print(f"Attack data file path: {attack_data_file}")
        print(f"Attack data file exists: {attack_data_file.exists()}")
        
        if not attack_data_file.exists():
            print("💡 Try running: python ttp_analyzer.py --update-attack-data")
    else:
        # Show first few techniques for verification
        technique_ids = list(techniques.keys())[:5]
        print(f"   First 5 technique IDs: {technique_ids}")
    
except Exception as e:
    print(f"❌ Failed to initialize TTPExtractor: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test with simple sample text
print("\n=== Testing Simple Extraction ===")
try:
    sample_text = """
    The threat actor used T1566.001 Spearphishing Attachment for initial access.
    They also employed T1078 Valid Accounts and T1055 Process Injection techniques.
    This is a MITRE ATT&CK analysis of the campaign.
    """
    
    print("Sample text:")
    print("-" * 40)
    print(sample_text.strip())
    print("-" * 40)
    print(f"Text length: {len(sample_text)} characters")
    
    report_data = {
        'source': 'test',
        'title': 'Simple Test',
        'content': sample_text,
        'publication_date': '2023-11-15',
        'content_type': 'text'
    }
    
    print(f"Calling extract_ttps with {len(sample_text)} characters...")
    ttps = extractor.extract_ttps(report_data)
    print(f"✅ extract_ttps returned {len(ttps)} TTPs")
    
    if ttps:
        print("\nExtracted TTPs:")
        for i, ttp in enumerate(ttps, 1):
            print(f"{i}. {ttp['technique_id']} - {ttp['technique_name']}")
            print(f"   Matched: '{ttp['matched_text']}'")
            print(f"   Confidence: {ttp['confidence']:.2f}")
            print(f"   Type: {ttp.get('match_type', 'unknown')}")
    else:
        print("❌ No TTPs extracted from simple test")
        
        # Debug: Test basic pattern matching
        import re
        pattern = r'\bT\d{4}(?:\.\d{3})?\b'
        matches = re.findall(pattern, sample_text)
        print(f"Basic regex pattern matches: {matches}")
        
        # Check specific technique
        if 'T1566.001' in techniques:
            print("✅ T1566.001 exists in techniques")
            print(f"   Name: {techniques['T1566.001']['name']}")
        else:
            print("❌ T1566.001 not found in techniques")

except Exception as e:
    print(f"❌ Error during extraction: {e}")
    import traceback
    traceback.print_exc()

# Test with minimal content
print("\n=== Testing Minimal Content ===")
try:
    minimal_text = "MITRE ATT&CK technique T1566.001 was used in this attack campaign."
    
    print(f"Minimal text: {minimal_text}")
    print(f"Length: {len(minimal_text)} characters")
    
    minimal_report = {
        'source': 'test_minimal',
        'title': 'Minimal Test',
        'content': minimal_text,
        'publication_date': None
    }
    
    minimal_ttps = extractor.extract_ttps(minimal_report)
    print(f"Minimal test result: {len(minimal_ttps)} TTPs")
    
    if minimal_ttps:
        for ttp in minimal_ttps:
            print(f"   {ttp['technique_id']}: {ttp['matched_text']} (conf: {ttp['confidence']:.2f})")
    else:
        print("❌ No TTPs found in minimal test")

except Exception as e:
    print(f"❌ Error in minimal test: {e}")
    import traceback
    traceback.print_exc()

print("\n=== Test Complete ===")
print("Fixed debug script completed successfully.")
