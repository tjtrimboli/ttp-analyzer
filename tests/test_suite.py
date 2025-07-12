#!/usr/bin/env python3
"""
Comprehensive Test Suite for  TTP Extraction
Tests the improved TTP extraction functionality with real-world scenarios.
"""

import sys
import os
from pathlib import Path
import logging
from typing import List, Dict, Tuple

def setup_test_environment():
    """Set up the test environment."""
    project_root = Path.cwd()
    sys.path.insert(0, str(project_root))
    
    # Set up logging for tests
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    return project_root

def test_basic_imports():
    """Test that all  modules can be imported."""
    print("=== Testing  Module Imports ===")
    
    try:
        from src.config import Config
        from src.ttp_extractor import TTPExtractor
        from src.report_parser import ReportParser
        
        print("✅ All  modules imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test__configuration():
    """Test the  configuration."""
    print("\n=== Testing  Configuration ===")
    
    try:
        from src.config import Config
        
        config = Config()
        
        # Test improved settings
        print(f"Min confidence threshold: {config.MIN_CONFIDENCE_THRESHOLD}")
        print(f"Heuristic extraction enabled: {config.ENABLE_HEURISTIC_EXTRACTION}")
        print(f"Max report size: {config.MAX_REPORT_SIZE_MB}MB")
        
        # Verify the settings are more permissive
        assert config.MIN_CONFIDENCE_THRESHOLD <= 0.4, "Confidence threshold should be lowered"
        assert config.ENABLE_HEURISTIC_EXTRACTION == True, "Heuristic extraction should be enabled"
        
        print("✅  configuration validated")
        return True
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def test__ttp_extraction():
    """Test the  TTP extraction with realistic scenarios."""
    print("\n=== Testing  TTP Extraction ===")
    
    try:
        from src.config import Config
        from src.ttp_extractor import TTPExtractor
        
        config = Config()
        extractor = TTPExtractor(config)
        
        print(f"Loaded {len(extractor.get_all_techniques())} techniques")
        print(f"ID patterns: {len(extractor.technique_id_patterns)}")
        print(f"Name patterns: {len(extractor.technique_name_patterns)}")
        
        # Test cases with realistic threat intelligence content
        test_cases = [
            {
                'name': 'Scattered Spider Analysis',
                'content': '''
                Scattered Spider Analysis Report
                
                The Scattered Spider cybercriminal group has employed several MITRE ATT&CK techniques:
                
                • Single Sign On (SSO) & Service Account Abuse: T1136 / T1556.006
                • Social Engineering & Phishing: T1566 / T1566.004 
                • Remote Access Tools: T1219
                • PowerShell execution: T1059.001
                • Valid Accounts for persistence: T1078
                
                The threat actor leveraged Process Injection techniques and employed 
                Command and Scripting Interpreter methods for execution.
                ''',
                'expected_techniques': ['T1136', 'T1556.006', 'T1566', 'T1566.004', 'T1219', 'T1059.001', 'T1078'],
                'expected_names': ['Process Injection', 'Command and Scripting Interpreter']
            },
            {
                'name': 'APT Campaign Report',
                'content': '''
                Advanced Persistent Threat Campaign Analysis
                
                This MITRE ATT&CK analysis covers the following techniques observed:
                
                Initial Access:
                - Spearphishing Attachment (T1566.001) 
                - Exploit Public-Facing Application (T1190)
                
                Execution:
                - The adversary used PowerShell for script execution
                - Command and Scripting Interpreter abuse was detected
                
                Persistence:
                - Valid Accounts (T1078) were compromised
                - Create Account (T1136) for maintaining access
                
                Defense Evasion:
                - Obfuscated Files or Information techniques
                - Process Injection was observed
                ''',
                'expected_techniques': ['T1566.001', 'T1190', 'T1078', 'T1136'],
                'expected_names': ['PowerShell', 'Spearphishing Attachment', 'Valid Accounts', 'Create Account']
            },
            {
                'name': 'Threat Intelligence Brief',
                'content': '''
                Threat Intelligence Brief: Operation CloudHopper
                
                Techniques observed in this campaign include:
                
                T1105 - Ingress Tool Transfer for payload delivery
                T1083 - File and Directory Discovery during reconnaissance  
                T1027 - Obfuscated Files or Information to evade detection
                T1070 - Indicator Removal for anti-forensics
                
                The threat actors employed Remote Desktop Protocol (T1021.001) 
                for lateral movement and utilized Remote Access Software 
                for maintaining persistence in the environment.
                ''',
                'expected_techniques': ['T1105', 'T1083', 'T1027', 'T1070', 'T1021.001'],
                'expected_names': ['Remote Desktop Protocol', 'Remote Access Software']
            }
        ]
        
        all_tests_passed = True
        
        for test_case in test_cases:
            print(f"\n--- Testing: {test_case['name']} ---")
            
            report_data = {
                'source': f"test_{test_case['name'].lower().replace(' ', '_')}",
                'title': test_case['name'],
                'content': test_case['content'],
                'publication_date': '2023-11-15'
            }
            
            ttps = extractor.extract_ttps(report_data)
            extracted_ids = [ttp['technique_id'] for ttp in ttps]
            extracted_names = [ttp['technique_name'] for ttp in ttps]
            
            print(f"Extracted technique IDs: {sorted(extracted_ids)}")
            print(f"Extracted technique names: {sorted(set(extracted_names))}")
            
            # Check expected techniques
            missing_techniques = []
            for expected_id in test_case['expected_techniques']:
                if expected_id not in extracted_ids:
                    missing_techniques.append(expected_id)
            
            # Check expected names (partial matching)
            missing_names = []
            for expected_name in test_case['expected_names']:
                found = any(expected_name.lower() in name.lower() for name in extracted_names)
                if not found:
                    missing_names.append(expected_name)
            
            if missing_techniques:
                print(f"❌ Missing expected techniques: {missing_techniques}")
                all_tests_passed = False
            else:
                print("✅ All expected technique IDs found")
            
            if missing_names:
                print(f"⚠️  Missing expected names: {missing_names}")
                # Names are less critical than IDs
            else:
                print("✅ All expected technique names found")
            
            # Check confidence scores
            confidences = [ttp['confidence'] for ttp in ttps]
            if confidences:
                avg_confidence = sum(confidences) / len(confidences)
                print(f"Average confidence: {avg_confidence:.2f}")
                
                if avg_confidence < 0.3:
                    print("⚠️  Low average confidence scores")
            
            print(f"Total TTPs extracted: {len(ttps)}")
        
        return all_tests_passed
        
    except Exception as e:
        print(f"❌  TTP extraction test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_false_positive_prevention():
    """Test that false positives are prevented."""
    print("\n=== Testing False Positive Prevention ===")
    
    try:
        from src.config import Config
        from src.ttp_extractor import TTPExtractor
        
        config = Config()
        extractor = TTPExtractor(config)
        
        # Test cases that should NOT extract certain techniques
        false_positive_tests = [
            {
                'name': 'Generic web services mention',
                'content': 'The company provides various web services for cloud infrastructure hosting.',
                'should_not_contain': ['T1588.006']  # Web Services technique
            },
            {
                'name': 'Product marketing content',
                'content': 'Our enterprise software solutions include file management, remote access, and data services.',
                'should_not_contain': ['T1083', 'T1021', 'T1005']  # Generic mentions
            },
            {
                'name': 'Non-security context',
                'content': 'The user reported issues with file access and network connectivity in the office.',
                'should_not_contain': ['T1083', 'T1005', 'T1082']  # Non-threat context
            },
            {
                'name': 'Negative context mention',
                'content': 'This test should not trigger T1566.001 as it is mentioned as an example of what not to extract.',
                'should_not_contain': ['T1566.001']  # Explicit negative context
            }
        ]
        
        all_tests_passed = True
        
        for test in false_positive_tests:
            print(f"\n--- Testing: {test['name']} ---")
            
            report_data = {
                'source': 'false_positive_test',
                'title': test['name'],
                'content': test['content'],
                'publication_date': None
            }
            
            ttps = extractor.extract_ttps(report_data)
            extracted_ids = [ttp['technique_id'] for ttp in ttps]
            
            print(f"Content: {test['content']}")
            print(f"Extracted: {extracted_ids}")
            
            false_positives_found = []
            for forbidden_id in test['should_not_contain']:
                if forbidden_id in extracted_ids:
                    false_positives_found.append(forbidden_id)
            
            if false_positives_found:
                print(f"❌ False positives detected: {false_positives_found}")
                all_tests_passed = False
            else:
                print("✅ No false positives detected")
        
        return all_tests_passed
        
    except Exception as e:
        print(f"❌ False positive prevention test failed: {e}")
        return False

def test__report_parsing():
    """Test the  report parsing capabilities."""
    print("\n=== Testing  Report Parsing ===")
    
    try:
        from src.config import Config
        from src.report_parser import ReportParser
        
        config = Config()
        parser = ReportParser(config)
        
        # Test HTML content with TTP information
        test_html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>MITRE ATT&CK Threat Analysis Report</title>
            <meta property="article:published_time" content="2023-11-15">
        </head>
        <body>
            <nav>Navigation menu - should be removed</nav>
            <script>alert('script content');</script>
            
            <article class="threat-analysis">
                <h1>Advanced Threat Actor Campaign</h1>
                
                <div class="mitre-analysis">
                    <p>The adversary employed <strong>T1566.001 Spearphishing Attachment</strong> for initial access.</p>
                    <p>Following initial compromise, the threat actor used:</p>
                    <ul>
                        <li>T1059.001 PowerShell for execution</li>
                        <li>T1078 Valid Accounts for persistence</li>
                        <li>Process Injection techniques for privilege escalation</li>
                    </ul>
                </div>
                
                <section class="intelligence">
                    <h2>Threat Intelligence Summary</h2>
                    <p>This campaign demonstrates sophisticated use of MITRE ATT&CK techniques.</p>
                </section>
            </article>
            
            <footer>Footer content - should be removed</footer>
        </body>
        </html>
        '''
        
        result = parser._parse_html_content(test_html, "test_source")
        
        print(f"Title: {result['title']}")
        print(f"Content length: {result['content_length']}")
        print(f"Publication date: {result['publication_date']}")
        
        content = result['content']
        print(f"Content preview: {content[:300]}...")
        
        # Verify important content is preserved
        required_content = ['T1566.001', 'T1059.001', 'T1078', 'Spearphishing Attachment', 'PowerShell', 'Valid Accounts']
        missing_content = []
        
        for required in required_content:
            if required not in content:
                missing_content.append(required)
        
        if missing_content:
            print(f"❌ Missing required content: {missing_content}")
            return False
        else:
            print("✅ All required TTP content preserved")
        
        # Verify unwanted content is removed
        unwanted_content = ['Navigation menu', "alert('script content')", 'Footer content']
        unwanted_found = []
        
        for unwanted in unwanted_content:
            if unwanted in content:
                unwanted_found.append(unwanted)
        
        if unwanted_found:
            print(f"⚠️  Unwanted content found: {unwanted_found}")
            # This is warning, not failure
        else:
            print("✅ Unwanted content properly removed")
        
        # Test date extraction
        if result['publication_date']:
            print("✅ Date extraction successful")
        else:
            print("⚠️  Date not extracted")
        
        return True
        
    except Exception as e:
        print(f"❌  report parsing test failed: {e}")
        return False

def test_sub_technique_handling():
    """Test handling of sub-techniques (T1234.001 format)."""
    print("\n=== Testing Sub-Technique Handling ===")
    
    try:
        from src.config import Config
        from src.ttp_extractor import TTPExtractor
        
        config = Config()
        extractor = TTPExtractor(config)
        
        sub_technique_content = '''
        MITRE ATT&CK Sub-Technique Analysis
        
        The following sub-techniques were observed:
        • T1566.001 - Spearphishing Attachment
        • T1566.002 - Spearphishing Link  
        • T1566.004 - Spearphishing Voice
        • T1059.001 - PowerShell
        • T1021.001 - Remote Desktop Protocol
        • T1556.006 - Multi-Factor Authentication
        
        These sub-techniques provide more granular detail about adversary behavior
        within the broader T1566 Phishing and T1059 Command and Scripting Interpreter techniques.
        '''
        
        report_data = {
            'source': 'sub_technique_test',
            'title': 'Sub-Technique Test',
            'content': sub_technique_content,
            'publication_date': '2023-11-15'
        }
        
        ttps = extractor.extract_ttps(report_data)
        extracted_ids = [ttp['technique_id'] for ttp in ttps]
        
        expected_sub_techniques = ['T1566.001', 'T1566.002', 'T1566.004', 'T1059.001', 'T1021.001', 'T1556.006']
        
        print(f"Extracted IDs: {sorted(extracted_ids)}")
        print(f"Expected sub-techniques: {expected_sub_techniques}")
        
        missing_sub_techniques = []
        for expected in expected_sub_techniques:
            if expected not in extracted_ids:
                missing_sub_techniques.append(expected)
        
        if missing_sub_techniques:
            print(f"❌ Missing sub-techniques: {missing_sub_techniques}")
            return False
        else:
            print("✅ All sub-techniques correctly extracted")
            return True
            
    except Exception as e:
        print(f"❌ Sub-technique handling test failed: {e}")
        return False

def test_confidence_scoring():
    """Test that confidence scoring works appropriately."""
    print("\n=== Testing Confidence Scoring ===")
    
    try:
        from src.config import Config
        from src.ttp_extractor import TTPExtractor
        
        config = Config()
        extractor = TTPExtractor(config)
        
        confidence_tests = [
            {
                'name': 'High confidence - explicit ID with MITRE context',
                'content': 'According to MITRE ATT&CK analysis, the threat actor used T1566.001 for initial access.',
                'expected_min_confidence': 0.8,
                'expected_technique': 'T1566.001'
            },
            {
                'name': 'Medium confidence - technique name with threat context',
                'content': 'The adversary employed PowerShell execution during the campaign for malicious purposes.',
                'expected_min_confidence': 0.4,
                'expected_technique': 'T1059.001'
            },
            {
                'name': 'Lower confidence - heuristic match',
                'content': 'The threat actor executed malicious commands and scripts during the attack.',
                'expected_min_confidence': 0.3,
                'expected_technique': 'T1059'
            }
        ]
        
        all_tests_passed = True
        
        for test in confidence_tests:
            print(f"\n--- Testing: {test['name']} ---")
            
            report_data = {
                'source': 'confidence_test',
                'title': test['name'],
                'content': test['content'],
                'publication_date': None
            }
            
            ttps = extractor.extract_ttps(report_data)
            
            if not ttps:
                print(f"❌ No TTPs extracted")
                all_tests_passed = False
                continue
            
            # Find the relevant TTP
            relevant_ttp = None
            for ttp in ttps:
                if test['expected_technique'] in ttp['technique_id']:
                    relevant_ttp = ttp
                    break
            
            if not relevant_ttp:
                print(f"❌ Expected technique {test['expected_technique']} not found")
                all_tests_passed = False
                continue
            
            confidence = relevant_ttp['confidence']
            print(f"Confidence: {confidence:.2f} (expected min: {test['expected_min_confidence']})")
            
            if confidence >= test['expected_min_confidence']:
                print("✅ Confidence meets expectations")
            else:
                print("❌ Confidence below expectations")
                all_tests_passed = False
        
        return all_tests_passed
        
    except Exception as e:
        print(f"❌ Confidence scoring test failed: {e}")
        return False

def test_integration_scenario():
    """Test a complete integration scenario."""
    print("\n=== Testing Integration Scenario ===")
    
    try:
        from src.config import Config
        from src.ttp_extractor import TTPExtractor
        from src.report_parser import ReportParser
        
        config = Config()
        parser = ReportParser(config)
        extractor = TTPExtractor(config)
        
        # Simulate a realistic threat intelligence report
        realistic_report = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Scattered Spider: A Comprehensive Analysis</title>
            <meta name="date" content="2023-11-15">
        </head>
        <body>
            <h1>Scattered Spider Threat Group Analysis</h1>
            
            <div class="executive-summary">
                <p>This report analyzes the tactics, techniques, and procedures (TTPs) 
                employed by the Scattered Spider cybercriminal group.</p>
            </div>
            
            <div class="mitre-analysis">
                <h2>MITRE ATT&CK Mapping</h2>
                
                <h3>Initial Access</h3>
                <ul>
                    <li><strong>T1566 Phishing</strong> - Social engineering campaigns</li>
                    <li><strong>T1566.004 Spearphishing Voice</strong> - Vishing attacks</li>
                </ul>
                
                <h3>Execution</h3>
                <ul>
                    <li>T1059.001 PowerShell - Script execution</li>
                    <li>Command and Scripting Interpreter abuse</li>
                </ul>
                
                <h3>Persistence</h3>
                <ul>
                    <li>T1078 Valid Accounts - Compromised credentials</li>
                    <li>T1136 Create Account - Rogue account creation</li>
                </ul>
                
                <h3>Credential Access</h3>
                <ul>
                    <li>T1556.006 Multi-Factor Authentication bypass</li>
                </ul>
                
                <h3>Lateral Movement</h3>
                <ul>
                    <li>T1021.001 Remote Desktop Protocol</li>
                    <li>T1219 Remote Access Software (AnyDesk, etc.)</li>
                </ul>
                
                <h3>Command and Control</h3>
                <ul>
                    <li>T1105 Ingress Tool Transfer</li>
                </ul>
            </div>
            
            <div class="analysis">
                <h2>Campaign Analysis</h2>
                <p>The threat actors demonstrated sophisticated understanding of enterprise environments,
                leveraging legitimate tools and services to blend in with normal network traffic.</p>
                
                <p>Observed techniques include Process Injection for defense evasion and 
                File and Directory Discovery for reconnaissance activities.</p>
            </div>
        </body>
        </html>
        '''
        
        # Step 1: Parse the report
        print("Step 1: Parsing HTML report...")
        parsed_report = parser._parse_html_content(realistic_report, "integration_test")
        
        print(f"Title: {parsed_report['title']}")
        print(f"Content length: {parsed_report['content_length']}")
        print(f"Date: {parsed_report['publication_date']}")
        
        # Step 2: Extract TTPs
        print("\nStep 2: Extracting TTPs...")
        ttps = extractor.extract_ttps(parsed_report)
        
        extracted_ids = [ttp['technique_id'] for ttp in ttps]
        print(f"Extracted technique IDs: {sorted(extracted_ids)}")
        
        # Expected techniques from the report
        expected_core_techniques = [
            'T1566', 'T1566.004', 'T1059.001', 'T1078', 'T1136', 
            'T1556.006', 'T1021.001', 'T1219', 'T1105'
        ]
        
        expected_name_techniques = [
            'T1055',  # Process Injection
            'T1083'   # File and Directory Discovery
        ]
        
        # Check core techniques
        missing_core = [t for t in expected_core_techniques if t not in extracted_ids]
        if missing_core:
            print(f"❌ Missing core techniques: {missing_core}")
            return False
        else:
            print("✅ All core techniques extracted successfully")
        
        # Check name-based techniques (less critical)
        missing_names = [t for t in expected_name_techniques if t not in extracted_ids]
        if missing_names:
            print(f"⚠️  Missing name-based techniques: {missing_names}")
        else:
            print("✅ Name-based techniques also extracted")
        
        # Check confidence distribution
        confidences = [ttp['confidence'] for ttp in ttps]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0
        
        print(f"\nConfidence Statistics:")
        print(f"Average confidence: {avg_confidence:.2f}")
        print(f"Confidence range: {min(confidences):.2f} - {max(confidences):.2f}")
        
        # Step 3: Validate extraction quality
        print(f"\nExtraction Quality:")
        print(f"Total TTPs extracted: {len(ttps)}")
        print(f"Unique techniques: {len(set(extracted_ids))}")
        
        high_confidence_ttps = [ttp for ttp in ttps if ttp['confidence'] >= 0.7]
        print(f"High confidence TTPs (≥0.7): {len(high_confidence_ttps)}")
        
        if avg_confidence >= 0.5 and len(ttps) >= 8:
            print("✅ Integration test passed successfully")
            return True
        else:
            print("❌ Integration test failed - insufficient quality")
            return False
            
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_comprehensive_test_suite():
    """Run the complete test suite."""
    print(" TTP Extraction Comprehensive Test Suite")
    print("=" * 60)
    
    # Setup
    project_root = setup_test_environment()
    print(f"Project root: {project_root}")
    
    # Define all tests
    tests = [
        ("Basic Imports", test_basic_imports),
        (" Configuration", test__configuration),
        (" TTP Extraction", test__ttp_extraction),
        ("False Positive Prevention", test_false_positive_prevention),
        (" Report Parsing", test__report_parsing),
        ("Sub-Technique Handling", test_sub_technique_handling),
        ("Confidence Scoring", test_confidence_scoring),
        ("Integration Scenario", test_integration_scenario)
    ]
    
    # Run tests
    results = {}
    for test_name, test_func in tests:
        try:
            print(f"\n{'='*60}")
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ {test_name} crashed: {e}")
            results[test_name] = False
    
    # Generate summary
    print(f"\n{'='*60}")
    print("COMPREHENSIVE TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(results.values())
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:<30} {status}")
    
    print(f"\nOverall Results: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED!")
        print("The  TTP extraction system is working correctly.")
        print("\nNext steps:")
        print("1. Replace the original modules with the  versions")
        print("2. Update the configuration file")
        print("3. Test with real threat intelligence reports")
        return True
    else:
        print(f"\n⚠️  {total - passed} TEST(S) FAILED")
        print("Please review the failed tests and address the issues.")
        return False

def main():
    """Main entry point."""
    success = run_comprehensive_test_suite()
    
    if success:
        print("\n📋 IMPLEMENTATION CHECKLIST:")
        print("□ Replace src/ttp_extractor.py with _ttp_extractor.py")
        print("□ Replace src/report_parser.py with _report_parser.py") 
        print("□ Update config.yaml with improved settings")
        print("□ Test with your actual threat actor reports")
        print("□ Monitor extraction results and adjust thresholds if needed")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
