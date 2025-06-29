#!/usr/bin/env python3
"""
Comprehensive test script to validate TTP extraction improvements
"""

import sys
import os
from pathlib import Path

def setup_path():
    """Set up Python path correctly."""
    project_root = Path.cwd()
    sys.path.insert(0, str(project_root))
    return project_root

def test_basic_functionality():
    """Test basic functionality to ensure everything still works."""
    print("=== Basic Functionality Test ===")
    
    try:
        from src.config import Config
        from src.ttp_extractor import TTPExtractor
        
        config = Config()
        extractor = TTPExtractor(config)
        
        print(f"✅ Successfully loaded {len(extractor.get_all_techniques())} techniques")
        print(f"✅ Compiled {len(extractor.technique_id_patterns)} ID patterns")
        print(f"✅ Compiled {len(extractor.technique_name_patterns)} name patterns")
        
        return True
        
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_false_positive_prevention():
    """Test that false positives like T1588.006 are prevented."""
    print("\n=== False Positive Prevention Test ===")
    
    try:
        from src.config import Config
        from src.ttp_extractor import TTPExtractor
        
        config = Config()
        extractor = TTPExtractor(config)
        
        # Test cases that should NOT extract T1588.006
        false_positive_tests = [
            {
                'name': 'Generic web services mention',
                'content': 'The company uses various web services for their cloud infrastructure.',
                'should_not_contain': ['T1588.006']
            },
            {
                'name': 'Product description',
                'content': 'Our web services platform provides secure cloud hosting solutions.',
                'should_not_contain': ['T1588.006']
            },
            {
                'name': 'News article without MITRE context',
                'content': 'The retail company suffered significant losses due to the attack.',
                'should_not_contain': ['T1588.006', 'T1486']  # Should not match generic terms
            },
            {
                'name': 'Negative context mention',
                'content': 'This analysis should not trigger T1588.006 as it is not in proper MITRE context.',
                'should_not_contain': ['T1588.006']  # Should reject due to negative context
            }
        ]
        
        all_passed = True
        
        for test in false_positive_tests:
            report_data = {
                'source': 'test',
                'title': test['name'],
                'content': test['content'],
                'publication_date': None
            }
            
            ttps = extractor.extract_ttps(report_data)
            extracted_ids = [ttp['technique_id'] for ttp in ttps]
            
            print(f"\nTest: {test['name']}")
            print(f"Content: {test['content']}")
            print(f"Extracted: {extracted_ids}")
            
            for forbidden_id in test['should_not_contain']:
                if forbidden_id in extracted_ids:
                    print(f"❌ FAIL: False positive {forbidden_id} detected")
                    all_passed = False
                else:
                    print(f"✅ PASS: No false positive {forbidden_id}")
        
        return all_passed
        
    except Exception as e:
        print(f"❌ False positive test failed: {e}")
        return False

def test_true_positive_detection():
    """Test that legitimate MITRE references are correctly detected."""
    print("\n=== True Positive Detection Test ===")
    
    try:
        from src.config import Config
        from src.ttp_extractor import TTPExtractor
        
        config = Config()
        extractor = TTPExtractor(config)
        
        true_positive_tests = [
            {
                'name': 'Explicit MITRE ID reference',
                'content': 'The threat actor used T1566.001 Spearphishing Attachment for initial access according to the MITRE ATT&CK framework.',
                'should_contain': ['T1566.001']
            },
            {
                'name': 'MITRE context with technique name',
                'content': 'Analysis shows the adversary employed Process Injection [T1055] to evade detection.',
                'should_contain': ['T1055']
            },
            {
                'name': 'Multiple techniques with proper context',
                'content': 'The campaign utilized several MITRE ATT&CK techniques: T1078 Valid Accounts and T1219 Remote Access Software.',
                'should_contain': ['T1078', 'T1219']
            },
            {
                'name': 'Threat intelligence report context',
                'content': 'Scattered Spider leverages on-premises and cloud service accounts [T1136 / T1556.006] following privilege escalation.',
                'should_contain': ['T1136', 'T1556.006']
            }
        ]
        
        all_passed = True
        
        for test in true_positive_tests:
            report_data = {
                'source': 'test',
                'title': test['name'],
                'content': test['content'],
                'publication_date': None
            }
            
            ttps = extractor.extract_ttps(report_data)
            extracted_ids = [ttp['technique_id'] for ttp in ttps]
            
            print(f"\nTest: {test['name']}")
            print(f"Content: {test['content']}")
            print(f"Extracted: {extracted_ids}")
            
            for required_id in test['should_contain']:
                if required_id in extracted_ids:
                    print(f"✅ PASS: Correctly detected {required_id}")
                else:
                    print(f"❌ FAIL: Failed to detect {required_id}")
                    all_passed = False
        
        return all_passed
        
    except Exception as e:
        print(f"❌ True positive test failed: {e}")
        return False

def test_confidence_scoring():
    """Test that confidence scoring works appropriately."""
    print("\n=== Confidence Scoring Test ===")
    
    try:
        from src.config import Config
        from src.ttp_extractor import TTPExtractor
        
        config = Config()
        extractor = TTPExtractor(config)
        
        confidence_tests = [
            {
                'name': 'High confidence ID match',
                'content': 'The threat actor employed T1566.001 for initial access according to MITRE ATT&CK analysis.',
                'expected_min_confidence': 0.8
            },
            {
                'name': 'Medium confidence name match with context',
                'content': 'The MITRE ATT&CK technique Process Injection was observed during the campaign analysis.',
                'expected_min_confidence': 0.6
            },
            {
                'name': 'Lower confidence heuristic match',
                'content': 'The threat actor executed malicious PowerShell commands to establish persistence in the compromised environment.',
                'expected_min_confidence': 0.3
            }
        ]
        
        all_passed = True
        
        for test in confidence_tests:
            report_data = {
                'source': 'test',
                'title': test['name'],
                'content': test['content'],
                'publication_date': None
            }
            
            ttps = extractor.extract_ttps(report_data)
            
            print(f"\nTest: {test['name']}")
            print(f"Content: {test['content']}")
            
            if ttps:
                max_confidence = max(ttp['confidence'] for ttp in ttps)
                print(f"Max confidence: {max_confidence:.2f} (expected min: {test['expected_min_confidence']})")
                
                if max_confidence >= test['expected_min_confidence']:
                    print(f"✅ PASS: Confidence meets expectations")
                else:
                    print(f"❌ FAIL: Confidence too low")
                    all_passed = False
            else:
                print(f"❌ FAIL: No TTPs extracted")
                all_passed = False
        
        return all_passed
        
    except Exception as e:
        print(f"❌ Confidence scoring test failed: {e}")
        return False

def test_enhanced_html_parsing():
    """Test enhanced HTML parsing capabilities."""
    print("\n=== Enhanced HTML Parsing Test ===")
    
    try:
        from src.config import Config
        from src.report_parser import ReportParser
        
        config = Config()
        parser = ReportParser(config)
        
        # Test HTML content with various structures
        test_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>MITRE ATT&CK Analysis Report</title>
            <meta property="article:published_time" content="2023-11-15">
        </head>
        <body>
            <nav>Navigation menu</nav>
            <header>Header content</header>
            <article>
                <h1>Threat Intelligence Report</h1>
                <p>The adversary employed T1566.001 Spearphishing Attachment in their campaign.</p>
                <p>Additional techniques included T1078 Valid Accounts for persistence.</p>
                <div class="content">
                    <p>This analysis follows the MITRE ATT&CK framework.</p>
                </div>
            </article>
            <footer>Footer content</footer>
            <script>Some JavaScript</script>
        </body>
        </html>
        """
        
        result = parser._parse_html_content(test_html, "test_source")
        
        print(f"Title extracted: {result['title']}")
        print(f"Content length: {result['content_length']}")
        print(f"Publication date: {result['publication_date']}")
        print(f"Content preview: {result['content'][:200]}...")
        
        # Verify content quality
        content = result['content']
        if 'T1566.001' in content and 'T1078' in content:
            print("✅ PASS: Important content preserved")
        else:
            print("❌ FAIL: Important content missing")
            return False
        
        if 'Navigation menu' not in content and 'JavaScript' not in content:
            print("✅ PASS: Unwanted content removed")
        else:
            print("❌ FAIL: Unwanted content present")
            return False
        
        if result['publication_date']:
            print("✅ PASS: Date extraction working")
        else:
            print("⚠️  WARNING: Date not extracted (may be normal)")
        
        return True
        
    except Exception as e:
        print(f"❌ HTML parsing test failed: {e}")
        return False

def run_integration_test():
    """Run an integration test simulating the Halcyon report issue."""
    print("\n=== Integration Test (Halcyon-style content) ===")
    
    try:
        from src.config import Config
        from src.ttp_extractor import TTPExtractor
        
        config = Config()
        extractor = TTPExtractor(config)
        
        # Simulate content similar to Halcyon report but without T1588.006
        test_content = """
        Scattered Spider Tactics Analysis
        
        Since 2021, the Scattered Spider cybercriminal group has rapidly honed its skill 
        in combining human deception with technical precision. The group can execute a 
        full data theft and ransomware campaign within hours.
        
        Single Sign On (SSO) & Service Account Abuse: Scattered Spider leverages 
        on-premises and cloud service accounts, setting up rogue federated services 
        and enrolling MFA tokens. [T1136 / T1556.006]
        
        Social Engineering & Phishing: The group uses email phishing, SMS phishing, 
        and unsolicited help desk phone calls. [T1566 / T1566.004]
        
        Remote Access Tools: After initial infiltration, they deploy trusted remote-access 
        tools like AnyDesk, Ngrok, and Remcos. [T1219]
        
        The group uses various web services and cloud platforms for their operations,
        leveraging these infrastructure components to maintain persistence and command control.
        """
        
        report_data = {
            'source': 'test_halcyon_style',
            'title': 'Scattered Spider Analysis',
            'content': test_content,
            'publication_date': '2025-06-26'
        }
        
        ttps = extractor.extract_ttps(report_data)
        extracted_ids = [ttp['technique_id'] for ttp in ttps]
        
        print(f"Content length: {len(test_content)} characters")
        print(f"Extracted techniques: {extracted_ids}")
        
        # Check for expected techniques
        expected = ['T1136', 'T1556.006', 'T1566', 'T1566.004', 'T1219']
        unexpected = ['T1588.006']  # This should NOT be extracted
        
        all_passed = True
        
        for tech_id in expected:
            if tech_id in extracted_ids:
                print(f"✅ PASS: Correctly extracted {tech_id}")
            else:
                print(f"❌ FAIL: Failed to extract expected {tech_id}")
                all_passed = False
        
        for tech_id in unexpected:
            if tech_id in extracted_ids:
                print(f"❌ FAIL: False positive {tech_id} detected")
                all_passed = False
            else:
                print(f"✅ PASS: Correctly avoided false positive {tech_id}")
        
        # Show confidence scores
        print("\nConfidence scores:")
        for ttp in ttps:
            print(f"  {ttp['technique_id']}: {ttp['confidence']:.2f} ({ttp['match_type']})")
        
        return all_passed
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("Enhanced TTP Extraction Validation Tests")
    print("=" * 50)
    
    # Setup
    project_root = setup_path()
    print(f"Project root: {project_root}")
    
    # Run tests
    tests = [
        ("Basic Functionality", test_basic_functionality),
        ("False Positive Prevention", test_false_positive_prevention),
        ("True Positive Detection", test_true_positive_detection),
        ("Confidence Scoring", test_confidence_scoring),
        ("Enhanced HTML Parsing", test_enhanced_html_parsing),
        ("Integration Test", run_integration_test)
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ {test_name} crashed: {e}")
            results[test_name] = False
    
    # Summary
    print("\n" + "=" * 50)
    print("TEST SUMMARY")
    print("=" * 50)
    
    passed = sum(results.values())
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:.<30} {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED! The improvements are working correctly.")
        return True
    else:
        print("⚠️  SOME TESTS FAILED. Please review the issues above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
