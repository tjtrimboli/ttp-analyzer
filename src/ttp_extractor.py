"""
TTP Extractor Module for identifying MITRE ATT&CK techniques in threat intelligence reports.
"""

import re
import json
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from datetime import datetime
import requests


class TTPExtractor:
    """Extractor for MITRE ATT&CK Tactics, Techniques, and Procedures."""
    
    def __init__(self, config):
        """Initialize the TTP extractor."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Load MITRE ATT&CK framework data
        self.attack_data = self._load_attack_data()
        
        # Compile regex patterns for efficient matching
        self._compile_patterns()
        
    def _load_attack_data(self) -> Dict:
        """Load MITRE ATT&CK framework data."""
        data_file = Path(self.config.ATTACK_DATA_FILE)
        
        if not data_file.exists():
            self.logger.error(f"ATT&CK data file not found: {data_file}")
            self.logger.error("Please run: python ttp_analyzer.py --update-attack-data")
            return self._get_default_attack_data()
        
        try:
            with open(data_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load ATT&CK data: {e}")
            self.logger.error("Try running: python ttp_analyzer.py --update-attack-data")
            return self._get_default_attack_data()

    def download_attack_data(self) -> bool:
        """
        Download MITRE ATT&CK data from official source.
        
        Returns:
            bool: True if download was successful, False otherwise
        """
        try:
            self.logger.info("Downloading MITRE ATT&CK data...")
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # Save for future use
            data_file = Path(self.config.ATTACK_DATA_FILE)
            data_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
                
            self.logger.info(f"ATT&CK data downloaded and saved to: {data_file}")
            
            # Update internal data and recompile patterns
            self.attack_data = data
            self._compile_patterns()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to download ATT&CK data: {e}")
            return False
            
    def _get_default_attack_data(self) -> Dict:
        """Get default ATT&CK data with common techniques."""
        return {
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--01df3350-ce05-4bdf-bdf8-0a919a66d4a8",
                    "external_references": [{"external_id": "T1566.001", "source_name": "mitre-attack"}],
                    "name": "Spearphishing Attachment",
                    "description": "Spearphishing attachment is a specific variant of spearphishing.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]
                },
                {
                    "type": "attack-pattern", 
                    "id": "attack-pattern--dfd7cc1d-e1d8-4394-a198-97c4cab8aa67",
                    "external_references": [{"external_id": "T1055", "source_name": "mitre-attack"}],
                    "name": "Process Injection",
                    "description": "Process injection is a method of executing arbitrary code.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--7bc57495-ea59-4380-be31-a64af124ef18",
                    "external_references": [{"external_id": "T1059", "source_name": "mitre-attack"}],
                    "name": "Command and Scripting Interpreter",
                    "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add",
                    "external_references": [{"external_id": "T1105", "source_name": "mitre-attack"}],
                    "name": "Ingress Tool Transfer",
                    "description": "Adversaries may transfer tools or other files from an external system into a compromised environment.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--7bc57495-ea59-4380-be31-a64af124ef19",
                    "external_references": [{"external_id": "T1083", "source_name": "mitre-attack"}],
                    "name": "File and Directory Discovery",
                    "description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "discovery"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--799ace7f-e227-4411-baa0-8868704f2a69",
                    "external_references": [{"external_id": "T1070", "source_name": "mitre-attack"}],
                    "name": "Indicator Removal on Host",
                    "description": "Adversaries may delete or alter generated artifacts on a host system, including logs or captured files such as quarantined malware.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--b3d682b6-98f2-4fb0-aa3b-b4df007ca70a",
                    "external_references": [{"external_id": "T1027", "source_name": "mitre-attack"}],
                    "name": "Obfuscated Files or Information",
                    "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}]
                }
            ]
        }
        
    def _compile_patterns(self):
        """Compile regex patterns for TTP extraction."""
        # Extract techniques from ATT&CK data
        self.techniques = {}
        self.technique_patterns = []
        
        for obj in self.attack_data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                # Get technique ID
                technique_id = None
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        technique_id = ref.get("external_id")
                        break
                        
                if technique_id:
                    name = obj.get("name", "")
                    description = obj.get("description", "")
                    
                    # Get tactic
                    tactic = "unknown"
                    kill_chain_phases = obj.get("kill_chain_phases", [])
                    if kill_chain_phases:
                        tactic = kill_chain_phases[0].get("phase_name", "unknown")
                    
                    self.techniques[technique_id] = {
                        "name": name,
                        "description": description,
                        "tactic": tactic
                    }
                    
                    # Create patterns for matching
                    patterns = self._create_technique_patterns(technique_id, name)
                    self.technique_patterns.extend(patterns)
                    
        self.logger.info(f"Loaded {len(self.techniques)} ATT&CK techniques")
        
    def _create_technique_patterns(self, technique_id: str, name: str) -> List[Tuple[str, str]]:
        """Create regex patterns for matching a technique."""
        patterns = []
        
        # Pattern for technique ID (e.g., T1566.001)
        id_pattern = rf'\b{re.escape(technique_id)}\b'
        patterns.append((id_pattern, technique_id))
        
        # Pattern for technique name (case insensitive)
        if name:
            # Split name into words and create flexible pattern
            words = re.findall(r'\b\w+\b', name.lower())
            if words:
                # Exact name match
                name_pattern = rf'\b{re.escape(name.lower())}\b'
                patterns.append((name_pattern, technique_id))
                
                # Partial name matches for longer names
                if len(words) > 1:
                    # Match any 2+ consecutive words
                    for i in range(len(words) - 1):
                        partial = ' '.join(words[i:i+2])
                        partial_pattern = rf'\b{re.escape(partial)}\b'
                        patterns.append((partial_pattern, technique_id))
        
        return patterns
        
    def extract_ttps(self, report_data: Dict) -> List[Dict]:
        """
        Extract TTPs from a parsed report.
        
        Args:
            report_data: Parsed report data from ReportParser
            
        Returns:
            List of extracted TTP dictionaries
        """
        content = report_data.get('content', '')
        
        # Check if content is empty or too short
        if not content or len(content.strip()) < 50:
            self.logger.warning(f"Report content is empty or too short: {report_data.get('source', 'unknown')}")
            return []
        
        content_lower = content.lower()
        
        extracted_ttps = []
        matched_techniques = set()  # Avoid duplicates within this report
        
        # Search for techniques using compiled patterns
        for pattern, technique_id in self.technique_patterns:
            if technique_id in matched_techniques:
                continue  # Skip if already matched
                
            matches = list(re.finditer(pattern, content_lower, re.IGNORECASE))
            
            if matches:
                # Use the first match for this technique
                match = matches[0]
                technique_info = self.techniques.get(technique_id, {})
                
                ttp = {
                    'technique_id': technique_id,
                    'technique_name': technique_info.get('name', ''),
                    'tactic': technique_info.get('tactic', 'unknown'),
                    'description': technique_info.get('description', ''),
                    'matched_text': match.group(),
                    'match_position': match.start(),
                    'confidence': self._calculate_confidence(match.group(), technique_info),
                    'source': report_data.get('source', ''),
                    'report_title': report_data.get('title', ''),
                    'date': self._parse_date(report_data.get('publication_date')),
                    'extracted_at': datetime.utcnow().isoformat(),
                    'match_count': len(matches)  # Track how many times this technique was mentioned
                }
                
                extracted_ttps.append(ttp)
                matched_techniques.add(technique_id)
        
        # Additional heuristic-based extraction (only if not already matched)
        heuristic_ttps = self._extract_heuristic_ttps(report_data, matched_techniques)
        extracted_ttps.extend(heuristic_ttps)
        
        # Sort by confidence (highest first)
        extracted_ttps.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        
        self.logger.info(f"Extracted {len(extracted_ttps)} unique TTPs from report")
        if len(extracted_ttps) == 0:
            self.logger.warning(f"No TTPs extracted from: {report_data.get('source', 'unknown')}")
            # Log a sample of the content for debugging
            sample_content = content[:500] + "..." if len(content) > 500 else content
            self.logger.debug(f"Content sample: {sample_content}")
        
        return extracted_ttps
        
    def _extract_heuristic_ttps(self, report_data: Dict, already_matched: set = None) -> List[Dict]:
        """Extract TTPs using heuristic patterns for common attack behaviors."""
        if already_matched is None:
            already_matched = set()
            
        content = report_data.get('content', '').lower()
        heuristic_ttps = []
        
        # Define heuristic patterns for common attack behaviors
        heuristic_patterns = {
            'T1059': [  # Command and Scripting Interpreter
                r'\b(powershell|cmd\.exe|command line|shell|bash|script)\b',
                r'\b(execute|run|invoke).{0,20}(command|script|powershell|cmd)\b'
            ],
            'T1105': [  # Ingress Tool Transfer
                r'\b(download|upload|transfer|retrieve).{0,20}(tool|payload|file)\b',
                r'\b(wget|curl|certutil|bitsadmin)\b'
            ],
            'T1083': [  # File and Directory Discovery
                r'\b(enumerate|list|discover).{0,20}(file|director|folder)\b',
                r'\b(dir|ls|find|search).{0,20}command\b'
            ],
            'T1070': [  # Indicator Removal on Host
                r'\b(delete|remove|clear|wipe).{0,20}(log|trace|evidence|artifact)\b',
                r'\b(anti-forensic|cover.{0,10}track)\b'
            ],
            'T1027': [  # Obfuscated Files or Information
                r'\b(obfuscat|encrypt|encod|pack|hide).{0,20}(payload|code|file)\b',
                r'\b(base64|xor|cipher|steganograph)\b'
            ],
            'T1078': [  # Valid Accounts
                r'\b(compromise|stolen|hijack).{0,20}(account|credential|login)\b',
                r'\b(account takeover|credential theft)\b'
            ],
            'T1566': [  # Phishing
                r'\b(phishing|spear.?phish|malicious.?email)\b',
                r'\b(email.?attack|fraudulent.?message)\b'
            ]
        }
        
        for technique_id, patterns in heuristic_patterns.items():
            # Skip if already matched by exact patterns
            if technique_id in already_matched:
                continue
                
            for pattern in patterns:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                
                if matches:
                    technique_info = self.techniques.get(technique_id, {})
                    match = matches[0]  # Use first match
                    
                    ttp = {
                        'technique_id': technique_id,
                        'technique_name': technique_info.get('name', f'Technique {technique_id}'),
                        'tactic': technique_info.get('tactic', 'unknown'),
                        'description': technique_info.get('description', ''),
                        'matched_text': match.group(),
                        'match_position': match.start(),
                        'confidence': 0.6,  # Lower confidence for heuristic matches
                        'source': report_data.get('source', ''),
                        'report_title': report_data.get('title', ''),
                        'date': self._parse_date(report_data.get('publication_date')),
                        'extracted_at': datetime.utcnow().isoformat(),
                        'extraction_method': 'heuristic',
                        'match_count': len(matches)
                    }
                    
                    heuristic_ttps.append(ttp)
                    already_matched.add(technique_id)
                    break  # Only match once per technique per report
        
        return heuristic_ttps
        
    def _calculate_confidence(self, matched_text: str, technique_info: Dict) -> float:
        """Calculate confidence score for a TTP match."""
        confidence = 0.5  # Base confidence
        
        # Increase confidence for exact ID matches
        if re.match(r'T\d{4}', matched_text):
            confidence += 0.4
        
        # Increase confidence for exact name matches
        technique_name = technique_info.get('name', '').lower()
        if technique_name and matched_text.lower() == technique_name:
            confidence += 0.3
        
        # Decrease confidence for very short matches
        if len(matched_text) < 5:
            confidence -= 0.2
        
        # Ensure confidence is between 0 and 1
        return max(0.0, min(1.0, confidence))
        
    def _parse_date(self, date_str: Optional[str]) -> Optional[str]:
        """Parse date string into ISO format."""
        if not date_str:
            return None
            
        # Clean up the date string
        date_str = date_str.strip()
        
        # Skip obviously invalid dates (like '925-11-11')
        if re.match(r'^\d{3}-\d{1,2}-\d{1,2}$', date_str):
            self.logger.debug(f"Skipping invalid date format: '{date_str}'")
            return None
        
        # Handle malformed dates like '2-16-16' (MM-DD-YY format)
        if re.match(r'^\d{1,2}-\d{1,2}-\d{1,2}$', date_str):
            parts = date_str.split('-')
            if len(parts) == 3:
                month, day, year = parts
                # Assume 2-digit years in 00-30 range are 2000s, 31+ are 1900s
                if len(year) == 2:
                    try:
                        year_int = int(year)
                        if year_int <= 30:
                            year = f"20{year}"
                        else:
                            year = f"19{year}"
                        
                        # Reconstruct as MM/DD/YYYY
                        date_str = f"{month.zfill(2)}/{day.zfill(2)}/{year}"
                    except (ValueError, TypeError):
                        return None
        
        # Try to parse various date formats
        date_formats = [
            '%Y-%m-%d',
            '%m/%d/%Y',
            '%d/%m/%Y', 
            '%m-%d-%Y',
            '%d-%m-%Y',
            '%B %d, %Y',
            '%d %B %Y',
            '%b %d %Y',
            '%b %d, %Y',
            '%Y/%m/%d',
            '%d.%m.%Y',
            '%m.%d.%Y'
        ]
        
        for fmt in date_formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                # Validate the parsed date is reasonable (between 1900 and 2030)
                if 1900 <= dt.year <= 2030:
                    return dt.date().isoformat()
            except ValueError:
                continue
        
        # If no format matches, log as debug (not warning to reduce noise)
        self.logger.debug(f"Could not parse date: '{date_str}'")
        return None
        
    def get_technique_info(self, technique_id: str) -> Optional[Dict]:
        """Get information about a specific technique."""
        return self.techniques.get(technique_id)
        
    def get_all_techniques(self) -> Dict:
        """Get all loaded techniques."""
        return self.techniques.copy()
        
    def get_techniques_by_tactic(self, tactic: str) -> Dict:
        """Get all techniques for a specific tactic."""
        return {
            tid: info for tid, info in self.techniques.items()
            if info.get('tactic') == tactic
        }
